"""Analyse reproductible de l'echantillon mal, uniquement en memoire/Unicorn.

Python 3.10+; pip install capstone==5.0.9 pyelftools==0.33 unicorn==2.1.4
python analyser_mal.py mal.7z --sevenzip 7z --output preuves
Aucun appel systeme du binaire n'est transmis au systeme hote.
"""
import argparse
import base64
import hashlib
import io
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

local_libs = Path(__file__).resolve().parent.parent / 'work' / 'pythonlibs'
if local_libs.is_dir():
    sys.path.insert(0, str(local_libs))
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_INSN
from unicorn.x86_const import *

EXPECTED = '8f0bdcaabfe1089e0ea169eefeb1795bc6ea7762fff2aab0aabc60c8804dd6e2'
EXIT_PATCH = bytes.fromhex('31ffb83c0000000f05')
BASE = 0x1000000
HEAP = 0x3000000
STACK = 0x4000000
STOP = 0x5000000

def sha(data):
    return hashlib.sha256(data).hexdigest()

def read_sample(path, sevenzip):
    if path.suffix.lower() == '.7z':
        return subprocess.run([sevenzip, 'x', '-so', '-ptest', str(path), 'mal.bin'],
                              capture_output=True, check=True).stdout
    return path.read_bytes()

class Sample:
    def __init__(self, data):
        if sha(data) != EXPECTED:
            raise ValueError('SHA-256 inattendu : ces adresses ne valent que pour le fichier audite.')
        self.data = data
        self.elf = ELFFile(io.BytesIO(data))
        self.symbols = {s.name: s for s in self.elf.get_section_by_name('.symtab').iter_symbols()}
        self.names = {s['st_value']: s.name for s in self.symbols.values() if s['st_value']}

    def address(self, name):
        return self.symbols[name]['st_value']

    def offset(self, address):
        for seg in self.elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= address < seg['p_vaddr'] + seg['p_filesz']:
                return address - seg['p_vaddr'] + seg['p_offset']
        raise ValueError(f'Adresse sans octets dans le fichier : {address:x}')

    def assembly(self, names):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        lines = ['; Adresses virtuelles ELF relatives a la base, pas adresses ASLR du systeme.']
        for name in names:
            sym = self.symbols[name]
            addr, size = sym['st_value'], sym['st_size'] or 22
            offset = self.offset(addr)
            lines.append(f'\n{name}: VA=0x{addr:x}, offset=0x{offset:x}, taille={size}')
            for inst in md.disasm(self.data[offset:offset+size], addr):
                refs = []
                for op in inst.operands:
                    dest = None
                    if op.type == X86_OP_IMM:
                        dest = op.imm
                    elif op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                        dest = inst.address + inst.size + op.mem.disp
                    if dest in self.names:
                        refs.append(self.names[dest])
                lines.append(f'{inst.address:08x}: {inst.bytes.hex():24} {inst.mnemonic:8} {inst.op_str:42} ; {", ".join(refs)}')
        return '\n'.join(lines) + '\n'

class Emulator:
    """Chargeur ELF minimal, heap simulee et appels a effet externe interceptes."""
    def __init__(self, sample, edits=()):
        self.sample = sample
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.events = []
        self.instructions = 0
        self.next_heap = HEAP + 0x10000
        self.allocations = {}
        self.branch_eax = None
        self.returned = False
        for seg in sample.elf.iter_segments():
            if seg['p_type'] != 'PT_LOAD':
                continue
            addr = BASE + seg['p_vaddr']
            low = addr & ~0xfff
            high = (addr + seg['p_memsz'] + 0xfff) & ~0xfff
            self.uc.mem_map(low, high - low)
            self.uc.mem_write(addr, seg.data())
        rel = sample.elf.get_section_by_name('.rela.dyn')
        for r in rel.iter_relocations():
            typ, addend = r['r_info_type'], r['r_addend']
            if typ == 8:  # R_X86_64_RELATIVE
                value = BASE + addend
            elif typ == 1:  # R_X86_64_64, symbole defini ou weak absent
                sym = sample.elf.get_section(rel['sh_link']).get_symbol(r['r_info_sym'])
                value = (BASE + sym['st_value'] if sym['st_shndx'] != 'SHN_UNDEF' else 0) + addend
            else:
                raise ValueError(f'Relocation non geree : {typ}')
            self.uc.mem_write(BASE + r['r_offset'], struct.pack('<Q', value))
        self.uc.mem_map(HEAP, 0x100000)
        self.uc.mem_map(STACK, 0x100000)
        self.uc.mem_map(STOP, 0x1000)
        # TLS minimal de musl : __errno_location lit fs:[0], puis ajoute 0x44.
        tls = HEAP + 0x8000
        self.uc.mem_write(tls, struct.pack('<Q', tls))
        self.uc.reg_write(UC_X86_REG_FS_BASE, tls)
        rsp = STACK + 0x80000 - 8
        self.uc.reg_write(UC_X86_REG_RSP, rsp)
        self.uc.mem_write(rsp, struct.pack('<Q', STOP))
        self.uc.mem_write(HEAP + 0x20, struct.pack('<Q', HEAP + 0x4000))
        self.uc.reg_write(UC_X86_REG_RDI, HEAP)
        self.uc.reg_write(UC_X86_REG_RSI, 0)
        for address, value in edits:
            self.uc.mem_write(BASE + address, value)
        self.hooks = {BASE + sample.address(n): n for n in [
            'malloc', 'realloc', 'free', 'c2_add_transport_uri',
            'mettle_set_uuid_base64', 'mettle_set_session_guid_base64',
            'start_service',
            'mettle_console_start_interactive', 'modulemgr_load_path',
        ]}
        self.uc.hook_add(UC_HOOK_CODE, self.on_code)
        self.uc.hook_add(UC_HOOK_INSN, self.on_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

    def string(self, addr):
        out = bytearray()
        for i in range(4096):
            value = self.uc.mem_read(addr + i, 1)[0]
            if value == 0:
                return out.decode('utf-8', errors='replace')
            out.append(value)
        raise ValueError('Chaine non terminee')

    def alloc(self, size):
        addr = self.next_heap
        self.next_heap += max(16, (size + 15) & ~15)
        if self.next_heap >= HEAP + 0x100000:
            raise ValueError('Heap simulee epuisee')
        self.allocations[addr] = size
        return addr

    def ret(self, value=0):
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        dest = struct.unpack('<Q', self.uc.mem_read(rsp, 8))[0]
        self.uc.reg_write(UC_X86_REG_RAX, value)
        self.uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        self.uc.reg_write(UC_X86_REG_RIP, dest)

    def on_code(self, uc, addr, size, _):
        self.instructions += 1
        if addr == STOP:
            self.returned = True
            uc.emu_stop()
            return
        if addr == BASE + 0x9ba2:
            eax = uc.reg_read(UC_X86_REG_EAX)
            self.branch_eax = eax if eax < 0x80000000 else eax - 0x100000000
        if addr == BASE + self.sample.address('parse_cmdline'):
            argc = uc.reg_read(UC_X86_REG_RDI)
            argv = uc.reg_read(UC_X86_REG_RSI)
            args = [self.string(struct.unpack('<Q', uc.mem_read(argv+i*8, 8))[0]) for i in range(argc)]
            self.events.append({'event': 'parse_cmdline', 'argc': argc, 'argv': args})
        name = self.hooks.get(addr)
        if not name:
            return
        a = uc.reg_read(UC_X86_REG_RDI)
        b = uc.reg_read(UC_X86_REG_RSI)
        if name == 'malloc':
            self.ret(self.alloc(a))
        elif name == 'realloc':
            new = self.alloc(b)
            if a:
                uc.mem_write(new, bytes(uc.mem_read(a, min(self.allocations[a], b))))
            self.ret(new)
        elif name == 'free':
            self.ret()
        else:
            event = {'event': name, 'intercepted': True}
            if name in ['c2_add_transport_uri', 'mettle_set_uuid_base64', 'mettle_set_session_guid_base64']:
                event['value'] = self.string(b)
            self.events.append(event)
            self.ret()

    def on_syscall(self, uc, _):
        number = uc.reg_read(UC_X86_REG_RAX)
        self.events.append({'event': 'syscall_intercepted', 'number': number,
                            'arg1': uc.reg_read(UC_X86_REG_RDI), 'host_forwarded': False})
        uc.emu_stop()
        if number != 60:
            raise RuntimeError(f'Appel systeme inattendu bloque : {number}')

    def run(self, address):
        try:
            self.uc.emu_start(BASE + address, STOP + 1, timeout=5_000_000, count=200_000)
        except UcError as error:
            raise RuntimeError(f'{error}; RIP={self.uc.reg_read(UC_X86_REG_RIP):x}; events={self.events}') from error
        result = {'instructions': self.instructions, 'returned': self.returned,
                  'comparison_eax': self.branch_eax, 'events': self.events,
                  'final_rip': hex(self.uc.reg_read(UC_X86_REG_RIP)),
                  'log_level': struct.unpack('<i', self.uc.mem_read(BASE + self.sample.address('_zlog_level'), 4))[0]}
        if not self.returned and not any(e['event'] == 'syscall_intercepted' for e in self.events):
            raise RuntimeError('Emulation incomplete : limite atteinte')
        return result

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('sample', type=Path)
    ap.add_argument('--sevenzip', default=shutil.which('7z') or r'C:\Program Files\7-Zip\7z.exe')
    ap.add_argument('--output', type=Path, default=Path('preuves'))
    args = ap.parse_args()
    data = read_sample(args.sample, args.sevenzip)
    s = Sample(data)
    config_addr = s.address('default_opts.7006')
    config_offset = s.offset(config_addr)
    config = data[config_offset:config_offset+2013].split(b'\0')[0].decode()
    expected_uri = 'tcp://192.168.192.130:1337'
    tests = {}
    tests['original_config'] = Emulator(s).run(s.address('parse_default_args'))
    tests['skip_config_branch'] = Emulator(s, [(0x9ba4, b'\xeb')]).run(s.address('parse_default_args'))
    tests['sentinel_config'] = Emulator(s, [(config_addr, b'DEFAULT_OPTS')]).run(s.address('parse_default_args'))
    tests['exit_at_entry'] = Emulator(s, [(s.elf['e_entry'], EXIT_PATCH)]).run(s.elf['e_entry'])
    original = tests['original_config']
    assert any(e.get('event') == 'c2_add_transport_uri' and e.get('value') == expected_uri for e in original['events'])
    assert original['returned'] and original['comparison_eax'] != 0
    for name in ['skip_config_branch', 'sentinel_config']:
        assert tests[name]['returned'] and tests[name]['events'] == []
    exit_events = tests['exit_at_entry']['events']
    assert exit_events == [{'event':'syscall_intercepted','number':60,'arg1':0,'host_forwarded':False}]
    patched = bytearray(data)
    offset = s.offset(s.elf['e_entry'])
    before = data[offset:offset+len(EXIT_PATCH)]
    patched[offset:offset+len(EXIT_PATCH)] = EXIT_PATCH
    metadata = {'sample_sha256': sha(data), 'sample_size': len(data), 'elf_entry': hex(s.elf['e_entry']),
                'symbol_table_entries': s.elf.get_section_by_name('.symtab').num_symbols(),
                'config_address': hex(config_addr), 'config_offset': hex(config_offset),
                'config': config, 'uuid_hex': base64.b64decode('vaiB0/oaK6u7ub2702Dq8A==').hex(),
                'load_segments': [dict(seg.header) for seg in s.elf.iter_segments() if seg['p_type']=='PT_LOAD'],
                'patch': {'offset':hex(offset),'before':before.hex(),'after':EXIT_PATCH.hex(),
                          'patched_sha256':sha(patched),'length_unchanged':len(patched)==len(data)},
                'emulation_base':hex(BASE), 'tests':tests, 'all_assertions_passed': True,
                'scope':'Emulation de fonctions ciblees et du point entree modifie, pas execution Linux complete.'}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'preuves.json').write_text(json.dumps(metadata, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    names = ['_start', '_start_c', 'main', 'parse_default_args', 'parse_cmdline', 'argv_split',
             'mettle', 'mettle_start', 'c2_add_transport_uri', 'c2_start', 'transport_cb',
             'tcp_transport_start', 'network_client_start', 'start_service', 'sigar_password_get']
    (args.output / 'desassemblage.asm').write_text(s.assembly(names), encoding='utf-8')
    print(json.dumps(metadata, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    main()
