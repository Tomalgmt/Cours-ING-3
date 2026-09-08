# Kit VM — TP1 Durcissement d'un serveur Debian 12

Ce kit sert à ne pas perdre une séance à installer Debian. À la fin, chaque étudiant a **exactement la même machine** : Debian 12, bureau léger Xfce, terminal, Firefox, serveur SSH, baseline dégradée déjà appliquée, scripts du TP dans `~/tp`.

Compte créé : **`etudiant`** / mot de passe **`tp-durcissement`**. Compte `root` désactivé, `sudo` actif — comme le demande le sujet. Dites aux étudiants de changer ce mot de passe : c'est leur premier geste de durcissement, et il est vérifié à l'étape 2.

---

## Ce que contient le kit

| Fichier | Rôle |
|---|---|
| `preseed.cfg` | Installation entièrement automatique. Zéro question posée. |
| `preparer-vm.sh` | Post-installation : bureau, SSH, dégradation, dépôt des scripts. Utilisable seul. |
| `postinstall.sh` | Colle entre les deux. Appelé par le preseed, jamais à la main. |
| `README.md` | Ce fichier. |

Les deux scripts du TP (`degrade-debian.sh`, `check-debian.sh`) doivent être publiés **au même endroit** que ce kit.

---

## Avant diffusion — une seule chose à faire

Publier le dossier quelque part d'accessible en HTTP, puis remplacer l'URL dans `preseed.cfg` :

```
URL=https://REMPLACER-PAR-VOTRE-URL/kit-vm
```

Trois options, par ordre de simplicité :

- **Moodle / l'espace de cours de l'école** — le plus simple si les fichiers y sont servis en lien direct.
- **Un dépôt GitHub public**, en utilisant les URL `raw.githubusercontent.com`.
- **Votre poste, en séance** : `cd kit-vm && python3 -m http.server 8000`, puis l'URL `http://<votre-ip>:8000`. Ne marche que tant que vous êtes sur le même réseau, mais c'est instantané et cela ne dépend d'aucun service de l'école.

Vérifiez ensuite depuis un navigateur que `<votre-url>/preseed.cfg` s'affiche bien en texte brut.

---

## Voie A — installation automatique (12 min, aucune interaction)

À donner aux étudiants tel quel.

1. Créer une VM dans votre hyperviseur : **2 Go de RAM, 2 processeurs, 30 Go de disque, réseau NAT**.
2. Y attacher l'ISO **netinst Debian 12** — `amd64` sur PC, **`arm64` sur Mac Apple Silicon**.
3. Démarrer la VM. Au menu bleu de l'installateur, **ne pas valider « Install »** : appuyer sur `Tab` (mode BIOS) ou sur `e` puis aller à la fin de la ligne `linux` (mode UEFI), et **ajouter à la fin de la ligne** :

```
auto=true priority=critical url=https://VOTRE-URL/kit-vm/preseed.cfg
```

4. Valider (`Entrée` en mode BIOS, `Ctrl-X` ou `F10` en mode UEFI). L'installation se déroule seule, la machine redémarre sur le bureau.
5. **Prendre un instantané nommé `baseline`.** Obligatoire.

> Si l'installateur pose malgré tout une question, c'est que le preseed n'a pas été téléchargé : vérifiez l'URL et le réseau de la VM. L'installation se poursuit normalement en manuel, il suffira ensuite de passer par la voie B.

---

## Voie B — installation manuelle + un script (si la voie A échoue)

1. Installer Debian 12 normalement. Sélection des logiciels : **décocher tout sauf « serveur SSH » et « utilitaires usuels du système »**.
2. Copier `preparer-vm.sh`, `degrade-debian.sh` et `check-debian.sh` dans la VM (clé USB, dossier partagé, ou `wget` depuis l'URL du kit).
3. Lancer :

```bash
chmod +x preparer-vm.sh
sudo ./preparer-vm.sh              # avec le bureau léger
sudo ./preparer-vm.sh --sans-bureau  # ou serveur pur
```

4. **Prendre un instantané nommé `baseline`.**

---

## Réglages par hyperviseur

| Hyperviseur | Image | Réseau | Remarque |
|---|---|---|---|
| **VirtualBox** (PC) | amd64 | NAT | Activer EFI si l'installateur ne démarre pas. Redirection de port `2222 → 22` pour le SSH depuis l'hôte. |
| **VMware Workstation / Fusion** | amd64, ou arm64 sur Mac M | NAT | Rien de particulier. |
| **UTM** (Mac Apple Silicon) | **arm64** | Shared Network | Choisir « Virtualize », pas « Emulate » : l'émulation est dix fois plus lente. |
| **Parallels** (Mac Apple Silicon) | **arm64** | Réseau partagé | Créer la VM via **Fichier > Nouveau** et l'ISO. Voir l'avertissement ci-dessous. |
| **Hyper-V** (Windows Pro) | amd64 | Commutateur par défaut | Génération 2, désactiver le démarrage sécurisé. |

### Avertissements Parallels

- La fenêtre **Configuration** de certaines versions n'enregistre pas le fichier choisi dans le champ « Source / Emplacement » d'un périphérique. Pour monter une ISO : VM allumée, menu **Périphériques > CD/DVD > Connecter l'image…**. Pour créer un disque : passer par l'assistant **Fichier > Nouveau**, pas par la fenêtre de configuration.
- Prendre un instantané suspend brièvement la VM. Si le bail DHCP expire pendant ce temps, **la VM perd son adresse IPv4** et vous perdez SSH. Diagnostic : `ip -br a` ne montre plus que de l'IPv6. Correctif : `sudo dhclient <interface>`, et si cela ne suffit pas, redémarrer la VM.

---

## Copier-coller entre l'hôte et la VM

C'est la raison d'être du bureau léger. Trois niveaux, du plus simple au plus complet :

1. **Travailler en SSH depuis le terminal de l'hôte.** C'est la meilleure solution, elle ne demande rien à installer. `ssh etudiant@<ip-de-la-vm>` (ou `ssh -p 2222 etudiant@127.0.0.1` avec la redirection VirtualBox).
2. **Dans le bureau de la VM**, ouvrir le sujet dans Firefox : le copier-coller fonctionne alors entre les fenêtres de la VM.
3. **Additions invité** pour un presse-papiers partagé hôte/VM : `virtualbox-guest-x11` (VirtualBox), `open-vm-tools-desktop` (VMware), `spice-vdagent` (UTM/QEMU), Parallels Tools (Parallels). Elles ne fonctionnent **qu'avec un serveur graphique** : sur une VM en console pure, il n'y a pas de copier-coller, point.

---

## Vérifier que la VM est bonne

Dans la VM :

```bash
curl http://127.0.0.1:8080/health     # doit afficher OK
sudo ~/tp/check-debian.sh             # doit afficher un score bas (c'est normal : c'est le point de départ)
```

Un score de départ autour de **12/60** est le comportement attendu. Si le service métier ne répond pas, la dégradation ne s'est pas appliquée : relancer `sudo ~/tp/degrade-debian.sh`.
