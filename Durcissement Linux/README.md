# TP1 — Durcissement d’une machine Debian 12

Dans ce rapport, je présente l’audit et le durcissement que j’ai réalisés sur une VM Debian 12, tout en maintenant le service métier nginx disponible sur le port TCP 8080. Je regroupe les mesures selon les thèmes du script `check-debian.sh`.

## Sommaire

1. [Mise en place de la VM](#mise-en-place-de-la-vm)
2. [Service métier et audit](#a-service-métier-et-audit)
3. [Comptes et authentification](#b-comptes-et-authentification)
4. [Élévation de privilèges](#c-élévation-de-privilèges)
5. [Accès distant SSH](#d-accès-distant-ssh)
6. [Services et paquets](#e-services-et-paquets)
7. [Réseau et pare-feu](#f-réseau-et-pare-feu)
8. [Systèmes de fichiers et SUID](#g-systèmes-de-fichiers-et-suid)
9. [Noyau](#h-noyau)
10. [Confinement des processus](#i-confinement-des-processus)
11. [Journalisation et intégrité](#j-journalisation-et-intégrité)
12. [Mises à jour](#k-mises-à-jour)
13. [Vérification finale](#vérification-finale)
14. [Corrections issues de la relecture](#corrections-issues-de-la-relecture)

## Mise en place de la VM

### Presse-papiers partagé

Pour simplifier le transfert de fichiers et de commandes entre l’hôte et la VM, j’ai activé le presse-papiers bidirectionnel dans VirtualBox. Cela permet de copier-coller du texte entre les deux environnements.

J’ai installé les VirtualBox Guest Additions dans la VM, puis activé Périphériques-> Presse-papiers partagé-> Bidirectionnel :

Puis j'ai installé les paquets nécessaires à la compilation et aux modules du noyau, j'ai monté l'image CD des Guest Additions (les Guest Addition c'est des outils pour améliorer l'expérience utilisateur dans VirtualBox), puis j’ai exécuté le script d’installation des Guest 

J’ai recréé l’instantané de baseline après cette installation. Ainsi, une restauration conserve les Guest Additions et la session Xorg ; il me reste seulement à vérifier que `Périphériques -> Presse-papiers partagé -> Bidirectionnel` est toujours sélectionné dans VirtualBox.

### Accès SSH depuis l’hôte

Le mode NAT ne permettait pas à l’hôte de joindre directement `10.0.2.15`. J’ai ajouté une redirection VirtualBox hôte `127.0.0.1:2222`-> VM `10.0.2.15:22`, puis activé SSH :

```bash
sudo systemctl enable --now ssh
```

Je peux ensuite me connecter depuis l’hôte avec :

```bash
ssh -p 2222 moutsss@127.0.0.1
```

### Synchronisation de l’horloge

Après la reprise d’un instantané VirtualBox, j’ai constaté que l’horloge de la VM pouvait être décalée. APT refusait alors les fichiers `InRelease` en indiquant qu’ils n’étaient « pas encore valides ». J’ai activé la synchronisation NTP avant toute installation de paquet :

```bash
sudo timedatectl set-timezone Europe/Paris
sudo timedatectl set-ntp true
sudo systemctl restart systemd-timesyncd.service
timedatectl status
```

Dans `hardening.sh`, ces commandes sont exécutées dès le début, juste après la vérification des droits root et avant les sauvegardes ou `apt-get update`. Le script attend que `NTPSynchronized` vaut `yes` et s’arrête avec un message explicite si l’horloge n’a pas pu être corrigée.

### Prérequis contrôlé par le script

Sur une restauration vierge de la baseline, la clé SSH et le client graphique VirtualBox peuvent être absents. Avant de commencer le durcissement, `hardening.sh` vérifie donc la présence de `VBoxClient`, d’une session Xorg et du processus `VBoxClient --clipboard`. Si l’un de ces éléments manque, le script affiche les étapes d’installation des Guest Additions, demande un redémarrage et s’arrête. Je relance alors le script après le redémarrage.

Lorsque ces prérequis sont présents mais que la clé SSH manque encore, le script me demande d’activer `Périphériques -> Presse-papiers partagé -> Bidirectionnel` dans la fenêtre VirtualBox. J’appuie ensuite sur Entrée pour poursuivre. La demande de collage de la clé n’apparaît qu’après ce contrôle.

Après ça on peut suivre le TP et commencer par installer openssh-server si ce n’est pas déjà fait ou lancer le script prepare-debian.sh

Executer le script de dégradation :
```bash
sudo ./kit-vm/degrade.sh
```

On prend un instantané de la VM pour pouvoir revenir à l’état initial si nécessaire.


## A. Service métier et audit

Après avoir exécuté les scripts de préparation et de dégradation, j’ai vérifié que le service métier répondait :

```bash
curl -fsS http://127.0.0.1:8080/health
```

```text
OK
```

J’ai ensuite réalisé et enregistré un audit Lynis avec :

```bash
sudo lynis audit system 2>&1 | tee audit_lynis.txt
```

Lynis donne une vue globale de la surface d’attaque et propose des améliorations. J’ai synthétisé les constatations utiles au TP dans `audit_lynis_priorisé.txt`, avec pour chacune la constatation factuelle, la menace associée et une criticité argumentée. Je les ai ensuite classées selon les thèmes du TP.

## B. Comptes et authentification

### Inventaire

J’ai examiné les comptes, leurs UID et leurs shells avec :

```bash
getent passwd
```

J’ai initialement observé les comptes interactifs suivants :

```text
moutsss      UID=1000  shell=/bin/bash
alice        UID=1001  shell=/bin/bash
bob          UID=1002  shell=/bin/bash
stagiaire    UID=1003  shell=/bin/bash
sauvegarde   UID=1004  shell=/bin/bash
deploy       UID=1005  shell=/bin/bash
```

Je n’ai trouvé aucun compte autre que `root` avec l’UID 0. Après avoir confirmé que le compte `stagiaire` était inutile, je l’ai supprimé :

```bash
sudo userdel -r stagiaire
```

J’ai retiré le shell interactif des comptes de service :

```bash
sudo usermod -s /usr/sbin/nologin deploy
sudo usermod -s /usr/sbin/nologin sauvegarde
```

### Expiration des mots de passe

J’ai constaté que l’état initial d’Alice indiquait une durée maximale de `99999` jours, c’est-à-dire aucune expiration pratique :

```bash
sudo passwd -S alice
sudo chage -l alice
```

```text
alice P 2026-09-08 0 99999 7 -1
```

J’ai défini la politique par défaut des futurs comptes dans `/etc/login.defs`. 

```text
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_WARN_AGE   14
```

La directive `PASS_MAX_DAYS 90` impose le changement du mot de passe au plus tard après 90 jours et satisfait le contrôle `PASS_MAX_DAYS <= 90`.

`PASS_MIN_DAYS` impose un délai d’un jour avant un nouveau changement. `/etc/login.defs` n’agit que sur les comptes créés par la suite. J’ai alors appliqué la politique aux comptes existants avec `chage` :

```bash
sudo chage -M 90 -m 1 -W 14 alice
sudo chage -M 90 -m 1 -W 14 bob
sudo chage -M 90 -m 1 -W 14 moutsss
```

### Qualité des mots de passe

J’ai installé le module, puis je l’ai activé dans PAM :

```bash
sudo apt update
sudo apt install -y libpam-pwquality libpam-modules
sudo pam-auth-update
```

Dans `/etc/pam.d/common-password`, l’appel suivant autorise trois essais lors du choix d’un nouveau mot de passe :

```text
password requisite pam_pwquality.so retry=3
```

J’ai configuré `/etc/security/pwquality.conf` de la façon suivante :

```text
minlen = 12
minclass = 3
dcredit = -2
ucredit = -2
lcredit = -2
ocredit = -2
maxrepeat = 3
```

Cette configuration impose donc au moins deux chiffres, deux majuscules, deux minuscules et deux caractères spéciaux, avec une longueur minimale de douze caractères et au plus trois répétitions consécutives. (La politique est un peu stricte j'ai eu quelques problemes qui m'ont forcés a changer le mot de passe depuis un shell root lors de l'init de la machine)

### Verrouillage après échecs

Le fichier `/etc/security/faillock.conf` contient :

```text
deny = 5
fail_interval = 900
unlock_time = 900
audit
```

Les comptes sont verrouillés après cinq échecs comptabilisés sur quinze minutes, puis automatiquement déverrouillés après quinze minutes. Les appels PAM utilisés sont :

```text
# /etc/pam.d/common-auth
auth required pam_faillock.so preauth
auth [success=2 default=ignore] pam_unix.so nullok
auth [default=die] pam_faillock.so authfail

# /etc/pam.d/common-account
account required pam_faillock.so
```

L’ordre des lignes PAM est important. `success=2` permet à une authentification Unix réussie de sauter à la fois `pam_faillock ... authfail` et `pam_deny`. J’ai conservé une session locale ouverte pendant les essais afin d’éviter une perte d’accès en cas d’erreur.


## C. Élévation de privilèges

J’ai supprimé la règle trop permissive :

```bash
sudo rm /etc/sudoers.d/99-laxiste
```

J’ai placé la configuration de journalisation dans `/etc/sudoers.d/logging` :

```text
Defaults logfile="/var/log/sudo.log"
Defaults log_input
Defaults log_output
```

`logfile` journalise les événements sudo. `log_input` et `log_output` activent en plus les journaux d’entrées-sorties des sessions sudo.

J’ai contrôlé les droits et la syntaxe avant de fermer la session administrateur avec visudo qui permet de vérifier la syntaxe des fichiers sudoers :

```bash
sudo chmod 0440 /etc/sudoers.d/logging
sudo visudo -cf /etc/sudoers.d/logging
sudo visudo -c
```

## D. Accès distant SSH

J’ai créé un fichier dédié dans `/etc/ssh/sshd_config.d/00-durcissement.conf` :

```text
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 4
LoginGraceTime 60
X11Forwarding no
AllowUsers moutsss alice bob
Banner /etc/issue.net
ClientAliveInterval 600
AllowTcpForwarding no
```

Ces options interdisent la connexion directe sur le compte `root`, désactivent l’authentification par mot de passe, imposent les clés publiques, limitent les essais et les comptes autorisés, et désactivent les transferts X11 et TCP. `ClientAliveInterval 600` permet également au serveur de vérifier périodiquement que le client répond toujours.

Avant de désactiver le mot de passe, j’ai créé une clé ssh sur l'hote et placé la clé publique dans `~moutsss/.ssh/authorized_keys` comme ça je ne perd pas l'accès à la VM. J’ai ensuite sécurisé les permissions du répertoire et du fichier :

```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

J’ai validé la configuration avant de la recharger :

```bash
sudo sshd -t
sudo systemctl reload ssh
```

Depuis l’hôte, la redirection NAT VirtualBox utilise :

```bash
ssh -p 2222 moutsss@127.0.0.1
```

La bannière `/etc/issue.net` contient :

```text
Accès réservé aux utilisateurs autorisés.
```

J’ai vérifié ces deux options avec `sshd -T` : il retourne désormais `clientaliveinterval 600` et `allowtcpforwarding no`.

## E. Services et paquets

J’ai inventorié les sockets TCP avec :

```bash
sudo ss -ltnp
```

 Il ne faut qu’aucun port autre que 22 et 8080 ne doit écouter sur toutes les interfaces IPv4 (`0.0.0.0`).

J’ai arrêté et désactivé les services inutiles lorsqu’ils existaient :

```bash
sudo systemctl disable --now rpcbind.service rpcbind.socket
sudo systemctl disable --now avahi-daemon.service avahi-daemon.socket
sudo systemctl disable --now nfs-server.service
sudo systemctl disable --now xinetd.service
sudo apt remove -y xinetd telnetd
```

## F. Réseau et pare-feu

J’ai installé nftables et sauvegardé le fichier d’origine :

```bash
sudo apt install -y nftables
sudo cp /etc/nftables.conf /etc/nftables.conf.back
```

J’ai préparé la configuration suivante dans `/etc/nftables.conf` :

```nftables
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        tcp dport 22 accept
        tcp dport 8080 accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
```

La politique est restrictive en entrée et en forward, les sorties restent autorisées. Le loopback, les flux établis, ICMP/ICMPv6, SSH et le service métier sont explicitement autorisés.

```bash
sudo nft -c -f /etc/nftables.conf
sudo nft -f /etc/nftables.conf
sudo systemctl enable --now nftables
sudo nft list ruleset
```

J’ai rechargé le fichier puis vérifié avec `sudo nft list ruleset` que les politiques effectivement chargées des chaînes `input` et `forward` étaient toutes les deux à `drop`. La chaîne `output` reste à `accept` pour permettre les communications sortantes.

## G. Systèmes de fichiers et SUID

J’ai examiné les permissions initiales avec :

```bash
ls -l /etc/shadow /usr/local/bin/find-suid
ls -ld /srv/metier /opt/scripts
find /srv/metier /opt/scripts -maxdepth 2 -printf '%M %u:%g %p\n'
```

Je les ai corrigées avec :

```bash
sudo chown root:shadow /etc/shadow
sudo chmod 640 /etc/shadow

sudo chown -R root:root /srv/metier
sudo find /srv/metier -type d -exec chmod 755 {} + # fait une boucle sur le répertoire et change les droits de tous les sous-répertoires
sudo find /srv/metier -type f -exec chmod 644 {} +  #similaire

sudo chown -R root:root /opt/scripts
sudo find /opt/scripts -type d -exec chmod 755 {} + # similaire
sudo find /opt/scripts -type f -exec chmod 750 {} + #similaire
```

Le groupe système `shadow` existe par défaut sur Debian. Il permet à certains programmes privilégiés de lire `/etc/shadow` sans ouvrir ce fichier aux autres utilisateurs. Avec le mode `0640`, `root` peut lire et modifier le fichier, le groupe `shadow` peut le lire et les autres n’ont aucun droit.

J'ai d'abord mis en quarantaine le binaire SUID superflu pour voir si le service métier continuait de fonctionner. J’ai créé un répertoire `/root/prison`, déplacé le binaire SUID et restreint ses permissions :

```bash
sudo mkdir -p /root/prison
sudo mv /usr/local/bin/find-suid /root/prison/find-suid.disabled
sudo chmod 700 /root/prison/find-suid.disabled
curl -fsS http://127.0.0.1:8080/health
```

Le service fonctionnant toujours, j’ai ensuite retiré le fichier :

```bash
sudo rm /root/prison/find-suid.disabled
```

## H. Noyau

Le fichier persistant `/etc/sysctl.d/99-z-durcissement.conf` contient :

```ini
kernel.randomize_va_space = 2   
# active l’ASLR (Address Space Layout Randomization)
kernel.dmesg_restrict = 1       
# restreint l’accès à dmesg aux utilisateurs privilégiés
kernel.kptr_restrict = 2        
# restreint l’accès aux pointeurs du noyau dans /proc/kallsyms et /proc/modules
fs.suid_dumpable = 0            
# désactive les dumps de processus SUID
net.ipv4.ip_forward = 0         
# désactive le routage IPv4
net.ipv4.tcp_syncookies = 1     
# active les SYN cookies pour se protéger contre les attaques par déni de service
net.ipv4.conf.all.accept_redirects = 0  
# désactive les redirections ICMP
net.ipv4.conf.default.accept_redirects = 0  
# désactive les redirections ICMP par défaut
net.ipv4.conf.all.accept_source_route = 0   
# désactive le routage imposé par la source
net.ipv4.conf.default.accept_source_route = 0   
# désactive le routage imposé par la source par défaut
```

Ces réglages activent l’ASLR, limitent l’exposition d’informations du noyau, désactivent les dumps privilégiés et le routage, activent les SYN cookies, puis refusent les redirections ICMP et le routage imposé par la source.

```bash
#ici on recharge la configuration du noyau pour qu'elle soit appliquée immédiatement
sudo sysctl --system
sysctl kernel.randomize_va_space kernel.dmesg_restrict kernel.kptr_restrict
sysctl fs.suid_dumpable net.ipv4.ip_forward net.ipv4.tcp_syncookies
sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects
sysctl net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route
```

Les neuf contrôles noyau passent après redémarrage.

## I. Confinement des processus

J’ai installé et activé AppArmor et ses outils :

```bash
sudo apt install -y apparmor apparmor-utils
sudo systemctl enable --now apparmor
sudo aa-status
```

AppArmor applique un contrôle d’accès obligatoire aux processus. Pour construire un profil adapté à nginx, j’ai lancé la génération interactive dans un premier terminal :

```bash
sudo aa-genprof /usr/sbin/nginx
```

`aa-genprof` place d’abord nginx en mode apprentissage (`complain`). Dans un second terminal, j’ai provoqué les actions normales du service :

```bash
sudo nginx -t
sudo systemctl restart nginx
curl -fsS http://127.0.0.1:8080/
curl -fsS http://127.0.0.1:8080/health
sudo systemctl reload nginx
curl -fsS http://127.0.0.1:8080/health
```

Dans le premier terminal, j’ai utilisé `S` pour analyser les événements, puis `F` pour enregistrer le profil après avoir examiné les règles. Mon premier profil était incomplet et refusait `/etc/nginx/nginx.conf`, ce qui empêchait nginx de redémarrer. J’ai donc complété `/etc/apparmor.d/usr.sbin.nginx` avec les accès nécessaires à la configuration, aux certificats, aux modules, au PID, aux journaux et à `/srv/metier`.

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx
sudo aa-enforce /usr/sbin/nginx
sudo nginx -t
sudo systemctl restart nginx
systemctl is-active nginx
curl -fsS http://127.0.0.1:8080/health
sudo aa-status
```

Le redémarrage sous le profil restrictif est indispensable car le service peut continuer a fonctionner alors qu'il ne fonctionnera plus a uprochain redémarrage

J’ai ajouté le confinement systemd dans `/etc/systemd/system/nginx.service.d/hardening.conf` :

```ini
[Service]
NoNewPrivileges=yes
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart nginx
systemctl show nginx -p NoNewPrivileges
```

`NoNewPrivileges=yes` empêche nginx et ses descendants d’acquérir de nouveaux privilèges lors d’un `execve`.

`execve` est l’appel système utilisé par `system()` et `popen()` qui permet de lancer un nouveau processus. Il est donc important de restreindre les privilèges pour éviter qu’un processus compromis ne puisse élever ses droits.

## J. Journalisation et intégrité

### auditd

```bash
sudo apt install -y auditd audispd-plugins
sudo systemctl enable --now auditd
systemctl is-active auditd
systemctl is-enabled auditd
```

J’ai créé `/etc/audit/rules.d/50-hardening.rules` afin de surveiller les fichiers sensibles :

```text
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege
-w /etc/ssh/sshd_config -p wa -k ssh
-w /etc/ssh/sshd_config.d/ -p wa -k ssh
```

`w` surveille les écritures, `a` les changements d’attributs et les clés facilitent les recherches avec `ausearch`.

```bash
# on recharge les règles et on vérifie qu’elles sont bien prises en compte
sudo augenrules --load
sudo auditctl -l
sudo ausearch -k identity
```

Ces logs d'audit peuvent être consultés avec `ausearch` ou `journalctl -k`.

### Journal persistant

J’ai créé `/etc/systemd/journald.conf.d/99-persistent.conf` avec le contenu suivant :

```ini
[Journal]
Storage=persistent
SystemMaxUse=200M
```
Je créée ensuite le journal, redémarre le service, flush pour transferer les données en RAM vers le nouveau espace disque et on vérifie l’espace disque utilisé par le journal :

```bash
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo systemctl restart systemd-journald
sudo journalctl --flush
journalctl --disk-usage
```

### AIDE

AIDE vérifie l’intégrité des fichiers en les comparant avec une base de référence :

```bash
# on initialise la base de référence AIDE
sudo apt install -y aide aide-common
sudo /usr/sbin/aideinit --yes --force
```

Sur ma VM, l’initialisation a duré 13 minutes.

```bash
# ici je vérifie que la base a été créée et que les contrôles passent
sudo ls -lh /var/lib/aide/aide.db
sudo aide --config=/etc/aide/aide.conf --check
```

J’utilise explicitement `--config=/etc/aide/aide.conf`, car la commande générique `sudo aide --check` ne trouve pas automatiquement le fichier de configuration sur cette installation Debian. J’ai obtenu une base `/var/lib/aide/aide.db` d’environ 54 Mo. Les six contrôles de journalisation et d’intégrité passent.

## K. Mises à jour
Je commence par installer le paquet `unattended-upgrades` pour activer les mises à jour automatiques :

```bash
sudo apt install -y unattended-upgrades
```

J’ai créé `/etc/apt/apt.conf.d/20auto-upgrades` avec le contenu suivant :

```text
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::"Unattended-Upgrade" "1";
APT::Periodic::AutocleanInterval "7";
```

J’ai activé les minuteurs immédiatement et au démarrage :

```bash
sudo systemctl enable --now apt-daily.timer
sudo systemctl enable --now apt-daily-upgrade.timer
```

J’ai vérifié la configuration comprise par APT ainsi que l’état réel des services :

```bash
apt-config dump | grep '^APT::Periodic::Unattended-Upgrade'
systemctl is-enabled unattended-upgrades.service
systemctl is-active unattended-upgrades.service
systemctl is-enabled apt-daily-upgrade.timer
systemctl is-active apt-daily-upgrade.timer
systemctl list-timers apt-daily.timer apt-daily-upgrade.timer --all
```

Après le redémarrage, j’ai constaté que le service et les deux minuteurs étaient actifs. La version fournie de `check-debian.sh` cherche un guillemet immédiatement après `Unattended-Upgrade`.  
 Je valide avec le dernier composant de la clé entre guillemets

```bash
APT::Periodic::"Unattended-Upgrade" "1";
```

J’ai confirmé qu’APT interprète cette écriture de la même manière :

```bash
apt-config dump | grep '^APT::Periodic::Unattended-Upgrade'
```

Elle affiche `APT::Periodic::Unattended-Upgrade "1";`.

Avec la version du 09/09/2026 du check-debian le test passe, et le service est bien actif après redémarrage.

## Vérification finale

### Automatisation du durcissement

J’ai regroupé les opérations décrites dans ce rapport dans `hardening.sh`. Je lance ce script depuis la VM avec les privilèges root :

```bash
chmod +x hardening.sh
sudo ./hardening.sh
```

Il synchronise d’abord l’horloge par NTP afin que les dépôts APT soient utilisables. Il sauvegarde ensuite les fichiers remplacés sous `/root/hardening-backups/`. Si aucune clé publique n’est installée pour le compte administrateur, il me demande de la coller, vérifie son format avec `ssh-keygen`, puis l’ajoute à `authorized_keys` avec les permissions adaptées. Il ne désactive l’authentification SSH par mot de passe qu’après cette installation. Il vérifie aussi nginx après les changements sensibles et relance `check-debian.sh` lorsqu’il le trouve à côté du script ou dans `kit-vm/`.

Le script peut être relancé : les règles et fichiers générés sont remplacés proprement, et la base AIDE existante est conservée lorsqu’elle est valide. Sur une VM non encore initialisée, la création de cette base peut ajouter plus de quinze minutes à l’exécution.

J’ai redémarré la VM afin de vérifier la persistance :

```bash
sudo reboot
```

J’ai également vérifié que le service métier répondait en HTTP 200 et que la base AIDE de 54 Mo était toujours présente.

```bash
systemctl is-active ssh nginx nftables auditd apparmor unattended-upgrades
systemctl is-active apt-daily.timer apt-daily-upgrade.timer
curl -fsS http://127.0.0.1:8080/health
sudo aa-status
sudo auditctl -l
sudo ls -lh /var/lib/aide/aide.db
sudo ./kit-vm/check-debian.sh
sudo lynis audit system
```

Résultat du script après redémarrage :

```text
Contrôles réussis : 58 / 58
Score technique   : 60 / 60
```

Les 58 contrôles passent. Le service métier reste disponible et les configurations persistent après redémarrage.

Je refais un audit lynis pour voir les différences après le hardening et on peut voir une nette amélioration.
