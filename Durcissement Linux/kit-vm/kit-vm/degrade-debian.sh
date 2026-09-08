#!/usr/bin/env bash
# =====================================================================
#  degrade-debian.sh — Mise en place de la baseline dégradée (TP noté)
#  Cours : Durcissement Linux et Windows — 5e année
#
#  A EXECUTER UNIQUEMENT DANS LA VM DE TP, JAMAIS SUR UNE MACHINE REELLE.
#  Cible : Debian 12 (bookworm) fraichement installee, en root.
#
#  Ce script ne contient aucun code d'exploitation. Il remet le systeme
#  dans un etat de configuration volontairement laxiste, comparable a ce
#  qu'on trouve sur un serveur jamais administre.
# =====================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] A lancer en root (sudo -i)."; exit 1
fi

cat << 'WARN'
------------------------------------------------------------------
 Ce script degrade volontairement la configuration de la machine.
 Il est destine a une VM de laboratoire isolee (reseau host-only ou NAT).
 Ne pas l'executer sur un poste personnel ou un serveur de production.
------------------------------------------------------------------
WARN
read -r -p "Taper OUI en majuscules pour continuer : " OK
[ "$OK" = "OUI" ] || { echo "Abandon."; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx openssh-server rsync cron nano curl >/dev/null

# --- 1. Service metier a preserver : nginx sur 8080 + page de sante ---
mkdir -p /srv/metier
cat > /srv/metier/index.html << 'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>Service metier</title></head>
<body><h1>Application metier</h1><p>Ce service doit rester accessible.</p></body></html>
HTML
echo "OK" > /srv/metier/health
cat > /etc/nginx/sites-available/metier << 'NGINX'
server {
    listen 8080;
    server_name _;
    root /srv/metier;
    index index.html;
    location /health { default_type text/plain; }
}
NGINX
ln -sf /etc/nginx/sites-available/metier /etc/nginx/sites-enabled/metier
rm -f /etc/nginx/sites-enabled/default
systemctl enable --now nginx >/dev/null 2>&1
systemctl restart nginx

# --- 2. Comptes et mots de passe laxistes ---
for U in alice bob stagiaire sauvegarde; do
  id "$U" >/dev/null 2>&1 || useradd -m -s /bin/bash "$U"
done
echo 'alice:alice'         | chpasswd
echo 'bob:123456'          | chpasswd
echo 'stagiaire:stagiaire' | chpasswd
echo 'sauvegarde:backup'   | chpasswd
# compte de service inutile avec shell interactif
id deploy >/dev/null 2>&1 || useradd -m -s /bin/bash deploy
echo 'deploy:deploy' | chpasswd
# aucune politique d'expiration
for U in alice bob stagiaire sauvegarde deploy; do chage -M 99999 -m 0 -W 7 "$U"; done

# --- 3. sudo trop permissif ---
cat > /etc/sudoers.d/99-laxiste << 'SUDO'
stagiaire ALL=(ALL) NOPASSWD: ALL
bob ALL=(ALL) NOPASSWD: /bin/bash
alice ALL=(ALL) NOPASSWD: /usr/bin/find
SUDO
chmod 0440 /etc/sudoers.d/99-laxiste

# --- 4. SSH ouvert a tous les vents ---
cat > /etc/ssh/sshd_config.d/00-laxiste.conf << 'SSHD'
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
X11Forwarding yes
MaxAuthTries 10
LoginGraceTime 300
ClientAliveInterval 0
AllowTcpForwarding yes
SSHD
systemctl enable --now ssh >/dev/null 2>&1
systemctl restart ssh

# --- 5. Services et paquets inutiles actives ---
apt-get install -y -qq telnetd rpcbind nfs-kernel-server avahi-daemon xinetd >/dev/null 2>&1
systemctl enable --now rpcbind avahi-daemon >/dev/null 2>&1

# --- 6. Permissions de fichiers incorrectes ---
chmod 666 /etc/shadow 2>/dev/null
chmod 777 /srv/metier
mkdir -p /opt/scripts && chmod 777 /opt/scripts
cat > /opt/scripts/backup.sh << 'BAK'
#!/bin/bash
# script de sauvegarde maison
rsync -a /srv/metier/ /var/backups/metier/
BAK
chmod 777 /opt/scripts/backup.sh
# binaire SUID superflu
cp /usr/bin/find /usr/local/bin/find-suid 2>/dev/null && chmod 4755 /usr/local/bin/find-suid

# --- 7. Cron non maitrise ---
echo '*/5 * * * * root /opt/scripts/backup.sh' > /etc/cron.d/backup-metier
chmod 644 /etc/cron.d/backup-metier

# --- 8. Noyau : protections desactivees ---
cat > /etc/sysctl.d/99-laxiste.conf << 'SYSCTL'
kernel.randomize_va_space = 0
kernel.dmesg_restrict = 0
kernel.kptr_restrict = 0
kernel.unprivileged_bpf_disabled = 0
fs.suid_dumpable = 2
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.tcp_syncookies = 0
net.ipv4.ip_forward = 1
SYSCTL
sysctl --system >/dev/null 2>&1

# --- 9. Pare-feu et MAC desactives ---
systemctl disable --now nftables >/dev/null 2>&1
apt-get purge -y -qq ufw >/dev/null 2>&1
systemctl disable --now apparmor >/dev/null 2>&1
aa-teardown >/dev/null 2>&1

# --- 10. Journalisation reduite au minimum ---
apt-get purge -y -qq auditd >/dev/null 2>&1
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-laxiste.conf << 'JRN'
[Journal]
Storage=volatile
SystemMaxUse=10M
JRN
systemctl restart systemd-journald >/dev/null 2>&1

# --- 11. Bannieres et divers ---
echo "Bienvenue sur le serveur de production - contact: admin@ecole.local" > /etc/issue.net
sed -i 's/^#Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config 2>/dev/null

echo
echo "[OK] Baseline degradee installee."
echo "     Service metier : http://127.0.0.1:8080/health  -> doit repondre OK"
echo "     Faites un instantane (snapshot) MAINTENANT, nomme 'baseline'."
