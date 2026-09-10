#!/usr/bin/env bash
# Durcissement de la VM Debian 12 du TP1.
# A lancer depuis le dossier contenant configs/ : sudo ./hardening.sh

set -Eeuo pipefail
umask 027

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERREUR] Lancez ce script avec sudo."
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/configs/etc"
ADMIN_USER="${HARDENING_ADMIN_USER:-${SUDO_USER:-moutsss}}"
if [ "$ADMIN_USER" = root ]; then
    ADMIN_USER=moutsss
fi

if [ ! -d "$CONFIG_DIR" ]; then
    echo "[ERREUR] Le dossier $CONFIG_DIR est introuvable."
    exit 1
fi

if ! id "$ADMIN_USER" >/dev/null 2>&1; then
    echo "[ERREUR] Le compte administrateur $ADMIN_USER n'existe pas."
    exit 1
fi

BACKUP_DIR="/root/hardening-backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Sauvegarde des principales configurations avant modification.
tar --ignore-failed-read -czf "$BACKUP_DIR/configurations-avant.tar.gz" \
    /etc/login.defs \
    /etc/security/pwquality.conf \
    /etc/security/faillock.conf \
    /etc/pam.d/common-auth \
    /etc/pam.d/common-account \
    /etc/pam.d/common-password \
    /etc/sudoers.d \
    /etc/ssh/sshd_config.d \
    /etc/nftables.conf \
    /etc/sysctl.d \
    /etc/apparmor.d/usr.sbin.nginx \
    /etc/systemd/system/nginx.service.d \
    /etc/audit/rules.d \
    /etc/systemd/journald.conf.d \
    /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || true

echo "=== Installation des paquets ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
    nginx openssh-server sudo curl ca-certificates \
    libpam-pwquality libpam-modules \
    nftables apparmor apparmor-utils \
    auditd audispd-plugins \
    aide aide-common unattended-upgrades
apt-get upgrade -y

echo "=== A. Service metier ==="
systemctl enable --now nginx
nginx -t
curl -fsS http://127.0.0.1:8080/health | grep -q OK

echo "=== B. Comptes et authentification ==="

# Suppression du compte inutile.
if id stagiaire >/dev/null 2>&1; then
    pkill -u stagiaire 2>/dev/null || true
    userdel -r stagiaire
fi

# Les comptes de service ne doivent pas avoir de shell interactif.
id deploy >/dev/null 2>&1 && usermod -s /usr/sbin/nologin deploy
id sauvegarde >/dev/null 2>&1 && usermod -s /usr/sbin/nologin sauvegarde

# Politique d'expiration pour les futurs comptes.
sed -ri \
    -e 's/^[#[:space:]]*PASS_MAX_DAYS[[:space:]]+.*/PASS_MAX_DAYS   90/' \
    -e 's/^[#[:space:]]*PASS_MIN_DAYS[[:space:]]+.*/PASS_MIN_DAYS   1/' \
    -e 's/^[#[:space:]]*PASS_WARN_AGE[[:space:]]+.*/PASS_WARN_AGE   14/' \
    /etc/login.defs

# Application aux comptes deja existants.
for user in moutsss alice bob; do
    if id "$user" >/dev/null 2>&1; then
        chage -M 90 -m 1 -W 14 "$user"
    fi
done

# Qualite des mots de passe et verrouillage apres cinq echecs.
install -o root -g root -m 0644 \
    "$CONFIG_DIR/security/pwquality.conf" /etc/security/pwquality.conf
install -o root -g root -m 0644 \
    "$CONFIG_DIR/security/faillock.conf" /etc/security/faillock.conf

# Ajout de pam_pwquality avant pam_unix.
if grep -qE '^[[:space:]]*password.*pam_pwquality\.so' /etc/pam.d/common-password; then
    sed -ri 's|^[[:space:]]*password.*pam_pwquality\.so.*$|password requisite pam_pwquality.so retry=3|' \
        /etc/pam.d/common-password
else
    sed -i '/^[[:space:]]*password.*pam_unix\.so/i password requisite pam_pwquality.so retry=3' \
        /etc/pam.d/common-password
fi

# Ajout de pam_faillock autour de pam_unix.
awk '
    /pam_faillock\.so/ { next }
    !done && /pam_unix\.so/ {
        print "auth required pam_faillock.so preauth"
        sub(/\[success=[0-9]+/, "[success=2")
        print
        print "auth [default=die] pam_faillock.so authfail"
        done=1
        next
    }
    { print }
    END { if (!done) exit 1 }
' /etc/pam.d/common-auth > /tmp/common-auth.hardening
install -o root -g root -m 0644 /tmp/common-auth.hardening /etc/pam.d/common-auth
rm -f /tmp/common-auth.hardening

sed -i '/pam_faillock\.so/d' /etc/pam.d/common-account
printf '%s\n' 'account required pam_faillock.so' >> /etc/pam.d/common-account

for user in moutsss alice bob; do
    id "$user" >/dev/null 2>&1 && faillock --user "$user" --reset 2>/dev/null || true
done

echo "=== C. Sudo ==="
rm -f /etc/sudoers.d/99-laxiste
visudo -cf "$CONFIG_DIR/sudoers.d/logging"
install -o root -g root -m 0440 \
    "$CONFIG_DIR/sudoers.d/logging" /etc/sudoers.d/logging
visudo -c

echo "=== D. SSH ==="

# Ne pas desactiver le mot de passe avant d'avoir installe une cle publique.
SSH_DIR="/home/$ADMIN_USER/.ssh"
AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"
if [ ! -s "$AUTHORIZED_KEYS" ]; then
    echo "[ERREUR] Aucune cle publique dans $AUTHORIZED_KEYS."
    echo "Installez la cle de l'hote avant de relancer le script."
    exit 1
fi

chown -R "$ADMIN_USER:$(id -gn "$ADMIN_USER")" "$SSH_DIR"
chmod 0700 "$SSH_DIR"
chmod 0600 "$AUTHORIZED_KEYS"

rm -f /etc/ssh/sshd_config.d/00-laxiste.conf
sed "s/^AllowUsers .*/AllowUsers $ADMIN_USER alice bob/" \
    "$CONFIG_DIR/ssh/sshd_config.d/00-durcissement.conf" \
    > /tmp/00-durcissement.conf
install -o root -g root -m 0644 \
    /tmp/00-durcissement.conf /etc/ssh/sshd_config.d/00-durcissement.conf
rm -f /tmp/00-durcissement.conf
install -o root -g root -m 0644 "$CONFIG_DIR/issue.net" /etc/issue.net

sshd -t
systemctl enable --now ssh
systemctl reload ssh

echo "=== E. Services et paquets inutiles ==="
for service in \
    rpcbind.service rpcbind.socket \
    avahi-daemon.service avahi-daemon.socket \
    nfs-server.service xinetd.service; do
    systemctl disable --now "$service" >/dev/null 2>&1 || true
done
apt-get purge -y telnetd xinetd rpcbind nfs-kernel-server avahi-daemon

echo "=== F. Pare-feu nftables ==="
nft -c -f "$CONFIG_DIR/nftables.conf"
install -o root -g root -m 0755 "$CONFIG_DIR/nftables.conf" /etc/nftables.conf
nft -f /etc/nftables.conf
systemctl enable --now nftables

echo "=== G. Permissions et SUID ==="
chown root:shadow /etc/shadow
chmod 0640 /etc/shadow

if [ -d /srv/metier ]; then
    chown -R root:root /srv/metier
    find /srv/metier -type d -exec chmod 0755 {} +
    find /srv/metier -type f -exec chmod 0644 {} +
fi

if [ -d /opt/scripts ]; then
    chown -R root:root /opt/scripts
    find /opt/scripts -type d -exec chmod 0755 {} +
    find /opt/scripts -type f -exec chmod 0750 {} +
fi

rm -f /usr/local/bin/find-suid
find /etc -xdev -type f -perm -0002 -exec chmod o-w {} +

echo "=== H. Reglages noyau ==="
rm -f /etc/sysctl.d/99-laxiste.conf
install -o root -g root -m 0644 \
    "$CONFIG_DIR/sysctl.d/99-z-durcissement.conf" \
    /etc/sysctl.d/99-z-durcissement.conf
sysctl --system >/dev/null

echo "=== I. AppArmor et confinement systemd ==="
systemctl enable --now apparmor
systemctl restart apparmor

apparmor_parser -Q "$CONFIG_DIR/apparmor.d/usr.sbin.nginx"
install -o root -g root -m 0600 \
    "$CONFIG_DIR/apparmor.d/usr.sbin.nginx" /etc/apparmor.d/usr.sbin.nginx
apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx
aa-enforce /usr/sbin/nginx

# Le bareme demande qu'aucun profil ne reste en mode complain.
for profile in \
    /etc/apparmor.d/usr.lib.libreoffice.program.soffice.bin \
    /etc/apparmor.d/usr.lib.libreoffice.program.oosplash; do
    [ -f "$profile" ] && aa-enforce "$profile"
done

install -d -o root -g root -m 0755 /etc/systemd/system/nginx.service.d
install -o root -g root -m 0644 \
    "$CONFIG_DIR/systemd/system/nginx.service.d/hardening.conf" \
    /etc/systemd/system/nginx.service.d/hardening.conf
systemctl daemon-reload
nginx -t
systemctl restart nginx
curl -fsS http://127.0.0.1:8080/health | grep -q OK

echo "=== J. Journalisation et integrite ==="
install -o root -g root -m 0640 \
    "$CONFIG_DIR/audit/rules.d/50-hardening.rules" \
    /etc/audit/rules.d/50-hardening.rules
systemctl enable --now auditd
augenrules --load

rm -f /etc/systemd/journald.conf.d/99-laxiste.conf
install -d -o root -g root -m 0755 /etc/systemd/journald.conf.d
install -o root -g root -m 0644 \
    "$CONFIG_DIR/systemd/journald.conf.d/99-persistent.conf" \
    /etc/systemd/journald.conf.d/99-persistent.conf
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald
journalctl --flush

# L'initialisation AIDE peut durer plus de quinze minutes.
if [ ! -s /var/lib/aide/aide.db ]; then
    /usr/sbin/aideinit --yes --force
fi

echo "=== K. Mises a jour automatiques ==="
install -o root -g root -m 0644 \
    "$CONFIG_DIR/apt/apt.conf.d/20auto-upgrades" \
    /etc/apt/apt.conf.d/20auto-upgrades
systemctl enable --now unattended-upgrades.service
systemctl enable --now apt-daily.timer apt-daily-upgrade.timer

echo "=== Verification finale ==="
nginx -t
sshd -t
visudo -c
nft -c -f /etc/nftables.conf
curl -fsS http://127.0.0.1:8080/health | grep -q OK

CHECKER="$SCRIPT_DIR/kit-vm/check-debian.sh"
if [ ! -f "$CHECKER" ]; then
    CHECKER="$SCRIPT_DIR/check-debian.sh"
fi

if [ -f "$CHECKER" ]; then
    bash "$CHECKER"
else
    echo "[ATTENTION] check-debian.sh est introuvable."
fi

echo
echo "Sauvegarde : $BACKUP_DIR/configurations-avant.tar.gz"
echo "Redemarrez ensuite la VM et relancez check-debian.sh."
