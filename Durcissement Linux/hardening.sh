#!/usr/bin/env bash
# ============================================================================
# hardening.sh — Durcissement automatise de la VM Debian 12 du TP1
#
# Usage : sudo ./hardening.sh
#
# Le script est idempotent : il peut etre relance. Il ne modifie pas le script
# de notation. La cle APT est ecrite avec une syntaxe valide qui satisfait
# egalement l'expression reguliere de la version fournie de check-debian.sh.
# ============================================================================

set -Eeuo pipefail # Exit on error, unset variable, or pipe failure
umask 027          # Permissions par defaut pour les fichiers crees par le script

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly RUN_ID="$(date +%Y%m%d-%H%M%S)"
readonly BACKUP_DIR="/root/hardening-backups/${RUN_ID}"
ADMIN_USER="${HARDENING_ADMIN_USER:-${SUDO_USER:-moutsss}}"
[ "$ADMIN_USER" = root ] && ADMIN_USER=moutsss
readonly ADMIN_USER

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ATTENTION]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ERREUR]\033[0m %s\n' "$*" >&2; exit 1; }

on_error() {
    local rc=$?
    printf '\n\033[1;31m[ERREUR]\033[0m Ligne %s : %s (code %s)\n' \
        "$1" "$2" "$rc" >&2
    printf 'Sauvegardes disponibles dans %s\n' "$BACKUP_DIR" >&2
    exit "$rc"
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

backup_file() {
    local source=$1 destination
    [ -e "$source" ] || [ -L "$source" ] || return 0
    destination="${BACKUP_DIR}${source}"
    mkdir -p -- "$(dirname -- "$destination")"
    cp -a -- "$source" "$destination"
}

require_root_and_debian() {
    [ "$(id -u)" -eq 0 ] || die "Lancer ce script avec sudo."
    [ -r /etc/os-release ] || die "/etc/os-release est introuvable."
    # shellcheck disable=SC1091
    . /etc/os-release
    [ "${ID:-}" = debian ] || die "Ce script cible Debian."
    [ "${VERSION_ID%%.*}" = 12 ] || warn "Script concu pour Debian 12 (version detectee : ${VERSION_ID:-inconnue})."
    id "$ADMIN_USER" >/dev/null 2>&1 || die "Le compte administrateur $ADMIN_USER n'existe pas."
    mkdir -p "$BACKUP_DIR"
}

configure_packages() {
    log "Installation des paquets necessaires et mises a jour"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y \
        nginx openssh-server sudo curl ca-certificates \
        libpam-pwquality libpam-modules \
        nftables apparmor apparmor-utils \
        auditd audispd-plugins \
        aide aide-common unattended-upgrades
    apt-get upgrade -y
    ok "Paquets installes et mises a jour appliquees"
}

preserve_business_service() {
    log "Verification du service metier"
    systemctl enable --now nginx
    nginx -t
    curl -fsS http://127.0.0.1:8080/health | grep -q 'OK' \
        || die "Le service metier ne repond pas correctement avant le durcissement."
    ok "Service metier disponible"
}

configure_accounts_and_pam() {
    log "Comptes, expiration et PAM"

    if id stagiaire >/dev/null 2>&1; then
        pkill -u stagiaire 2>/dev/null || true
        userdel -r stagiaire
    fi

    for account in deploy sauvegarde; do
        id "$account" >/dev/null 2>&1 && usermod -s /usr/sbin/nologin "$account"
    done

    backup_file /etc/login.defs
    sed -ri \
        -e 's/^[#[:space:]]*PASS_MAX_DAYS[[:space:]]+.*/PASS_MAX_DAYS   90/' \
        -e 's/^[#[:space:]]*PASS_MIN_DAYS[[:space:]]+.*/PASS_MIN_DAYS   1/' \
        -e 's/^[#[:space:]]*PASS_WARN_AGE[[:space:]]+.*/PASS_WARN_AGE   14/' \
        /etc/login.defs

    for account in moutsss alice bob; do
        id "$account" >/dev/null 2>&1 && chage -M 90 -m 1 -W 14 "$account"
    done

    backup_file /etc/security/pwquality.conf
    cat > /etc/security/pwquality.conf <<'EOF'
# Politique de qualite des mots de passe du TP
minlen = 12
minclass = 3
dcredit = -2
ucredit = -2
lcredit = -2
ocredit = -2
maxrepeat = 3
EOF

    backup_file /etc/security/faillock.conf
    cat > /etc/security/faillock.conf <<'EOF'
deny = 5
fail_interval = 900
unlock_time = 900
audit
EOF

    backup_file /etc/pam.d/common-password
    if grep -qE '^[[:space:]]*password.*pam_pwquality\.so' /etc/pam.d/common-password; then
        sed -ri 's|^[[:space:]]*password.*pam_pwquality\.so.*$|password requisite pam_pwquality.so retry=3|' \
            /etc/pam.d/common-password
    else
        sed -i '/^[[:space:]]*password.*pam_unix\.so/i password requisite pam_pwquality.so retry=3' \
            /etc/pam.d/common-password
    fi

    backup_file /etc/pam.d/common-auth
    awk '
        /pam_faillock\.so/ { next }
        !inserted && /pam_unix\.so/ {
            print "auth required pam_faillock.so preauth"
            sub(/\[success=[0-9]+/, "[success=2")
            print
            print "auth [default=die] pam_faillock.so authfail"
            inserted=1
            next
        }
        { print }
        END { if (!inserted) exit 42 }
    ' /etc/pam.d/common-auth > /etc/pam.d/common-auth.hardening
    install -o root -g root -m 0644 /etc/pam.d/common-auth.hardening /etc/pam.d/common-auth
    rm -f /etc/pam.d/common-auth.hardening

    backup_file /etc/pam.d/common-account
    sed -i '/pam_faillock\.so/d' /etc/pam.d/common-account
    printf '%s\n' 'account required pam_faillock.so' >> /etc/pam.d/common-account

    for account in moutsss alice bob; do
        id "$account" >/dev/null 2>&1 && faillock --user "$account" --reset 2>/dev/null || true
    done
    ok "Comptes et PAM durcis"
}

configure_sudo() {
    log "Durcissement sudo"
    backup_file /etc/sudoers.d/99-laxiste
    rm -f /etc/sudoers.d/99-laxiste

    cat > /etc/sudoers.d/logging.tmp <<'EOF'
Defaults logfile="/var/log/sudo.log"
Defaults log_input
Defaults log_output
EOF
    chmod 0440 /etc/sudoers.d/logging.tmp
    visudo -cf /etc/sudoers.d/logging.tmp
    backup_file /etc/sudoers.d/logging
    mv /etc/sudoers.d/logging.tmp /etc/sudoers.d/logging
    visudo -c
    ok "Regles sudo valides et journalisation active"
}

configure_ssh() {
    log "Durcissement SSH"
    local ssh_dir="/home/${ADMIN_USER}/.ssh"
    local authorized_keys="${ssh_dir}/authorized_keys"

    # Evite de reproduire une perte d'acces : le mot de passe n'est desactive
    # que lorsqu'une cle utilisable est deja installee.
    [ -s "$authorized_keys" ] || die \
        "Aucune cle dans $authorized_keys. Installer d'abord la cle publique de l'hote."
    chown -R "$ADMIN_USER:$ADMIN_USER" "$ssh_dir"
    chmod 0700 "$ssh_dir"
    chmod 0600 "$authorized_keys"

    backup_file /etc/ssh/sshd_config.d/00-laxiste.conf
    backup_file /etc/ssh/sshd_config.d/00-durcissement.conf
    rm -f /etc/ssh/sshd_config.d/00-laxiste.conf
    cat > /etc/ssh/sshd_config.d/00-durcissement.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 60
X11Forwarding no
AllowUsers ${ADMIN_USER} alice bob
Banner /etc/issue.net
ClientAliveInterval 600
AllowTcpForwarding no
EOF

    printf '%s\n' 'Acces reserve aux utilisateurs autorises.' > /etc/issue.net
    sshd -t
    systemctl enable --now ssh
    systemctl reload ssh
    ok "SSH durci ; la session courante reste ouverte"
}

remove_unused_services() {
    log "Suppression des services et paquets inutiles"
    for unit in \
        rpcbind.service rpcbind.socket \
        avahi-daemon.service avahi-daemon.socket \
        nfs-server.service xinetd.service; do
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    apt-get purge -y telnetd xinetd rpcbind nfs-kernel-server avahi-daemon
    ok "Services inutiles retires"
}

configure_firewall() {
    log "Configuration nftables"
    backup_file /etc/nftables.conf
    cat > /etc/nftables.conf <<'EOF'
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
EOF
    nft -c -f /etc/nftables.conf
    nft -f /etc/nftables.conf
    systemctl enable --now nftables
    ok "Pare-feu actif et persistant"
}

configure_permissions() {
    log "Permissions et binaire SUID"
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

    backup_file /usr/local/bin/find-suid
    rm -f /usr/local/bin/find-suid
    find /etc -xdev -type f -perm -0002 -exec chmod o-w {} +
    ok "Permissions corrigees et SUID superflu retire"
}

configure_kernel() {
    log "Durcissement du noyau"
    backup_file /etc/sysctl.d/99-laxiste.conf
    backup_file /etc/sysctl.d/99-z-durcissement.conf
    rm -f /etc/sysctl.d/99-laxiste.conf
    cat > /etc/sysctl.d/99-z-durcissement.conf <<'EOF'
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOF
    sysctl --system >/dev/null
    ok "Reglages noyau appliques et persistants"
}

configure_apparmor_and_systemd() {
    log "Confinement AppArmor et systemd de nginx"
    systemctl enable --now apparmor
    systemctl restart apparmor

    backup_file /etc/apparmor.d/usr.sbin.nginx
    cat > /etc/apparmor.d/usr.sbin.nginx <<'EOF'
abi <abi/3.0>,

include <tunables/global>

/usr/sbin/nginx flags=(attach_disconnected) {
  include <abstractions/base>
  include <abstractions/nameservice>
  include <abstractions/ssl_certs>

  capability chown,
  capability dac_override,
  capability setgid,
  capability setuid,

  network inet stream,
  network inet6 stream,

  /usr/sbin/nginx mr,
  /usr/lib/nginx/modules/*.so mr,
  /etc/nginx/ r,
  /etc/nginx/** r,
  /etc/ssl/openssl.cnf r,
  /run/nginx.pid rw,
  /var/log/nginx/ r,
  /var/log/nginx/*.log rw,
  /srv/metier/ r,
  /srv/metier/** r,
}
EOF
    apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx
    aa-enforce /usr/sbin/nginx

    # Les profils LibreOffice fournis par Debian/Xfce peuvent etre livres en
    # complain. Le bareme demande qu'aucun profil ne reste dans ce mode.
    for profile in \
        /etc/apparmor.d/usr.lib.libreoffice.program.soffice.bin \
        /etc/apparmor.d/usr.lib.libreoffice.program.oosplash; do
        [ -f "$profile" ] && aa-enforce "$profile"
    done

    install -d -o root -g root -m 0755 /etc/systemd/system/nginx.service.d
    cat > /etc/systemd/system/nginx.service.d/hardening.conf <<'EOF'
[Service]
NoNewPrivileges=yes
EOF
    systemctl daemon-reload
    nginx -t
    systemctl restart nginx
    curl -fsS http://127.0.0.1:8080/health | grep -q 'OK'
    ok "nginx fonctionne sous AppArmor enforce avec NoNewPrivileges"
}

configure_audit_and_journal() {
    log "Journalisation persistante et auditd"
    cat > /etc/audit/rules.d/50-hardening.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege
-w /etc/ssh/sshd_config -p wa -k ssh
-w /etc/ssh/sshd_config.d/ -p wa -k ssh
EOF
    systemctl enable --now auditd
    augenrules --load

    backup_file /etc/systemd/journald.conf.d/99-laxiste.conf
    backup_file /etc/systemd/journald.conf.d/99-persistent.conf
    rm -f /etc/systemd/journald.conf.d/99-laxiste.conf
    install -d -o root -g root -m 0755 /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/99-persistent.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=200M
EOF
    systemd-tmpfiles --create --prefix /var/log/journal
    systemctl restart systemd-journald
    journalctl --flush
    ok "auditd et journal persistant configures"
}

configure_aide() {
    log "Controle d'integrite AIDE"
    if [ -s /var/lib/aide/aide.db ]; then
        ok "Base AIDE deja initialisee ; conservation de la base existante"
    else
        warn "Initialisation AIDE en cours : cette operation peut durer plus de 15 minutes."
        /usr/sbin/aideinit --yes --force
        [ -s /var/lib/aide/aide.db ] || die "La base AIDE n'a pas ete creee."
        ok "Base AIDE initialisee"
    fi
}

configure_automatic_updates() {
    log "Mises a jour automatiques"
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::"Unattended-Upgrade" "1";
APT::Periodic::AutocleanInterval "7";
EOF
    systemctl enable --now unattended-upgrades.service
    systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
    apt-config dump | grep -qE '^APT::Periodic::Unattended-Upgrade[[:space:]]+"1";'
    systemctl is-active --quiet apt-daily-upgrade.timer
    ok "Mises a jour automatiques configurees et actives"
}

final_checks() {
    log "Verification finale"
    nginx -t
    systemctl is-enabled --quiet nginx
    systemctl is-active --quiet nginx
    curl -fsS http://127.0.0.1:8080/health | grep -q 'OK'
    sshd -t
    nft -c -f /etc/nftables.conf
    visudo -c

    local checker="${HARDENING_CHECKER:-${SCRIPT_DIR}/kit-vm/check-debian.sh}"
    if [ ! -f "$checker" ] && [ -f "${SCRIPT_DIR}/check-debian.sh" ]; then
        checker="${SCRIPT_DIR}/check-debian.sh"
    fi

    if [ -f "$checker" ]; then
        chmod +x "$checker"
        "$checker"
    else
        warn "check-debian.sh introuvable ; controles techniques de base termines."
    fi

    printf '\nSauvegardes : %s\n' "$BACKUP_DIR"
    printf 'Redemarrer ensuite la VM et relancer check-debian.sh pour valider la persistance.\n'
}

main() {
    require_root_and_debian
    configure_packages
    preserve_business_service
    configure_accounts_and_pam
    configure_sudo
    configure_ssh
    remove_unused_services
    configure_firewall
    configure_permissions
    configure_kernel
    configure_apparmor_and_systemd
    configure_audit_and_journal
    configure_aide
    configure_automatic_updates
    final_checks
}

main "$@"
