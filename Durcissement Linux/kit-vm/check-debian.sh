#!/usr/bin/env bash
# =====================================================================
#  check-debian.sh — Verification automatique du TP1 (Linux)
#  Fourni AUX ETUDIANTS des le lancement du TP : le bareme est public.
#  Sortie : liste de controles PASS/FAIL + score technique /60.
#  Le score technique est ensuite converti par l'enseignant (cf. grille).
#
#  Revision 2026-09-08 :
#   - le test eliminatoire n'utilise plus curl (absent d'une Debian
#     minimale) : bash /dev/tcp, avec repli sur curl ou wget ;
#   - permissions de /etc/shadow comparees en octal et non en decimal ;
#   - AppArmor : le seuil "10 profils" est remplace par un controle du
#     chargement effectif + un profil metier en enforce ;
#   - journal persistant : verifie aussi que Storage n'est pas volatile ;
#   - ajout des controles manquants correspondant a des etapes notees
#     (authentification par cle, journalisation sudo, confinement
#     systemd de l'unite metier).
# =====================================================================
set -u
PASS=0; FAIL=0; TOTAL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
ko(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }
chk(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else ko "$1"; fi; }
sec(){ echo; echo "=== $1 ==="; }

[ "$(id -u)" -ne 0 ] && { echo "A lancer en root."; exit 1; }

# --- Test du service metier, sans dependance a un paquet installable ---
# bash sait ouvrir une socket TCP tout seul : aucun binaire externe requis.
# Un etudiant qui purge curl a l'etape 5 ne doit pas etre plafonne a 8/20
# pour cette raison.
metier_repond(){
  local rep
  rep=$(
    exec 3<>/dev/tcp/127.0.0.1/8080 2>/dev/null || exit 1
    printf 'GET /health HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' >&3
    timeout 5 cat <&3
  ) 2>/dev/null && printf '%s' "$rep" | grep -q '^OK' && return 0
  command -v curl >/dev/null 2>&1 && curl -fs --max-time 5 http://127.0.0.1:8080/health 2>/dev/null | grep -q OK && return 0
  command -v wget >/dev/null 2>&1 && wget -qO- --timeout=5 http://127.0.0.1:8080/health 2>/dev/null | grep -q OK && return 0
  return 1
}

# Compare un mode de fichier a un masque, en octal (et non en decimal :
# "640" lu comme un entier decimal donne des comparaisons fausses).
mode_sans(){ # $1 = fichier, $2 = masque octal interdit
  local m; m=$(stat -c '%a' "$1" 2>/dev/null) || return 1
  [ $(( 8#$m & 8#$2 )) -eq 0 ]
}

sec "A. SERVICE METIER (eliminatoire)"
if metier_repond; then
  ok "Le service metier repond sur 8080/health"
  METIER=1
else
  ko "SERVICE METIER INDISPONIBLE -> plafond de note applique"
  METIER=0
fi
chk "nginx est actif et demarre au boot" "systemctl is-enabled nginx && systemctl is-active nginx"

sec "B. COMPTES ET AUTHENTIFICATION"
chk "Aucun compte (hors root) avec UID 0" "[ \$(awk -F: '\$3==0 && \$1!=\"root\"' /etc/passwd | wc -l) -eq 0 ]"
chk "Aucun compte sans mot de passe" "[ \$(awk -F: '\$2==\"\"' /etc/shadow | wc -l) -eq 0 ]"
chk "Comptes de service sans shell interactif (deploy, sauvegarde)" "! grep -E '^(deploy|sauvegarde):' /etc/passwd | grep -qE '(/bin/bash|/bin/sh)$'"
chk "Compte stagiaire supprime ou verrouille" "! id stagiaire || passwd -S stagiaire | grep -q ' L '"
chk "Politique d'expiration des mots de passe (PASS_MAX_DAYS <= 90)" "[ \$(awk '/^PASS_MAX_DAYS/{print \$2}' /etc/login.defs) -le 90 ]"
chk "Expiration appliquee aux comptes existants (alice, bob)" "[ \$(chage -l alice 2>/dev/null | awk -F: '/Nombre maximal|Maximum number/{gsub(/ /,\"\",\$2); print \$2}') -le 90 ]"
chk "Module de robustesse des mots de passe present (pwquality/cracklib)" "grep -rqE 'pam_(pwquality|cracklib)' /etc/pam.d/"
chk "Verrouillage apres echecs (pam_faillock ou pam_tally2)" "grep -rqE 'pam_(faillock|tally2)' /etc/pam.d/"

sec "C. SUDO"
chk "Plus aucune regle NOPASSWD: ALL" "! grep -rqE 'NOPASSWD:[[:space:]]*ALL' /etc/sudoers /etc/sudoers.d/"
chk "Fichier /etc/sudoers.d/99-laxiste supprime" "[ ! -f /etc/sudoers.d/99-laxiste ]"
chk "Syntaxe sudoers valide" "visudo -c"
chk "Journalisation des commandes sudo activee" "grep -rqE 'log_(input|output)|logfile=' /etc/sudoers /etc/sudoers.d/"

sec "D. SSH"
chk "PermitRootLogin desactive" "sshd -T | grep -qiE '^permitrootlogin (no|prohibit-password)'"
chk "Authentification par mot de passe desactivee" "sshd -T | grep -qi '^passwordauthentication no'"
chk "MaxAuthTries <= 4" "[ \$(sshd -T | awk '/^maxauthtries/{print \$2}') -le 4 ]"
chk "LoginGraceTime <= 60" "[ \$(sshd -T | awk '/^logingracetime/{print \$2}') -le 60 ]"
chk "X11Forwarding desactive" "sshd -T | grep -qi '^x11forwarding no'"
chk "PermitEmptyPasswords desactive" "sshd -T | grep -qi '^permitemptypasswords no'"
chk "Restriction d'acces (AllowUsers/AllowGroups/DenyUsers)" "sshd -T | grep -qiE '^(allowusers|allowgroups|denyusers|denygroups)'"
chk "Banniere ne divulguant plus d'information" "! grep -qiE 'production|admin@' /etc/issue.net 2>/dev/null"

sec "E. SERVICES ET PAQUETS"
chk "telnetd absent" "! dpkg -l | grep -qE '^ii +telnetd'"
chk "rpcbind arrete/desactive" "! systemctl is-active rpcbind"
chk "avahi-daemon arrete/desactive" "! systemctl is-active avahi-daemon"
chk "nfs-kernel-server absent ou inactif" "! systemctl is-active nfs-server"
chk "xinetd absent" "! dpkg -l | grep -qE '^ii +xinetd'"
chk "Aucun port en ecoute hors 22/8080 sur 0.0.0.0" "[ \$(ss -tlnH | awk '{print \$4}' | grep -vE '127\.0\.0\.1|\[::1\]' | sed 's/.*://' | grep -vE '^(22|8080)$' | wc -l) -eq 0 ]"

sec "F. PARE-FEU"
chk "Un pare-feu est actif (nftables ou ufw)" "systemctl is-active nftables || ufw status | grep -qi active"
chk "Politique par defaut restrictive en entree" "nft list ruleset 2>/dev/null | grep -qE 'type filter hook input.*policy drop' || ufw status verbose | grep -qi 'deny (incoming)'"
chk "Le pare-feu survit au redemarrage (unite activee)" "systemctl is-enabled nftables || systemctl is-enabled ufw"

sec "G. PERMISSIONS ET SUID"
chk "/etc/shadow non lisible par les autres, non modifiable par le groupe" "mode_sans /etc/shadow 0027"
chk "/srv/metier n'est plus en 777" "[ ! -d /srv/metier ] || mode_sans /srv/metier 0022"
chk "/opt/scripts n'est plus en 777" "[ ! -d /opt/scripts ] || mode_sans /opt/scripts 0022"
chk "Binaire SUID superflu /usr/local/bin/find-suid retire" "[ ! -u /usr/local/bin/find-suid ]"
chk "Aucun fichier world-writable dans /etc" "[ \$(find /etc -xdev -type f -perm -0002 2>/dev/null | wc -l) -eq 0 ]"

sec "H. NOYAU (sysctl)"
chk "kernel.randomize_va_space = 2" "[ \$(sysctl -n kernel.randomize_va_space) -eq 2 ]"
chk "kernel.dmesg_restrict = 1" "[ \$(sysctl -n kernel.dmesg_restrict) -eq 1 ]"
chk "kernel.kptr_restrict >= 1" "[ \$(sysctl -n kernel.kptr_restrict) -ge 1 ]"
chk "fs.suid_dumpable = 0" "[ \$(sysctl -n fs.suid_dumpable) -eq 0 ]"
chk "net.ipv4.ip_forward = 0" "[ \$(sysctl -n net.ipv4.ip_forward) -eq 0 ]"
chk "net.ipv4.tcp_syncookies = 1" "[ \$(sysctl -n net.ipv4.tcp_syncookies) -eq 1 ]"
chk "accept_redirects = 0 (all et default)" "[ \$(sysctl -n net.ipv4.conf.all.accept_redirects) -eq 0 ] && [ \$(sysctl -n net.ipv4.conf.default.accept_redirects) -eq 0 ]"
chk "accept_source_route = 0 (all et default)" "[ \$(sysctl -n net.ipv4.conf.all.accept_source_route) -eq 0 ] && [ \$(sysctl -n net.ipv4.conf.default.accept_source_route) -eq 0 ]"
chk "Les reglages survivent au reboot (fichier persistant present)" "grep -rqE '^[[:space:]]*kernel.randomize_va_space[[:space:]]*=[[:space:]]*2' /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null"

sec "I. CONTROLE D'ACCES OBLIGATOIRE"
# aa-status --enabled ne teste que le support noyau : il repond "oui" meme
# apres aa-teardown. On verifie donc que des profils sont reellement charges.
chk "AppArmor actif et profils charges" "aa-status --enabled && [ \$(aa-status --profiled 2>/dev/null) -gt 0 ]"
chk "Aucun profil laisse en mode complain" "[ \$(aa-status --complaining 2>/dev/null) -eq 0 ]"
chk "Le service metier est couvert par un profil en enforce" "aa-status 2>/dev/null | sed -n '/enforce mode/,/complain mode/p' | grep -qi nginx"
chk "Confinement systemd de l'unite metier (NoNewPrivileges)" "systemctl show nginx -p NoNewPrivileges 2>/dev/null | grep -qi 'yes'"

sec "J. JOURNALISATION ET INTEGRITE"
chk "auditd installe et actif" "systemctl is-active auditd"
chk "Regles auditd chargees (> 5)" "[ \$(auditctl -l 2>/dev/null | wc -l) -gt 5 ]"
chk "Journal persistant sur disque" "[ -d /var/log/journal ] && ! grep -rqiE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*volatile' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/ 2>/dev/null"
chk "Journal dimensionne explicitement (SystemMaxUse)" "grep -rqiE '^[[:space:]]*SystemMaxUse[[:space:]]*=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/ 2>/dev/null"
chk "Outil d'integrite fichiers present (AIDE ou equivalent)" "command -v aide || command -v tripwire"
chk "Base de reference d'integrite initialisee" "ls /var/lib/aide/aide.db* >/dev/null 2>&1 || ls /var/lib/tripwire/*.twd >/dev/null 2>&1"

sec "K. MISES A JOUR"
chk "Aucune mise a jour de securite en attente" "[ \$(apt-get -s upgrade 2>/dev/null | grep -ci '^Inst.*security') -eq 0 ]"
chk "Mises a jour automatiques configurees" "dpkg -l | grep -qE '^ii +unattended-upgrades'"
chk "Mises a jour automatiques reellement activees" "grep -rqE 'Unattended-Upgrade\"[[:space:]]*\"1\"' /etc/apt/apt.conf.d/ 2>/dev/null"

echo
echo "======================================================"
echo " Controles reussis : $PASS / $TOTAL"
SCORE=$(( PASS * 60 / TOTAL ))
echo " Score technique   : $SCORE / 60"
if [ "$METIER" -eq 0 ]; then
  echo " ATTENTION : service metier HS -> note finale plafonnee a 08/20"
fi
echo "======================================================"
