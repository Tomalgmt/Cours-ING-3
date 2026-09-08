#!/usr/bin/env bash
# =====================================================================
#  preparer-vm.sh — met une Debian 12 fraiche en etat de demarrer le TP1
#  Durcissement Linux et Windows
#
#  A LANCER EN ROOT DANS LA VM DE TP, JAMAIS SUR UNE MACHINE REELLE.
#
#  Ce que fait ce script :
#    1. installe un bureau leger Xfce + un terminal + Firefox
#       (pour avoir le copier-coller, qui n'existe pas en console pure)
#    2. installe openssh-server et affiche l'adresse pour s'y connecter
#    3. applique la baseline degradee du TP (degrade-debian.sh)
#    4. depose check-debian.sh dans /home/<user>/tp
#
#  Usage :
#    sudo ./preparer-vm.sh                 # tout, avec bureau
#    sudo ./preparer-vm.sh --sans-bureau   # serveur pur, sans Xfce
#
#  Les deux scripts du TP doivent etre a cote de celui-ci, ou
#  telechargeables : POSTINSTALL_URL=https://... sudo -E ./preparer-vm.sh
# =====================================================================
set -u
export DEBIAN_FRONTEND=noninteractive
[ "$(id -u)" -eq 0 ] || { echo "A lancer en root : sudo $0"; exit 1; }

BUREAU=1
[ "${1:-}" = "--sans-bureau" ] && BUREAU=0
ICI="$(cd "$(dirname "$0")" && pwd)"
URL="${POSTINSTALL_URL:-}"
UTIL="$(getent passwd 1000 | cut -d: -f1)"
[ -n "$UTIL" ] || UTIL=root
FOYER="$(getent passwd "$UTIL" | cut -d: -f6)"

titre(){ echo; echo "===== $* ====="; }

recuperer(){ # $1 = nom de fichier ; le cherche a cote, sinon le telecharge
  local f="$1"
  if [ -f "$ICI/$f" ]; then cp "$ICI/$f" "$FOYER/tp/$f"; return 0; fi
  if [ -n "$URL" ]; then
    wget -qO "$FOYER/tp/$f" "$URL/$f" 2>/dev/null && return 0
    curl -fsSL -o "$FOYER/tp/$f" "$URL/$f" 2>/dev/null && return 0
  fi
  echo "  !! $f introuvable (ni a cote du script, ni via POSTINSTALL_URL)"
  return 1
}

titre "1/5  Mise a jour de l'index des paquets"
apt-get update -qq || { echo "Pas d'acces reseau APT. Corrigez cela d'abord."; exit 1; }

if [ "$BUREAU" -eq 1 ]; then
  titre "2/5  Bureau leger Xfce (environ 5 min)"
  apt-get install -y -qq --no-install-recommends \
      xfce4 xfce4-terminal lightdm dbus-x11 \
      firefox-esr mousepad xfce4-screenshooter fonts-dejavu \
      >/dev/null
  systemctl set-default graphical.target >/dev/null 2>&1
  # Ouverture de session automatique : c'est une VM de laboratoire,
  # et cela evite de retaper un mot de passe a chaque instantane restaure.
  mkdir -p /etc/lightdm/lightdm.conf.d
  cat > /etc/lightdm/lightdm.conf.d/20-autologin.conf << EOF
[Seat:*]
autologin-user=$UTIL
autologin-user-timeout=0
user-session=xfce
EOF
  # Le copier-coller entre l'hote et la VM demande les additions invite
  # de votre hyperviseur : voir README, section "copier-coller".
else
  titre "2/5  Bureau : ignore (--sans-bureau)"
fi

titre "3/5  Acces distant"
apt-get install -y -qq openssh-server >/dev/null
systemctl enable --now ssh >/dev/null 2>&1

titre "4/5  Depot des scripts du TP"
install -d -o "$UTIL" -g "$UTIL" "$FOYER/tp"
recuperer degrade-debian.sh
recuperer check-debian.sh
chmod +x "$FOYER/tp/"*.sh 2>/dev/null
chown -R "$UTIL:$UTIL" "$FOYER/tp"

titre "5/5  Application de la baseline degradee"
if [ -x "$FOYER/tp/degrade-debian.sh" ]; then
  echo OUI | "$FOYER/tp/degrade-debian.sh"
else
  echo "  degrade-debian.sh absent : a lancer vous-meme ensuite."
fi

echo
echo "======================================================================"
echo " VM prete."
echo
echo " Utilisateur         : $UTIL"
echo " Scripts du TP       : $FOYER/tp"
IP=$(ip -4 -br addr show scope global | awk '{print $3}' | cut -d/ -f1 | head -1)
echo " Adresse IP          : ${IP:-aucune (verifiez le mode reseau de la VM)}"
[ -n "${IP:-}" ] && echo " Connexion depuis l'hote : ssh $UTIL@$IP"
echo
echo " ETAPE SUIVANTE, OBLIGATOIRE :"
echo "   prenez un instantane nomme 'baseline' MAINTENANT."
echo "======================================================================"
