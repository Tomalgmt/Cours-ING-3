#!/usr/bin/env bash
# =====================================================================
#  postinstall.sh — appele par preseed.cfg a la fin de l'installation
#  Durcissement Linux et Windows — TP1
#
#  Ne fait qu'une chose : recuperer les scripts du TP et lancer
#  preparer-vm.sh. Toute la logique est dans preparer-vm.sh, pour que
#  l'etudiant qui installe a la main obtienne exactement le meme etat.
# =====================================================================
set -u
export DEBIAN_FRONTEND=noninteractive
URL="${POSTINSTALL_URL:?POSTINSTALL_URL non defini}"
cd /root || exit 1

recup(){ wget -qO "$1" "$URL/$1" 2>/dev/null || curl -fsSL -o "$1" "$URL/$1" 2>/dev/null; }

recup preparer-vm.sh || { echo "preparer-vm.sh introuvable a $URL"; exit 1; }
recup degrade-debian.sh
recup check-debian.sh
chmod +x preparer-vm.sh degrade-debian.sh check-debian.sh 2>/dev/null

# Le bureau est deja installe par la tache xfce-desktop du preseed :
# preparer-vm.sh detectera les paquets presents et ne refera rien.
POSTINSTALL_URL="$URL" ./preparer-vm.sh

# Rappel visible au premier demarrage.
cat > /etc/profile.d/99-tp-rappel.sh << 'EOF'
if [ ! -f "$HOME/.tp-rappel-vu" ]; then
  echo
  echo "  ---------------------------------------------------------------"
  echo "   VM du TP1 - Durcissement d'un serveur Debian 12"
  echo "   Scripts : ~/tp   ·  service metier : http://127.0.0.1:8080/health"
  echo "   PRENEZ UN INSTANTANE NOMME 'baseline' AVANT DE COMMENCER."
  echo "  ---------------------------------------------------------------"
  echo
  touch "$HOME/.tp-rappel-vu" 2>/dev/null
fi
EOF
chmod 644 /etc/profile.d/99-tp-rappel.sh
