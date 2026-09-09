# Fichiers de configuration du durcissement

Ce dossier reproduit l’arborescence des fichiers créés ou modifiés par `hardening.sh`. Les chemins situés sous `configs/etc/` correspondent à leurs destinations sous `/etc/` dans la VM.

| Fichier du dépôt | Destination dans la VM | Rôle |
|---|---|---|
| `etc/login.defs.durcissement` | directives de `/etc/login.defs` | Expiration des mots de passe |
| `etc/security/pwquality.conf` | `/etc/security/pwquality.conf` | Robustesse des mots de passe |
| `etc/security/faillock.conf` | `/etc/security/faillock.conf` | Verrouillage après échecs |
| `etc/pam.d/common-auth.hardening` | intégration dans `/etc/pam.d/common-auth` | Appels `pam_faillock` |
| `etc/pam.d/common-account.hardening` | intégration dans `/etc/pam.d/common-account` | Réinitialisation/contrôle faillock |
| `etc/pam.d/common-password.hardening` | intégration dans `/etc/pam.d/common-password` | Appel `pam_pwquality` |
| `etc/sudoers.d/logging` | `/etc/sudoers.d/logging` | Journalisation sudo |
| `etc/ssh/sshd_config.d/00-durcissement.conf` | chemin identique sous `/etc` | Durcissement SSH |
| `etc/issue.net` | `/etc/issue.net` | Bannière SSH |
| `etc/nftables.conf` | `/etc/nftables.conf` | Pare-feu nftables |
| `etc/sysctl.d/99-z-durcissement.conf` | chemin identique sous `/etc` | Paramètres noyau |
| `etc/apparmor.d/usr.sbin.nginx` | chemin identique sous `/etc` | Profil AppArmor nginx |
| `etc/systemd/system/nginx.service.d/hardening.conf` | chemin identique sous `/etc` | `NoNewPrivileges` pour nginx |
| `etc/audit/rules.d/50-hardening.rules` | chemin identique sous `/etc` | Règles auditd |
| `etc/systemd/journald.conf.d/99-persistent.conf` | chemin identique sous `/etc` | Journal persistant |
| `etc/apt/apt.conf.d/20auto-upgrades` | chemin identique sous `/etc` | Mises à jour automatiques |

Les trois fichiers `pam.d/*.hardening` contiennent les lignes à intégrer aux fichiers PAM générés par Debian. `hardening.sh` effectue cette intégration sans remplacer aveuglément l’ensemble de la pile PAM.

Les fichiers sont fournis pour le rendu et la relecture. L’installation automatisée doit être réalisée avec `hardening.sh`, qui sauvegarde les fichiers existants, valide les syntaxes et recharge les services dans le bon ordre.
