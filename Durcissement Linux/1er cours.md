Seance 1 : principes de base

4 PRINCIPES : 



Moindre privilège,

défense en profondeur,

Valeurs par défaut sures

Économie de mécanisme



Le durcissement a un coup



pas tourner en root

réduire la surface d'attaque et elle s'annule jamais

identifier et neutraliser 





Le durcissement ne : 

fais pas de detection, restauration, correctifs



3 questions : Quest ce qui a de la valeure, 

c'est quoi l'objectif a atteindre

quels sont les points d'entrée



3 attaquants : distants, local et admin compromis => plusieurs positions de départ



DISA STIG, ANSSI, CIS



Niveaux CIS : (environnements) 

&#x09;L1 : acceptable

&#x09;L2 : sensible => regression 







Techniques : chiffrement de disque 

(au repos)



Seance 2 : Identité et élévation sous Linux



Un user a un UID (root = 0), les comptes de service (lance un daemon) : 1 à 999



/etc/shadow : mots de passe hachés avec sel

le sel empêche les tables précalculées



Piege PAM : mal placer pam\_faillock bloque TOUT LE MONDE

sudo  qui, sur quelle machine, en tant que qui, quelle commande



PAS de NOPASSWD un binaire suffit : find, vi , less, awk, tar ça peut ouvrir un shell root => injection de code compromis root



**Seance 3 :** 



Y a RIEN au dessus du noyau, c'est le maitre



DAC : Discretionnary Access Control : un process herite des droits de l'utilisateur qui exec 

ATTENTION un pdf peut lire les clés ssh exemple : code malveillant dans un pdf => prend une clé ssh puis l'envoie a un malveillant



Délégué confus : bit SUID execute sous l'identitée du proprietaire du fichier => mauvais car un user non root peut lancer un shell root



Il y a des capacitées root : CAP\_NET\_BIND\_SERVICE : ecouter sous 1024 => un serveur a pas besoin d'etre root pour écouter 

CAP\_SYS\_ADMIN : presque pareil que root



seccomp : réduire la surface d'attaque



MAC : mandatory access control : politique imposée par le système : 

&#x09;- AppArmor : raisonne par chemin de fichier

&#x09;- SELinux : raisonne par label/etiquette (sur les dstributions redhat entreprise)



AppArmor : profilcomplain, faire vivre, lire refus, basculer enforce



Exploitation mémoire : 



ASLR : randomise les adresses d'execution

KASLR : pareil mais pour le noyau

NX : Interdiction d'execution 

Canaris de pile : à chercher 

PIE : Position independant executable

RELRO : relocation Read Only



Attention AUCUNE protection ne repose sur le chiffrement ni du contrôle d'accès ça c'est probabiliste



sysctl : ce que chaques lignes retire a l'attaquant (à voir)



Seance 4 : 



deux systèmes deux roles

journald : événements applicatifs et système 

auditd : décision de sécurité du noyau



une regle d'audit répond a une question => ça peut trop enregistrer => rechercher "questce qui pourra me permettre de trancher"

storage = volatile : le journal disparait au redémarrage par défaut 



AIDE : Advanced intrusion Detection Environment ) 

Base de référentiel de l'etat des fichiers à stocker ailleur



Un attaquant root peut tout arreter, purger les journaux etc etc … 





