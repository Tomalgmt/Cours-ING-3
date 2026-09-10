# Ici je vais faire le TP Windows

### Partie QCM

## BLOC 1 : 

# Question 1 :

B :     whoami /priv,  permet de lister les privilèges de l'utilisateur courant.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/whoami

# Question 2 :

C : S-1-5-32-544, 

C'est l'identificateur de sécurité (SID) du groupe Administrateurs, a ne pas confondre avec d'autres SID comme S-1-5-18 (SID du compte système local) qui est un membre du groupe Administrateurs.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/understand-security-identifiers

S-1 : Niveau de révision (1)
5 : Autorité de sécurité NT (SECURITY_NT_AUTHORITY)
32 : Identificateur du domaine intégré (BUILTIN)
544 : Identificateur relatif (RID) spécifique au groupe des Administrateurs.


# Question 3 :

A : Le privilège est évalué avant l'ACL et peut la court-circuiter

Doc : 
https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
" This privilege causes the system to grant all read access control to any file, regardless of the access control list (ACL) specified for the file"

# Question 4 :

B : Medium, 
L'UAC génère deux jetons un accès filtré niveau medium et un accès complet niveau high. L'explorateur est lancé automatiquement au démarrage de la session sans élévation, il hérite du jeton filtré et du niveau d'integrité medium. 
Les applications lancées depuis l'explorateur héritent aussi du jeton filtré et du niveau d'intégrité medium.

Doc : 
https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control

# Question 5 :

C : LocalAccountTokenFilterPolicy

ça permet à un attaquant d'utiliser un identifiant d'administrateur local volé pour se connecter à distance à une autre machine du réseau. Si cette machine cible possède la clé de registre activée (1), elle accorde instantanément les pleins pouvoirs à l'attaquant, lui permettant d'en prendre le contrôle total sans être bloqué par la sécurité Windows standard.
Ce meme token a 0 permet de filtrer les jetons d'accès des comptes locaux avec l'UAC.

Doc : 
https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction

# Question 6 :

C. La mesure structurante est la séparation entre compte de travail et compte d'administration.

C'est explicitement indiqué que l'UAC est plus un outil pratique qu'une mesure de sécurité. 

Desactiver l'UAC désactive des mecanismes de sécurité
La renforcer un max peut aider mais encore ue fois c'est pas un outil de sécurité
Et l'UAC a justement été conçu pour les comptes administrateurs

Doc : 
https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/disable-user-account-control
"More important, Same-desktop Elevation in UAC isn't a security boundary. It can be hijacked by unprivileged software that runs on the same desktop. Same-desktop Elevation should be considered a convenience feature. "

## BLOC 2 :

# Question 1 : 



