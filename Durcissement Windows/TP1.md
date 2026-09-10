# Ici je vais faire le TP Windows

### Partie QCM

## Question 1 :

B :     whoami /priv,  permet de lister les privilèges de l'utilisateur courant.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/whoami

## Question 2 :

C : S-1-5-32-544, 

C'est l'identificateur de sécurité (SID) du groupe Administrateurs, a ne pas confondre avec d'autres SID comme S-1-5-18 (SID du compte système local) qui est un membre du groupe Administrateurs.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/understand-security-identifiers

S-1 : Niveau de révision (1)
5 : Autorité de sécurité NT (SECURITY_NT_AUTHORITY)
32 : Identificateur du domaine intégré (BUILTIN)
544 : Identificateur relatif (RID) spécifique au groupe des Administrateurs.


## Question 3 :

A : Le privilège est évalué avant l'ACL et peut la court-circuiter
