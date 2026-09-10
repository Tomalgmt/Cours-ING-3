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

# Question 7 : 

A : HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> RunAsPPL

1 : Active la protection avec verrouillage UEFI.
2 : Active la protection sans verrouillage UEFI.
0 (ou suppression) : Désactive la protection.

Concrètement ça sert a empecher a un attaquand d'accéder a la mémoire de tout les processus du système, y compris lsass.exe, pour voler les mots de passe et les jetons d'accès.


Doc : 
https://learn.microsoft.com/fr-fr/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

# Question 8 : 

B. La sécurité basée sur la virtualisation (VBS)

Ce systeme créée deux environnements : Normal et Securisé
Avec Credential Guard, les secrets sensibles sont définitivement retirés de la mémoire du lsass.exe standard. Ils sont déplacés à l'intérieur du mode sécurisé (VSM) au sein d'un processus isolé appelé LSAIso.exe.
Meme le noyau windows a pas accès à ce processus, donc meme si un attaquant arrive a executer du code malveillant avec les droits SYSTEM, il ne pourra pas accéder aux secrets sensibles.

Doc : 
https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/

# Question 9 :

B : UseLogonCredential = 0

Une mise à 1, force le processus lsass.exe à conserver une copie en clair du mot de passe de l'utilisateur en mémoire RAM.

Doc : 
https://learn.microsoft.com/fr-fr/answers/questions/4087651/ne-plus-avoir-la-coche-m-moriser-ces-informations


# Question 10 :

D : 5 

Le paramètre LmCompatibilityLevel ça détermine quel protocole d'authentification par Challenge/Response votre ordinateur va accepter d'utiliser lorsqu'il se connecte à un autre ordinateur sur le réseau local, spécifiquement pour les protocoles de la famille LAN Manager (LM) et NTLM.

0 Envoie les réponses LM et NTLMv1. N'utilise jamais NTLMv2.Accepte absolument tout (LM, NTLMv1 et NTLMv2).
1 Envoie LM et NTLMv1, mais utilise la sécurité de session NTLMv2 si le serveur la supporte.Accepte absolument tout (LM, NTLMv1 et NTLMv2).
2 Envoie uniquement NTLMv1 (le protocole LM est désactivé côté client).Accepte absolument tout (LM, NTLMv1 et NTLMv2).
3 Envoie uniquement NTLMv2 (LM et NTLMv1 désactivés côté client).Accepte absolument tout (LM, NTLMv1 et NTLMv2).
4 Envoie uniquement NTLMv2.Refuse LM côté serveur (accepte NTLMv1 et NTLMv2).
5 Envoie uniquement NTLMv2.Refuse LM et NTLMv1 côté serveur (n'accepte que NTLMv2).

Doc : 
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level

# Question 11 : 

C : RunAsPPL, parce que la protection est appliquée au lancement de LSASS

L’activation de RunAsPPL configure LSASS pour démarrer comme processus protégé (PPL). Si cette protection était désactivée, modifier le registre ne protège pas le processus déjà en cours : un redémarrage est nécessaire
Le script vérifie uniquement la configuration enregistrée, pas la protection réellement active.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

## BLOC 3 :

# Question 12 :

A : Get-MpComputerStatus

C'est ce qui permet d'obtenir toutes les informations sur l'état de Windows Defender, y compris la version, la date de mise à jour, l'état de protection en temps réel etc ... 

Doc : 
https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2025-ps

# Question 13 : 

C : 2 

Pour les règles de réduction de la surface d'attaque on utilise ce mode dont le nom est assez explicite.

0 : Désactivé (Disabled)
1 : Bloquer (Block / En production)
2 : Audit (Audit / Mode observation)
5 : non défini (je ne sais pas a quoi il sert)
6 : Avertir (Warn / Affiche un avertissement à l'utilisateur mais permet de passer outre)

Doc : 
https://learn.microsoft.com/fr-fr/defender-endpoint/attack-surface-reduction-rules-configure

# Question 14 : 

B : Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol (vérifie la présence physique des binaires SMBv1 sur le système)
Cette commande permet de vérifier que SMBv1 est bien désactivé sur le serveur, et que SMBv2 et SMBv3 sont activés.

Get-SmbServerConfiguration (vérifie l'etat de la configuration activée donc smbv1 est désactivé mais peut etre encore présent physiquement sur le système)
sc.exe query LanmanServer : permet d'interroger le service serveur SMB, mais ne permet pas de savoir si SMBv1 est activé ou non.
net share : liste simplement les dossiers actuellement partagés sur la machine sans donner d'info sur le protocole utilisé.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server

# Question 15 :

B : RequireSecuritySignature

EnableSecuritySignature : indique simplement que le serveur accepte ou supporte la signature si le client la demande, mais il ne l'impose pas (les connexions non signées restent autorisées si le client ne sait pas signer). En plus, ça sert que pour le vieux protocole SMBv1 et reste ignoré par SMBv2/v3
EnableSMB1Protocol : sert uniquement à activer ou désactiver la logique du protocole de partage de fichiers de première génération (SMBv1), il n'a aucun rapport avec la gestion des signatures de paquets
RejectUnencryptedAccess : sert à imposer le chiffrement global des données (le chiffrement SMB3 qui rend les fichiers illisibles en cas d'interception), ce qui est une mesure de confidentialité autre que la simple signature.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/storage/file-server/smb-signing-overview