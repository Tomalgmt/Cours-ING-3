#TP2 Sécurité Windows

## Partie QCM

### BLOC 1

#### Question 1 :

B :     whoami /priv,  permet de lister les privilèges de l'utilisateur courant.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/whoami

#### Question 2 :

C : S-1-5-32-544, 

C'est l'identificateur de sécurité (SID) du groupe Administrateurs, a ne pas confondre avec d'autres SID comme S-1-5-18 (SID du compte système local) qui est un membre du groupe Administrateurs.

S-1 : Niveau de révision (1)
5 : Autorité de sécurité NT (SECURITY_NT_AUTHORITY)
32 : Identificateur du domaine intégré (BUILTIN)
544 : Identificateur relatif (RID) spécifique au groupe des Administrateurs.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/understand-security-identifiers

#### Question 3 :

A : Le privilège est évalué avant l'ACL et peut la court-circuiter

Doc : 
https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
" This privilege causes the system to grant all read access control to any file, regardless of the access control list (ACL) specified for the file"

#### Question 4 :

B : Medium

L'UAC génère deux jetons un accès filtré niveau medium et un accès complet niveau high. L'explorateur est lancé automatiquement au démarrage de la session sans élévation, il hérite du jeton filtré et du niveau d'integrité medium. 
Les applications lancées depuis l'explorateur héritent aussi du jeton filtré et du niveau d'intégrité medium.

Doc : 
https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control

#### Question 5 :

C : LocalAccountTokenFilterPolicy

ça permet à un attaquant d'utiliser un identifiant d'administrateur local volé pour se connecter à distance à une autre machine du réseau. Si cette machine cible possède la clé de registre activée (1), elle accorde instantanément les pleins pouvoirs à l'attaquant, lui permettant d'en prendre le contrôle total sans être bloqué par la sécurité Windows standard.
Ce meme token a 0 permet de filtrer les jetons d'accès des comptes locaux avec l'UAC.

Doc : 
https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction

#### Question 6 :

C. La mesure structurante est la séparation entre compte de travail et compte d'administration.

C'est explicitement indiqué que l'UAC est plus un outil pratique qu'une mesure de sécurité. 

Desactiver l'UAC désactive des mecanismes de sécurité
La renforcer un max peut aider mais encore ue fois c'est pas un outil de sécurité
Et l'UAC a justement été conçu pour les comptes administrateurs

Doc : 
https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/disable-user-account-control
"More important, Same-desktop Elevation in UAC isn't a security boundary. It can be hijacked by unprivileged software that runs on the same desktop. Same-desktop Elevation should be considered a convenience feature. "

### BLOC 2

#### Question 7 : 

A : HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> RunAsPPL

1 : Active la protection avec verrouillage UEFI.
2 : Active la protection sans verrouillage UEFI.
0 (ou suppression) : Désactive la protection.

Concrètement ça sert a empecher a un attaquand d'accéder a la mémoire de tout les processus du système, y compris lsass.exe, pour voler les mots de passe et les jetons d'accès.


Doc : 
https://learn.microsoft.com/fr-fr/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

#### Question 8 : 

B. La sécurité basée sur la virtualisation (VBS)

Ce systeme créée deux environnements : Normal et Securisé
Avec Credential Guard, les secrets sensibles sont définitivement retirés de la mémoire du lsass.exe standard. Ils sont déplacés à l'intérieur du mode sécurisé (VSM) au sein d'un processus isolé appelé LSAIso.exe.
Meme le noyau windows a pas accès à ce processus, donc meme si un attaquant arrive a executer du code malveillant avec les droits SYSTEM, il ne pourra pas accéder aux secrets sensibles.

Doc : 
https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/

#### Question 9 :

B : UseLogonCredential = 0

Une mise à 1, force le processus lsass.exe à conserver une copie en clair du mot de passe de l'utilisateur en mémoire RAM.

Doc : 
https://learn.microsoft.com/fr-fr/answers/questions/4087651/ne-plus-avoir-la-coche-m-moriser-ces-informations


#### Question 10 :

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

### Question 11 : 

C : RunAsPPL, parce que la protection est appliquée au lancement de LSASS

L’activation de RunAsPPL configure LSASS pour démarrer comme processus protégé (PPL). Si cette protection était désactivée, modifier le registre ne protège pas le processus déjà en cours : un redémarrage est nécessaire
Le script vérifie uniquement la configuration enregistrée, pas la protection réellement active.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

### BLOC 3

#### Question 12 :

A : Get-MpComputerStatus

C'est ce qui permet d'obtenir toutes les informations sur l'état de Windows Defender, y compris la version, la date de mise à jour, l'état de protection en temps réel etc ... 

Doc : 
https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2025-ps

#### Question 13 : 

C : 2 

Pour les règles de réduction de la surface d'attaque on utilise ce mode dont le nom est assez explicite.

0 : Désactivé (Disabled)
1 : Bloquer (Block / En production)
2 : Audit (Audit / Mode observation)
5 : non défini (je ne sais pas a quoi il sert)
6 : Avertir (Warn / Affiche un avertissement à l'utilisateur mais permet de passer outre)

Doc : 
https://learn.microsoft.com/fr-fr/defender-endpoint/attack-surface-reduction-rules-configure

#### Question 14 : 

B : Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol (vérifie la présence physique des binaires SMBv1 sur le système)
Cette commande permet de vérifier que SMBv1 est bien désactivé sur le serveur, et que SMBv2 et SMBv3 sont activés.

Get-SmbServerConfiguration (vérifie l'etat de la configuration activée donc smbv1 est désactivé mais peut etre encore présent physiquement sur le système)
sc.exe query LanmanServer : permet d'interroger le service serveur SMB, mais ne permet pas de savoir si SMBv1 est activé ou non.
net share : liste simplement les dossiers actuellement partagés sur la machine sans donner d'info sur le protocole utilisé.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server

#### Question 15 :

B : RequireSecuritySignature

EnableSecuritySignature : indique simplement que le serveur accepte ou supporte la signature si le client la demande, mais il ne l'impose pas (les connexions non signées restent autorisées si le client ne sait pas signer). En plus, ça sert que pour le vieux protocole SMBv1 et reste ignoré par SMBv2/v3
EnableSMB1Protocol : sert uniquement à activer ou désactiver la logique du protocole de partage de fichiers de première génération (SMBv1), il n'a aucun rapport avec la gestion des signatures de paquets
RejectUnencryptedAccess : sert à imposer le chiffrement global des données (le chiffrement SMB3 qui rend les fichiers illisibles en cas d'interception), ce qui est une mesure de confidentialité autre que la simple signature.

Doc : 
https://learn.microsoft.com/fr-fr/windows-server/storage/file-server/smb-signing-overview

#### Question 16 :

B : Elle authentifie le client avant l'ouverture d'une session graphique, réduisant la surface exposée aux non-authentifiés

Elle chiffre la session, ce que RDP ne fait pas par défaut : Le protocole RDP intègre déjà  des mécanismes de chiffrement et de sécurité (avec TLS).
Elle limite le nombre de sessions simultanées : La limitation des connexions simultanées est gérée par la configuration des services de bureau à distance. La NLA rejete tentatives illégitimes mais pas a un nombre limité de sessions simultanées.
Elle impose l'usage d'un compte du domaine : La NLA impose pas de joindre la machine à un domaine Active Directory.

Doc : 
https://learn.microsoft.com/en-us/security-updates/securityadvisories/2013/2861855

#### Question 17 :


C : C'est un garde-fou contre l'exécution accidentelle, contournable trivialement, le vrai contrôle est la liste d'autorisation.

La politique "Restricted" empêche seulement l'exécution de fichiers de scripts (.ps1), mais permet toujours de saisir et d'exécuter du code PowerShell interactif dans la console. 
Microsoft précise officiellement que la politique d'exécution est un mécanisme de prévention contre les erreurs humaines et pas une frontière de sécurité.
La politique "AllSigned" exige uniquement que les scripts soient signés par un éditeur de confiance, ça immunise pas la machine si un attaquant parvient à signer son script malveillant avec un certificat approuvé ou à contourner la politique. 

Doc : 
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.6

### BLOC 4

#### Question 18 : 

A : 4104

624 appartient au journal de sécurité Windows et correspond à l'ouverture de session réussie d'un utilisateur.
4688 appartient également au journal de sécurité et sert à tracer la création de nouveaux processus sur la machine
5156 est généré par le pare-feu Windows lorsqu'une connexion réseau entrante ou sortante est autorisée

Doc : 
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.6

#### Question 19 :

B : Il faut activer explicitement l'inclusion de la ligne de commande dans les événements de création de processus

Ce champ existe sur Windows 11 ainsi que sur toutes les versions modernes de Windows Server
Le journal de sécurité ne tronque pas arbitrairement les arguments à 260 caractères, la ligne de commande est soit totalement absente (si l'option est désactivée), soit totalement affichée.Sysmon fournit cette information, l'événement standard Windows 4688 peut tout à fait le faire si la stratégie de groupe associée est activée.

Doc : 
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing

#### Question 20 :

B : krbtgt

Administrateur ses clés ne servent pas à signer les tickets Kerberos globaux du domaine, changer son mot de passe suffit à couper l'accès à l'attaquant
Le compte SYSTEM (LocalSystem) est un compte d'infrastructure local à chaque machine Windows et n'a aucune autorité globale sur le chiffrement Kerberos de l'Active Directory
Les comptes de machines des contrôleurs de domaine (DC$) possèdent de hauts privilèges, mais ce n'est pas leur mot de passe qui valide et signe de manière universelle les TGT de tous les utilisateurs du domaine.

Doc : 
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts


## Questions ouvertes

#### Question 21 :

À la première étape, le droit d'administration déléguée dans l'Active Directory (ForceChangePassword) est détourné pour s'emparer illégitimement du compte B.

À la deuxième étape, ce sont les privilèges légitiment accordés au groupe Administrateurs locaux du serveur qui sont abusés pour prendre le contrôle total du système de fichiers et de la mémoire.

Enfin, à la troisième étape, le droit d'accès aux processus locaux (le privilège système SeDebugPrivilege) est exploité pour dumper le processus lsass.exe et intercepter les secrets du DA.

Pour couper ce chemin d'attaque, la mesure la plus efficace est d'interdire formellement aux administrateurs de domaine de se connecter sur des serveurs membres, ça assure que leurs secrets ne transitent jamais là où un administrateur local peut les intercepter.

Il faut prendre 2 mesures pour bloquer ce chemin d'attaque :

Verrouiller techniquement la restriction (GPO) : il faut obligatoirement configurer des GPO de restriction de droits utilisateur (User Rights Assignment) pour interdire techniquement l'ouverture de session locale et distante des DA sur le Tier 1.

Corriger la source du problème (Délégation AD) : L'utilisateur A possède le droit légitime de réinitialiser le mot de passe de l'utilisateur B (qui est admin local du serveur). L'attaquant peut donc encore et toujours prendre le contrôle du serveur membre et y voler d'autres secrets (données de l'application, bases de données, jetons d'autres utilisateurs). Il faut donc impérativement supprimer cette délégation excessive dans l'Active Directory.

#### Question 22 :

RunAsPPL empêche les processus non protégés de lire ou de modifier la mémoire de LSASS, ce qui complique fortement l’usage d’outils de vol d’identifiants.

Credential Guard va plus loin en isolant les secrets réutilisables dans une zone protégée par la virtualisation, inaccessible même à un attaquant disposant des privilèges SYSTEM.

Protected Users réduit, pour les comptes concernés, les possibilités d’exploitation en bloquant notamment NTLM, la mise en cache de certains secrets et la délégation Kerberos, mais il ne protège ni tous les utilisateurs ni directement le processus LSASS.

Par exemple, un attaquant peut contourner RunAsPPL grâce à un pilote signé vulnérable, mais Credential Guard maintient les secrets hors de sa portée et Protected Users l’empêche d’obtenir un hash NTLM ou des identifiants délégués : chaque défense couvre donc les faiblesses laissées par les deux autres.

#### Question 23 : 

Pour le filtrage réseau réalisé avec nftables, l’équivalent est le pare-feu Windows fondé sur la Windows Filtering Platform : tous deux appliquent un filtrage à états, mais Windows raisonne aussi par profils réseau, applications et identités.

Le confinement d’un service avec AppArmor se transpose par une combinaison de jeton restreint, SID de service, ACL et contrôle d’exécution du code, contrairement au profil obligatoire d’AppArmor, Windows répartit donc cette protection entre plusieurs mécanismes.

Pour AIDE, Windows propose la protection des fichiers système et leur vérification d’intégrité, mais celles-ci ne surveillent pas arbitrairement tous les fichiers comme une base d’empreintes AIDE : il n’existe donc pas d’équivalent intégré parfaitement identique sans ajouter de l’audit ou une solution FIM.

#### Question 24 :

Je refuserais une politique WDAC/AppLocker qui interdit tout code non signé, car elle bloquerait les exécutables produits localement et provoquerait une régression des activités de compilation et de test.

À la place, je conserverais le contrôle strict sur le poste principal, mais j’autoriserais l’exécution du code expérimental dans une VM ou un conteneur isolé, avec journalisation et analyse par l’antivirus.

Je n’ajouterais pas non plus le compte quotidien du développeur au groupe Protected Users, car la suppression de NTLM et de la délégation Kerberos peut casser certains dépôts, outils de débogage distant ou environnements de développement anciens.

Je privilégierais un compte développeur standard protégé par Credential Guard et une authentification forte, complété par un compte administratif séparé placé dans Protected Users et utilisé uniquement lorsque nécessaire.