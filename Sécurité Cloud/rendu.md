# TP1 Sécurité Cloud

## Gestion des identités et des accès

**Étudiants :** Charles Basset, Tom Allaguillette, Elias Chekhab  
**Formation :** CY Tech - Ing 3  
**Année :** 2026-2027

## Introduction

Ce TP étudie la gestion des identités et des accès dans AWS. Il montre qu'une politique ne doit pas seulement être valide : elle doit limiter précisément les actions, les ressources et les conditions d'utilisation. Le travail porte successivement sur l'audit de politiques IAM, la création d'une politique de moindre privilège, le remplacement d'une clé permanente par des identifiants temporaires et la fédération d'une chaîne GitHub Actions.

Les sorties Parliament de la partie 2 proviennent des essais déjà réalisés. Pour les autres étapes, les commandes ne sont pas exécutées dans ce compte rendu : les observations sont les résultats attendus d'après le sujet et l'analyse des mécanismes AWS. Aucun identifiant ou secret réel n'est reproduit.

## 1 Mise en place de l'environnement

L'environnement prévu repose sur Python 3.10 ou supérieur, un environnement virtuel `tp1-iam`, Moto sur le port local `5055`, AWS CLI, Parliament et Policy Sentry. Moto émule les API AWS sans contacter un compte cloud réel.

Deux terminaux sont nécessaires : le premier conserve `moto_server` en fonctionnement, tandis que le second contient l'environnement virtuel actif et les variables AWS factices. La variable `AWS_ENDPOINT_URL=http://localhost:5055` force AWS CLI à contacter l'émulateur local.

La commande de vérification prévue est :

```console
aws sts get-caller-identity
```

Le résultat attendu contient le compte de l'émulateur :

```json
{
  "Account": "123456789012"
}
```

La présence de ce numéro confirme uniquement que le client communique avec Moto. Elle ne prouve pas qu'une politique IAM est correctement appliquée, car l'émulateur utilisé dans ce TP n'évalue pas les autorisations et ne renvoie pas de refus d'accès. Les politiques doivent donc être jugées par lecture et par analyse statique.

## 2 Lire et critiquer des politiques existantes

### 2.1 Tableau d'analyse

| Fichier | Constats à la lecture | Constats de l'outil | Correction proposée |
|:---:|---|---|---|
| `a.json` | `Action: "*"` autorise toutes les actions de tous les services. `Resource: "*"` ne limite aucune ressource. La politique accorde donc des droits proches d'un administrateur, sans condition, et ne respecte pas le moindre privilège. | `parliament --file a.json` n'affiche rien. Avec les community auditors et un seuil `HIGH`, Parliament signale **22 vecteurs d'escalade de privilèges** : création d'identifiants, modification ou attachement de politiques, délégation de rôles et exploitation de services avec un rôle privilégié. | Remplacer les deux jokers par une liste explicite d'actions et de ressources correspondant au besoin. Séparer les actions par service et type de ressource. Supprimer les permissions IAM et `iam:PassRole` non indispensables, puis ajouter des conditions de contexte. |
| `b.json` | `s3:GetObject` et `s3:PutObject` ciblent l'ARN du bucket alors que ces actions portent sur des objets. `iam:PassRole` est autorisé sur tous les rôles avec `Resource: "*"`, ce qui crée un risque d'escalade si un service peut être lancé avec un rôle plus puissant. | Parliament produit un constat `MEDIUM` car les deux actions S3 attendent un ARN d'objet de la forme `arn:*:s3:::*/*`. Il produit aussi un constat `LOW` sur l'utilisation inutile de `Resource *` pour `iam:PassRole`. La commande limitée aux constats `HIGH` n'affiche rien. | Utiliser `arn:aws:s3:::acme-reports/*` pour `GetObject` et `PutObject`. Supprimer `iam:PassRole` s'il est inutile. Sinon, l'isoler, le limiter à l'ARN exact du rôle autorisé et ajouter une condition `iam:PassedToService`. |
| `c.json` | La même instruction mélange une action de bucket, une action d'objet et une action IAM, qui n'utilisent pas les mêmes types de ressources. Le joker de la liste `Resource` annule les restrictions apportées par les ARN S3. `iam:CreateAccessKey` peut permettre de créer des identifiants pour un utilisateur privilégié. | La commande standard produit un constat `LOW` sur l'utilisation inutile de `Resource *`. Avec les community auditors et un seuil `HIGH`, Parliament détecte un vecteur d'escalade `CreateAccessKey`. | Créer une instruction pour `s3:ListBucket` sur le bucket, une autre pour `s3:GetObject` sur les objets, et retirer `iam:CreateAccessKey`. Si cette dernière action est indispensable, la placer dans une instruction distincte et la limiter à l'ARN exact de l'utilisateur concerné. |

### 2.2 Détail des résultats utiles

La politique `a.json` illustre une limite importante de l'outil. L'analyse standard ne signale rien alors que la politique est manifestement excessive. L'auditeur communautaire identifie les 22 scénarios `HIGH` suivants :

- `CreateAccessKey`, `CreateLoginProfile` et `UpdateLoginProfile` ;
- `CreateNewPolicyVersion` et `SetExistingDefaultPolicyVersion` ;
- `AttachUserPolicy`, `AttachGroupPolicy` et `AttachRolePolicy` ;
- `PutUserPolicy`, `PutGroupPolicy` et `PutRolePolicy` ;
- `AddUserToGroup` et `UpdateRolePolicyToAssumeIt` ;
- `CreateEC2WithExistingIP` ;
- `PassExistingRoleToNewLambdaThenInvoke` ;
- `PassExistingRoleToNewLambdaThenTriggerWithNewDynamo` ;
- `PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo` ;
- `PassExistingRoleToNewGlueDevEndpoint` ;
- `PassExistingRoleToCloudFormation` ;
- `PassExistingRoleToNewDataPipeline` ;
- `UpdateExistingGlueDevEndpoint` ;
- `EditExistingLambdaFunctionWithRole`.

Pour `b.json`, l'ARN `arn:aws:s3:::acme-reports` désigne le bucket lui-même. Une action telle que `s3:GetObject` ou `s3:PutObject` doit viser les objets avec le suffixe `/*`. Le fait qu'aucune alerte `HIGH` ne soit affichée ne supprime ni l'erreur fonctionnelle sur les ARN ni le risque créé par `iam:PassRole`.

Pour `c.json`, la présence du joker permet à `iam:CreateAccessKey` de s'appliquer au-delà des ressources S3 indiquées. L'auditeur communautaire complète donc utilement le contrôle standard en reliant cette action à un scénario d'escalade.

### 2.3 Conclusion sur l'analyse statique

L'outil a identifié des chaînes d'escalade de privilèges difficiles à énumérer manuellement, notamment les combinaisons fondées sur `iam:PassRole`. Inversement, la lecture humaine repère immédiatement que `Action: "*"` et `Resource: "*"` violent le moindre privilège, alors que l'analyse standard de `a.json` reste silencieuse. Un analyseur doit donc compléter la revue de code, jamais la remplacer : ses résultats dépendent de ses règles, de sa configuration et du type de politique analysé.

## 3 Écrire une politique de moindre privilège

### 3.1 Expression du besoin

Le service de reporting doit lire les objets du préfixe `2026/` du bucket `acme-reports` et écrire uniquement dans `2026/entrant/`.

Contenu de `besoin.yml` :

```yaml
mode: crud
read:
  - "arn:aws:s3:::acme-reports/2026/*"
write:
  - "arn:aws:s3:::acme-reports/2026/entrant/*"
```

### 3.2 Analyse de la politique générée par Policy Sentry

La sortie relevée dans le travail préparatoire comporte 25 actions : 13 classées en lecture et 12 classées en écriture. Cette politique est valide au sens des catégories d'accès, mais elle dépasse largement le besoin exprimé.

Les actions de lecture générées couvrent notamment les ACL, les attributs, les tags, les versions, les torrents, la rétention et le verrouillage légal. Les actions d'écriture couvrent notamment la suppression, les versions, la réplication, la restauration Glacier, la rétention, le verrouillage légal et la gestion des chargements multiparties. Ces fonctions ne sont pas demandées pour un simple dépôt et une simple lecture de rapports.

Dans l'interprétation la plus stricte de « Rien d'autre », seules les actions suivantes sont nécessaires :

- `s3:GetObject` pour lire sous `2026/` ;
- `s3:PutObject` pour écrire sous `2026/entrant/`.

`s3:GetObjectTagging`, `s3:DeleteObject` et `s3:AbortMultipartUpload` ne sont pas retenues : la consultation des tags, la suppression et l'annulation d'un transfert multipartie ne figurent pas dans le besoin. Si l'application prouve ultérieurement qu'elle réalise des transferts multiparties, `s3:AbortMultipartUpload` pourra être ajouté de manière justifiée.

### 3.3 Politique resserrée

Le fichier `lecture.json` sépare la lecture de l'écriture afin que `s3:PutObject` ne puisse pas écrire dans tout le préfixe de lecture. Les deux instructions imposent HTTPS et limitent l'origine à la plage d'adresses demandée.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LireRapports2026",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::acme-reports/2026/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "true"
        },
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    },
    {
      "Sid": "EcrireRapportsEntrants2026",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::acme-reports/2026/entrant/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "true"
        },
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    }
  ]
}
```

### 3.4 Vérification statique

La commande demandée est :

```console
parliament --file lecture.json
```

Le résultat fourni est une sortie vide. Parliament ne détecte donc aucun constat. Cela confirme la cohérence syntaxique des actions et des ARN, mais pas l'efficacité réelle des autorisations, puisque Moto n'évalue pas les politiques.

### 3.5 Création et rattachement attendus

Les commandes du sujet créeraient l'utilisateur `analyste`, la politique gérée `LectureRapports2026`, puis rattacheraient cette politique à l'utilisateur. Le résultat attendu de `list-attached-user-policies` est une entrée contenant :

```json
{
  "PolicyName": "LectureRapports2026",
  "PolicyArn": "arn:aws:iam::123456789012:policy/LectureRapports2026"
}
```

Cette sortie prouverait le rattachement, mais pas le respect effectif de la politique dans Moto.

## 4 Du secret permanent au rôle temporaire

### 4.1 Clé d'accès statique

La création d'une clé d'accès pour `analyste` produirait deux valeurs : un identifiant public commençant généralement par `AKIA` et une clé secrète affichée une seule fois. La date de création correspondrait au moment de l'appel. Aucune valeur n'est reproduite ici.

Une clé statique IAM ne contient pas de date d'expiration automatique. Six mois plus tard, elle peut donc encore être valide si elle n'a pas été désactivée, supprimée ou remplacée. L'absence de champ `Expiration` est précisément le risque à retenir.

### 4.2 Relation de confiance du rôle

Le fichier `confiance.json` indique que seul l'utilisateur `analyste` du compte émulé peut demander l'endossement du rôle. Il ne décrit pas les permissions du rôle, qui proviennent de la politique `LectureRapports2026` attachée séparément.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/analyste"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Le rôle attendu est `RoleLecture`. Sa relation de confiance répond à la question « qui peut l'endosser ? », tandis que la politique attachée répond à la question « que peut-il faire une fois endossé ? ».

### 4.3 Comparaison des identifiants

L'appel `sts:AssumeRole` demandé pour une durée de 900 secondes fournirait le résultat suivant :

| Élément | Clé statique de l'utilisateur | Identifiants temporaires du rôle |
|---|---|---|
| Préfixe attendu | `AKIA...` | `ASIA...` |
| Secret | Clé secrète permanente jusqu'à révocation | Clé secrète temporaire |
| Jeton de session | Absent | Présent et obligatoire |
| Expiration | Aucune expiration automatique | Environ 15 minutes après l'émission |
| Identité utilisée | Utilisateur IAM `analyste` | Session du rôle `RoleLecture` |

Le jeton de session distingue techniquement les identifiants STS d'une paire de clés IAM permanente. Les trois éléments temporaires doivent être utilisés ensemble et deviennent inutilisables après la date d'expiration.

### 4.4 Suppression de la clé permanente

Après suppression de la clé `AKIA...`, la commande de liste attendue ne doit plus retourner de métadonnée de clé :

```json
{
  "AccessKeyMetadata": []
}
```

Cette suppression retire le secret permanent. L'utilisateur conserve seulement la possibilité d'endosser le rôle, selon la relation de confiance et les permissions qui lui sont accordées.

### 4.5 Conséquence d'une fuite six mois plus tard

Si la clé statique a été publiée et n'a pas été révoquée, un attaquant peut encore l'utiliser six mois plus tard avec toutes les permissions de l'utilisateur. À l'inverse, les identifiants STS valables 900 secondes sont expirés depuis longtemps et ne peuvent plus servir, même si leurs trois valeurs ont été copiées.

L'incident Capital One vu en cours montre cependant que le caractère temporaire ne suffit pas à rendre des identifiants inoffensifs. Des identifiants de rôle volés peuvent être exploités pendant leur courte période de validité si le rôle possède des permissions excessives. La défense repose donc à la fois sur une durée courte, le moindre privilège, la protection du mécanisme d'obtention et la surveillance des usages inhabituels.

## 5 Une chaîne d'intégration continue sans clés

### 5.1 Relation de confiance GitHub Actions

Le fichier `confiance-ci.json` autorise uniquement un jeton GitHub Actions émis pour le dépôt `acme/rapports`, sur la branche `main`, et destiné au service STS d'AWS.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:acme/rapports:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

`StringEquals` sur l'audience empêche l'utilisation d'un jeton émis pour un autre service. La condition sur le sujet lie le rôle au dépôt et à la branche attendus.

### 5.2 Rôle de déploiement attendu

Le rôle peut être nommé `RoleCIRapports`. Les commandes prévues sont :

```console
aws iam create-role --role-name RoleCIRapports --assume-role-policy-document file://confiance-ci.json
aws iam attach-role-policy --role-name RoleCIRapports --policy-arn arn:aws:iam::123456789012:policy/LectureRapports2026
```

La chaîne CI n'a alors aucune clé AWS à stocker dans GitHub. À chaque exécution autorisée, elle présente son jeton OIDC et reçoit des identifiants temporaires associés au rôle.

### 5.3 Risque d'une condition de sujet trop large

Si la condition sur `sub` est absente, un attaquant capable d'obtenir un jeton GitHub Actions accepté par le fournisseur OIDC pourrait tenter d'endosser le rôle depuis un dépôt qui n'est pas celui prévu. Le rôle ne serait plus lié à `acme/rapports` ni à `main`.

Avec la valeur `repo:acme/*`, un attaquant contrôlant n'importe quel dépôt de l'organisation `acme` pourrait déclencher un workflow et présenter un sujet correspondant au joker. La compromission d'un dépôt secondaire ou la création d'un dépôt moins protégé pourrait alors donner accès au rôle de déploiement. La valeur exacte du sujet réduit la surface de confiance au dépôt et à la branche nécessaires.

### 5.4 Analyse Parliament et faux positifs

La commande prévue est :

```console
parliament --file confiance-ci.json
```

Le sujet annonce deux constats :

1. `Statement contains neither Resource nor NotResource` est un faux positif, car `confiance-ci.json` est une politique de confiance de rôle. Elle utilise `Principal` pour définir qui peut endosser le rôle et ne doit pas contenir un champ `Resource` comme une politique d'identité classique. La ressource concernée est le rôle auquel la relation de confiance appartient.
2. `Unknown federation source` est un faux positif dans ce contexte, car le principal fédéré est explicitement l'OIDC GitHub `token.actions.githubusercontent.com`. Parliament s'appuie sur un catalogue fini de fournisseurs et peut ne pas reconnaître cette source, même si la structure IAM est correcte.

Ces résultats montrent qu'un analyseur doit être utilisé dans son domaine de validité. Une règle conçue pour les politiques d'identité peut mal interpréter une relation de confiance, et un catalogue incomplet peut signaler un fournisseur valide comme inconnu.

## 6 Synthèse et grille d'audit

La grille ci-dessous évalue la configuration conçue dans le TP. Les politiques volontairement vulnérables `a.json`, `b.json` et `c.json` sont des objets d'audit et ne sont pas considérées comme déployées dans l'état final.

| Point de contrôle | Respecté ? | Justification dans le TP | Mesure à ajouter et preuve pour un auditeur |
|---|:---:|---|---|
| Compte racine scellé, sous MFA matériel, inutilisé au quotidien | Non évalué | Moto ne représente pas la gouvernance du compte racine et aucun MFA réel n'est configuré. | Dans un vrai compte : retirer toute clé du compte racine, activer un MFA matériel et surveiller son utilisation. Preuves : paramètres du compte, rapport d'identifiants IAM et événements CloudTrail concernant l'utilisateur racine. |
| Authentification fédérée et MFA résistant au phishing pour les humains | Non | L'utilisateur `analyste` est un utilisateur IAM local et non une identité humaine fédérée. | Utiliser IAM Identity Center avec un fournisseur d'identité et des facteurs FIDO2 ou WebAuthn. Preuves : configuration de la fédération, règles MFA du fournisseur et journaux d'authentification. |
| Rôles et identifiants temporaires pour les humains, les workloads et la CI | Partiellement | `RoleLecture` et le rôle OIDC de la CI utilisent STS. La clé statique de `analyste` est supprimée, mais l'identité humaine reste locale. | Généraliser l'accès humain fédéré et attribuer les droits par rôles. Preuves : événements `AssumeRole`, sessions Identity Center et absence de clés permanentes actives. |
| Politiques versionnées, revues et testées | Partiellement | Les politiques sont rédigées en JSON et analysées par Parliament, mais aucun dépôt, processus de revue ni test CI n'est démontré. | Stocker les politiques dans Git, imposer une revue par pull request et exécuter les analyseurs en CI. Preuves : historique Git, approbations et journaux de pipeline. |
| Recertification périodique des droits | Non | Aucun cycle de revue des accès n'est représenté par l'émulateur. | Mettre en place une campagne trimestrielle ou semestrielle avec propriétaires et révocation des droits inutiles. Preuves : rapports de campagne, décisions des responsables et tickets de retrait. |
| Environnements séparés par comptes distincts | Non | Moto utilise un unique compte émulé `123456789012`. | Employer AWS Organizations avec des comptes distincts pour développement, test et production, protégés par des SCP. Preuves : inventaire des comptes, structure des unités organisationnelles et politiques SCP. |
| Aucune action ou ressource en `*` hors cas encadré | Oui pour l'état final | `lecture.json` n'utilise que des actions précises. Le suffixe `*` des ARN S3 est encadré par les préfixes `2026/` et `2026/entrant/`. Les jokers dangereux des politiques d'exercice ne sont pas repris. | En production, ajouter un contrôle automatique bloquant les jokers non justifiés. Preuves : résultats Parliament, IAM Access Analyzer et règles de pipeline. |
| Aucune clé d'accès statique | Oui pour l'état final | La clé de `analyste` est supprimée et la CI utilise OIDC avec des identifiants STS temporaires. | Vérifier régulièrement qu'aucune nouvelle clé n'est créée. Preuves : rapport d'identifiants IAM, requêtes AWS Config et événements CloudTrail `CreateAccessKey`. |
| Aucun compte partagé ni compte local non fédéré | Non | `analyste` n'est pas partagé, mais reste un compte IAM local non fédéré. | Remplacer les utilisateurs IAM humains par des identités nominatives fédérées. Preuves : annuaire du fournisseur, affectations Identity Center et absence d'utilisateurs IAM humains. |
| Aucun secret dans le code ou les tickets | Oui sur les fichiers proposés | Les politiques et relations de confiance ne contiennent aucune clé. OIDC évite de stocker une clé AWS dans GitHub Actions. | Activer l'analyse de secrets et contrôler l'historique Git ainsi que les variables CI. Preuves : rapports de secret scanning, configuration du dépôt et procédure de rotation en cas d'alerte. |

Les points non couverts les plus importants sont la protection du compte racine, l'authentification humaine fédérée, la recertification périodique et la séparation des environnements par comptes. Ils dépendent d'une organisation AWS réelle et ne peuvent pas être prouvés avec Moto seul.

## Conclusion

Le TP met en évidence quatre règles. Une politique doit décrire un besoin précis, les ARN doivent correspondre au type de ressource visé, les secrets permanents doivent être remplacés par des sessions courtes, et une relation de confiance doit limiter exactement l'identité autorisée. Parliament et Policy Sentry facilitent ce travail, mais leurs résultats doivent rester soumis à une lecture humaine et au contexte d'architecture.

La configuration finale limite la lecture à `acme-reports/2026/*`, l'écriture à `acme-reports/2026/entrant/*`, impose un transport chiffré et une plage IP, remplace la clé permanente par un rôle et autorise la CI uniquement depuis `acme/rapports` sur `main`. Les contrôles organisationnels absents de Moto devront être ajoutés et prouvés dans un environnement AWS réel.
