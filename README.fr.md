<p align="center">
  <img src="build/appicon.png" width="128" alt="Icône de Limier">
</p>

<h1 align="center">Limier</h1>

<p align="center">
  <strong>Le détective de vos projets Node.js.</strong><br>
  Failles, paquets malveillants, dépendances en retard et qualité du code, sur un seul écran et sans quitter votre Mac.
</p>

<p align="center">
  <a href="https://github.com/despresnicolas/limier/releases/latest/download/limier.dmg"><strong>Télécharger pour macOS (Apple Silicon)</strong></a>
  ·
  <a href="https://github.com/despresnicolas/limier/releases">Toutes les versions</a>
  ·
  <a href="README.md">English</a>
</p>

---

## Pourquoi Limier

Vous avez des dizaines de projets Node.js dans vos dossiers. Lesquels embarquent une faille connue, un paquet malveillant, ou une dépendance en retard de trois versions majeures ? Limier vous répond en quelques secondes.

- **Tout reste sur votre Mac.** Pas de compte, pas de serveur, pas de CI. Votre code ne quitte jamais la machine.
- **Lecture seule.** Limier lit vos fichiers. Il n'exécute jamais `npm`, `node`, ni les scripts de vos projets.
- **Vous gardez la main.** Un correctif devient une branche git que vous relisez. Votre travail en cours ne bouge pas.

## Installation

1. Téléchargez [`limier.dmg`](https://github.com/despresnicolas/limier/releases/latest/download/limier.dmg).
2. Ouvrez le fichier et glissez **Limier** dans **Applications**.
3. Apple n'a pas encore notarié l'application. Au premier lancement, faites un clic droit sur **Limier → Ouvrir**, puis confirmez. Vous pouvez aussi lancer :

   ```sh
   xattr -dr com.apple.quarantine /Applications/limier.app
   ```

**Prérequis :** macOS 12 ou plus récent, Mac Apple Silicon. Pour créer des branches de correctif, [Docker](https://www.docker.com/products/docker-desktop/) doit tourner. Les analyses n'en ont pas besoin.

## Prise en main

1. Ouvrez **Projets → Ajouter un projet**.
2. Naviguez dans vos dossiers, cochez un ou plusieurs projets Node.js, puis cliquez sur **Analyser**. Un monorepo apparaît avec un sous-projet par workspace.
3. Attendez la fin de l'enquête : quelques secondes par projet.
4. Ouvrez le **Tableau de bord** pour voir l'état de tous vos projets.

## Ce que vous voyez

### Tableau de bord

Le nombre de failles ouvertes par sévérité, les failles exploitées activement (CISA KEV), les paquets malveillants, la tendance sur 90 jours et les projets les plus à risque.

### Vulnérabilités

Les failles de tous les projets, triées par priorité. Filtrez par sévérité, priorité, statut, dépendance directe ou indirecte, KEV, paquets malveillants ou **Nouvelles uniquement**. Le bouton **Exporter en CSV** enregistre la liste.

La priorité combine la gravité (CVSS), la probabilité d'exploitation (EPSS), la présence dans KEV et l'usage réel du paquet. Une faille sur un paquet que votre code n'importe pas porte la mention « non atteignable ».

### Fiche d'un projet

| Onglet | Contenu |
|--------|---------|
| **Vulnérabilités** | Les failles du projet et la version qui les corrige. |
| **Dépendances** | Les dépendances directes en retard ou dépréciées. Chacune se déplie sur ses dépendances indirectes. |
| **Code** | Les notes du code, les secrets en dur, les motifs à risque (`eval`, injections, XSS), la complexité, le code dupliqué, les fichiers et dépendances inutilisés, la couverture de tests. Un clic sur `fichier:ligne` ouvre votre éditeur à la bonne ligne. |
| **Correctifs** | Les montées de version proposées. Voir plus bas. |
| **Historique** | Chaque analyse et l'évolution des métriques. |
| **Paramètres** | La policy du projet, le préfixe des branches, l'éditeur, la suppression de l'analyse. |

### Paquets

- **Où est ce paquet ?** Une faille vient de sortir sur `axios` ? Tapez `axios`, `axios@1.6.0` ou `axios@<1.7.0` : Limier liste tous les projets qui l'utilisent.
- **Dérive des versions** : les paquets utilisés à plusieurs versions selon les projets.

## Appliquer un correctif

1. Ouvrez l'onglet **Correctifs** d'un projet.
2. Lisez l'effort estimé (faible, moyen, élevé) et, au besoin, le changelog du paquet.
3. Cliquez sur **Accepter**. Limier crée la branche `fix/bump-<paquet>-<version>` depuis `HEAD`.
4. Pour les montées sans risque, **Regrouper les montées sans risque** les met toutes dans une seule branche.
5. Dans votre terminal, relisez la branche, lancez l'installation et les tests, puis mergez :

   ```sh
   git switch fix/bump-cookie-0.7.0
   npm install && npm test
   git switch main && git merge fix/bump-cookie-0.7.0
   ```

Limier ne touche jamais votre working tree ni votre branche courante. Il n'écrase aucune branche et n'exécute aucun hook git. Le lockfile n'est pas régénéré : la commande d'installation est indiquée dans le message de commit.

## Signaler un faux positif

Ajoutez un commentaire `limier-ignore` avec le nom exact de la règle et une raison. Seul sur sa ligne, il vaut pour la ligne de code suivante :

```js
// limier-ignore sast.eval -- l'entrée est une constante
eval(template);
```

Le problème disparaît de la liste. Une carte repliable de l'onglet **Code** garde la liste des exclusions. Un secret reste signalé si le commentaire ne donne pas de raison.

## Réglages

- **Affichage :** thème clair, sombre ou système, langue (français ou anglais), éditeur par défaut.
- **Surveillance :** **Surveiller les nouvelles failles** revérifie vos paquets toutes les 6 h et vous envoie une notification si une faille apparaît. Limier ne relit pas vos projets pour cela.
- **Policy globale :** âge maximal d'une dépendance et pondérations du score de priorité. Chaque projet peut avoir sa propre policy.
- **Mises à jour :** Limier vérifie au démarrage puis toutes les 24 h. Rien ne s'installe sans votre clic, et toute mise à jour non signée par l'auteur est refusée.
- **Désinstaller Limier… :** supprime les données de l'application.

## Vos données

- Les données sont dans `~/Library/Application Support/limier/limier.db`.
- Supprimer un projet dans Limier efface son analyse, jamais votre dossier.
- Limier contacte OSV.dev, CISA KEV, FIRST EPSS, le registry npm, deps.dev, et GitHub pour les mises à jour. Il n'envoie que des noms et des versions de paquets, jamais de code.

## Compiler depuis les sources

Prérequis : Go 1.27+, Node.js 22+, [Wails 3](https://v3.wails.io) et [Task](https://taskfile.dev).

```sh
git clone https://github.com/despresnicolas/limier.git && cd limier
(cd frontend && npm ci)
wails3 dev -config ./build/config.yml   # mode développement
wails3 task darwin:package:dmg          # produit bin/limier.dmg
```

## Licence

Copyright (C) 2026 Nicolas Despres

Ce programme est un logiciel libre : vous pouvez le redistribuer et le modifier selon les termes de la [GNU General Public License version 3](LICENSE), publiée par la Free Software Foundation. Il est distribué sans aucune garantie.
