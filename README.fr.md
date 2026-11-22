<p align="center">
  <img src="build/appicon.png" width="128" alt="Icône de Limier">
</p>

<h1 align="center">Limier</h1>

<p align="center">
  <strong>Un tableau de bord local pour la santé et la sécurité de vos projets Node.js.</strong><br>
  Vulnérabilités, dépendances en retard, qualité du code et correctifs sûrs en branches git, le tout sur votre machine.
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

Vous avez des dizaines de projets Node.js dans vos dossiers. Lesquels embarquent une CVE connue, un paquet malveillant ou une dépendance en retard de trois versions majeures ? Limier répond sur un seul écran, sans serveur, sans compte et sans pipeline CI.

- **Local d'abord.** Une application de bureau, un fichier SQLite. Votre code ne quitte jamais votre machine.
- **Analyse en lecture seule.** Les scans sont écrits en Go. Limier n'exécute jamais `npm`, `node`, ni les scripts ou les hooks du projet analysé.
- **Vous gardez la main.** Un correctif est une nouvelle branche git. Votre working tree et votre branche courante ne changent jamais.

## Fonctionnalités

**Sécurité des dépendances**
- Lit `package-lock.json`, `pnpm-lock.yaml` et `yarn.lock` (v1 et berry), workspaces de monorepo compris.
- Compare chaque paquet à [OSV.dev](https://osv.dev), avec en plus CVSS, [EPSS](https://www.first.org/epss/) et [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- Signale les paquets malveillants (avis OpenSSF `MAL-`) et les noms proches de paquets connus (typosquatting).
- Calcule un score de priorité par vulnérabilité, avec l'atteignabilité : le paquet est-il vraiment importé ?
- Surveille en arrière-plan toutes les 6 h et envoie une notification système quand une nouvelle faille apparaît.
- Produit un SBOM CycloneDX par scan et un export CSV.

**Analyse du code**
- Lignes de code par langage, graphe d'imports, fichiers et dépendances inutilisés.
- Secrets en dur et motifs à risque (`eval`, injection de commande ou SQL, XSS, TLS désactivé).
- Complexité cyclomatique, fonctions longues, imbrication profonde, code dupliqué.
- Couverture de tests lue dans les rapports existants. Limier ne lance jamais vos tests.
- Notes à la SonarQube et historique de chaque scan.
- Exclusions dans le code : `// limier-ignore <règle> -- raison`.

**Correctifs**
- Propose des montées de version pour les dépendances directes et des overrides pour les transitives vulnérables, avec une estimation de l'effort.
- Un clic crée la branche `fix/bump-<paquet>-<version>` depuis `HEAD` dans votre dépôt. Relisez-la et mergez-la vous-même :

```sh
git branch --list 'fix/*'
git diff HEAD...fix/bump-cookie-0.7.0
git merge fix/bump-cookie-0.7.0
```

**Vue d'ensemble**
- Tableau de bord de tous les projets : CVE ouvertes par sévérité, KEV, paquets malveillants, tendance sur 90 jours, projets à risque.
- « Où est ce paquet ? » : cherchez `nom`, `nom@1.2.3` ou `nom@^1.6` dans tous les projets.
- Dérive des versions : les paquets utilisés à plusieurs versions.
- Interface en français et en anglais.

## Installation

1. Téléchargez [`limier.dmg`](https://github.com/despresnicolas/limier/releases/latest/download/limier.dmg) et glissez **Limier** dans **Applications**.
2. Apple n'a pas encore notarié l'application. Au premier lancement, faites un clic droit sur **Limier → Ouvrir**, ou lancez :

   ```sh
   xattr -dr com.apple.quarantine /Applications/limier.app
   ```

3. Dans **Projets → Ajouter un projet**, cochez vos dossiers Node.js et cliquez sur **Analyser**.

Prérequis : macOS 12 ou plus récent, Apple Silicon. Pour l'instant, la création des branches de correctif demande que [Docker](https://www.docker.com/products/docker-desktop/) tourne. Les scans n'en ont pas besoin.

Limier se met à jour seul. Il vérifie les GitHub Releases au démarrage puis une fois par jour, et n'installe que des paquets signés avec sa clé ed25519.

### Données et réseau

- Données : `~/Library/Application Support/limier/limier.db`. **Réglages → Désinstaller** les supprime.
- Appels réseau : OSV.dev, CISA KEV, FIRST EPSS, le registry npm, deps.dev, et les GitHub Releases pour les mises à jour. Limier n'envoie que des noms et des versions de paquets, jamais de code source.

## Compiler depuis les sources

Prérequis : Go 1.27+, Node.js 22+, [Wails 3](https://v3.wails.io) (`wails3`) et [Task](https://taskfile.dev).

```sh
git clone https://github.com/despresnicolas/limier.git
cd limier
cd frontend && npm ci && cd ..

wails3 dev -config ./build/config.yml   # mode dev avec rechargement à chaud
task build                              # binaire dans bin/
wails3 task darwin:package:dmg          # bin/limier.app et bin/limier.dmg
```

Tests :

```sh
go test ./...                     # coque de l'application
cd backend && go test ./...       # scanners, base de données, jobs
cd frontend && npm run check      # svelte-check
```

## Architecture

| Partie | Pile |
|--------|------|
| `./` | Coque Wails 3 : fenêtre, mises à jour, notifications système. L'API est servie dans le processus, à la webview seulement, jamais sur un port. |
| `backend/` | Logique métier en Go : parseurs de lockfiles, scanners, moteur de correctifs, jobs [River](https://riverqueue.com), SQLite (`modernc.org/sqlite`) avec sqlc et des migrations goose. |
| `frontend/` | SvelteKit 5, adapter statique, routage par hash. |
| `build/` | Packaging, mise en page du DMG, signature des releases (`build/updatesign`). |

## Publier une version

```sh
build/darwin/release.sh 0.2.0 "Ce qui change, en une ou deux phrases."
```

Le script augmente la version dans `build/darwin/Info.plist`, construit le DMG et le zip de mise à jour, signe le zip, puis publie une release GitHub avec `update.json`. La clé de signature reste dans `~/.config/limier/update-signing.key` et n'est jamais commitée.

## Licence

[GPL-3.0](LICENSE)
