<p align="center">
  <img src="build/appicon.png" width="128" alt="Limier icon">
</p>

<h1 align="center">Limier</h1>

<p align="center">
  <strong>A local health and security dashboard for your Node.js projects.</strong><br>
  Vulnerabilities, outdated dependencies, code quality, and safe fixes as git branches — all on your machine.
</p>

<p align="center">
  <a href="https://github.com/despresnicolas/limier/releases/latest/download/limier.dmg"><strong>Download for macOS (Apple Silicon)</strong></a>
  ·
  <a href="https://github.com/despresnicolas/limier/releases">All releases</a>
  ·
  <a href="README.fr.md">Français</a>
</p>

---

## Why Limier

You have dozens of Node.js projects in your folders. Which ones pull in a known CVE, a malicious package, or a dependency that is three majors behind? Limier answers in one screen, without a server, an account, or a CI pipeline.

- **Local first.** One desktop app, one SQLite file. Your code never leaves your machine.
- **Read-only analysis.** Scans are pure Go. Limier never runs `npm`, `node`, scripts, or hooks from the analysed project.
- **You stay in control.** A fix is a new git branch. Your working tree and current branch never change.

## Features

**Dependency security**
- Reads `package-lock.json`, `pnpm-lock.yaml` and `yarn.lock` (v1 and berry), monorepo workspaces included.
- Matches every package against [OSV.dev](https://osv.dev), enriched with CVSS, [EPSS](https://www.first.org/epss/) and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- Flags malicious packages (OpenSSF `MAL-` advisories) and typosquatting look-alikes.
- Priority score per finding, with reachability (is the package actually imported?).
- Background watch every 6 hours, with a native notification when a new vulnerability appears.
- CycloneDX SBOM per scan, CSV export.

**Code analysis**
- Lines of code by language, import graph, unused files and dependencies.
- Hard-coded secrets, risky patterns (`eval`, command or SQL injection, XSS sinks, disabled TLS).
- Cyclomatic complexity, long functions, deep nesting, copy-paste detection.
- Test coverage read from existing reports (Limier never runs your tests).
- SonarQube-style ratings and history of every scan.
- Inline suppressions: `// limier-ignore <rule> -- reason`.

**Fixes**
- Proposed upgrades for direct dependencies and overrides for vulnerable transitive ones, with an effort estimate.
- One click creates `fix/bump-<package>-<version>` from `HEAD` in your repo. Review it and merge it yourself:

```sh
git branch --list 'fix/*'
git diff HEAD...fix/bump-cookie-0.7.0
git merge fix/bump-cookie-0.7.0
```

**Overview**
- Dashboard across all projects: open CVEs by severity, KEV, malicious packages, 90-day trend, riskiest projects.
- "Where is this package?": search `name`, `name@1.2.3` or `name@^1.6` across every project.
- Version drift: packages used at several versions.
- French and English UI.

## Install

1. Download [`limier.dmg`](https://github.com/despresnicolas/limier/releases/latest/download/limier.dmg) and drag **Limier** to **Applications**.
2. The app is not notarized by Apple yet. On first launch, right-click **Limier → Open**, or run:

   ```sh
   xattr -dr com.apple.quarantine /Applications/limier.app
   ```

3. In **Projets → Ajouter un projet**, tick your Node.js folders and click **Analyser**.

Requirements: macOS 12 or later, Apple Silicon. Creating fix branches currently needs [Docker](https://www.docker.com/products/docker-desktop/) running; scans do not.

Limier updates itself: it checks GitHub Releases at start and once a day, and installs only packages signed with its ed25519 key.

### Data and network

- Data: `~/Library/Application Support/limier/limier.db`. **Réglages → Désinstaller** removes it.
- Network calls: OSV.dev, CISA KEV, FIRST EPSS, the npm registry, deps.dev, and GitHub Releases for updates. Only package names and versions are sent, never source code.

## Build from source

Prerequisites: Go 1.27+, Node.js 22+, [Wails 3](https://v3.wails.io) (`wails3`) and [Task](https://taskfile.dev).

```sh
git clone https://github.com/despresnicolas/limier.git
cd limier
cd frontend && npm ci && cd ..

wails3 dev -config ./build/config.yml   # dev mode with hot reload
task build                              # binary in bin/
wails3 task darwin:package:dmg          # bin/limier.app and bin/limier.dmg
```

Tests:

```sh
go test ./...                     # app shell
cd backend && go test ./...       # scanners, database, jobs
cd frontend && npm run check      # svelte-check
```

## Architecture

| Part | Stack |
|------|-------|
| `./` | Wails 3 shell: window, updater, native notifications. The API is served in-process to the webview only, never on a port. |
| `backend/` | Go business logic: lockfile parsers, scanners, fix engine, [River](https://riverqueue.com) jobs, SQLite (`modernc.org/sqlite`) with sqlc and goose migrations. |
| `frontend/` | SvelteKit 5, static adapter, hash routing. |
| `build/` | Packaging, DMG layout, release signing (`build/updatesign`). |

## Releasing

```sh
build/darwin/release.sh 0.2.0 "What changed, in one or two sentences."
```

The script bumps the version in `build/darwin/Info.plist`, builds the DMG and the update zip, signs the zip, and publishes a GitHub release with `update.json`. The signing key stays in `~/.config/limier/update-signing.key` and is never committed.

## License

[GPL-3.0](LICENSE)
