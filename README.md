<p align="center">
  <img src="build/appicon.png" width="128" alt="Limier icon">
</p>

<h1 align="center">Limier</h1>

<p align="center">
  <strong>The detective for your Node.js projects.</strong><br>
  Vulnerabilities, malicious packages, outdated dependencies and code quality, on one screen, without leaving your Mac.
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

You have dozens of Node.js projects in your folders. Which ones pull in a known vulnerability, a malicious package, or a dependency three majors behind? Limier tells you in seconds.

- **Everything stays on your Mac.** No account, no server, no CI. Your code never leaves the machine.
- **Read-only.** Limier reads your files. It never runs `npm`, `node`, or your project scripts.
- **You stay in control.** A fix becomes a git branch that you review. Your work in progress does not move.

## Install

1. Download [`limier.dmg`](https://github.com/despresnicolas/limier/releases/latest/download/limier.dmg).
2. Open it and drag **Limier** to **Applications**.
3. The app is not notarized by Apple yet. On first launch, right-click **Limier → Open**, then confirm. Or run:

   ```sh
   xattr -dr com.apple.quarantine /Applications/limier.app
   ```

**Requirements:** macOS 12 or later, Apple Silicon Mac. Creating fix branches needs [Docker](https://www.docker.com/products/docker-desktop/) running. Scans do not.

The interface opens in French. Switch to English in **Réglages → Langue** (Settings → Language).

## Getting started

1. Open **Projects → Add a project**.
2. Browse your folders, tick one or more Node.js projects, and click **Analyse**. A monorepo shows one sub-project per workspace.
3. Wait for the scan: a few seconds per project.
4. Open the **Dashboard** to see the state of all your projects.

## What you see

### Dashboard

Open vulnerabilities by severity, actively exploited ones (CISA KEV), malicious packages, the 90-day trend and the riskiest projects.

### Vulnerabilities

The vulnerabilities of every project, sorted by priority. Filter by severity, priority, status, direct or indirect dependency, KEV, malicious packages, or **New only**. **Export as CSV** saves the list.

Priority combines severity (CVSS), exploit probability (EPSS), presence in KEV and real usage of the package. A vulnerability in a package your code never imports is marked "unreachable".

### Project page

| Tab | Content |
|-----|---------|
| **Vulnerabilities** | The project's vulnerabilities and the version that fixes each one. |
| **Dependencies** | Outdated or deprecated direct dependencies. Each one expands to its indirect dependencies. |
| **Code** | Code ratings, hard-coded secrets, risky patterns (`eval`, injections, XSS), complexity, duplicated code, unused files and dependencies, test coverage. Click a `file:line` to open your editor at that line. |
| **Fixes** | Proposed upgrades. See below. |
| **History** | Every scan and how the metrics change. |
| **Settings** | Project policy, branch prefix, editor, deleting the analysis. |

### Packages

- **Where is this package?** A vulnerability just hit `axios`? Type `axios`, `axios@1.6.0` or `axios@<1.7.0`: Limier lists every project that uses it.
- **Version drift:** packages used at different versions across projects.

## Apply a fix

1. Open the **Fixes** tab of a project.
2. Check the estimated effort (low, medium, high) and, if needed, the package changelog.
3. Click **Accept**. Limier creates the branch `fix/bump-<package>-<version>` from `HEAD`.
4. For safe upgrades, **Group the safe bumps** puts them all in one branch.
5. In your terminal, review the branch, install, test, then merge:

   ```sh
   git switch fix/bump-cookie-0.7.0
   npm install && npm test
   git switch main && git merge fix/bump-cookie-0.7.0
   ```

Limier never touches your working tree or current branch. It never overwrites a branch and never runs git hooks. The lockfile is not regenerated: the commit message gives the install command to run.

## Mark a false positive

Add a `limier-ignore` comment with the exact rule name and a reason. Alone on its line, it applies to the next code line:

```js
// limier-ignore sast.eval -- the input is a constant
eval(template);
```

The issue leaves the list. A collapsible card in the **Code** tab keeps the list of suppressions. A secret stays reported unless the comment gives a reason.

## Settings

- **Display:** light, dark or system theme, language (French or English), default editor.
- **Watch:** **Watch for new vulnerabilities** rechecks your packages every 6 hours and sends a notification when a new one appears. Limier does not reread your projects for this.
- **Global policy:** maximum dependency age and priority score weights. Each project can have its own policy.
- **Updates:** Limier checks at start and every 24 hours. Nothing installs without your click, and any update not signed by the author is refused.
- **Uninstall Limier…:** removes the app data.

## Your data

- Data lives in `~/Library/Application Support/limier/limier.db`.
- Deleting a project in Limier removes its analysis, never your folder.
- Limier contacts OSV.dev, CISA KEV, FIRST EPSS, the npm registry, deps.dev, and GitHub for updates. It sends only package names and versions, never code.

## Build from source

Prerequisites: Go 1.27+, Node.js 22+, [Wails 3](https://v3.wails.io) and [Task](https://taskfile.dev).

```sh
git clone https://github.com/despresnicolas/limier.git && cd limier
(cd frontend && npm ci)
wails3 dev -config ./build/config.yml   # development mode
wails3 task darwin:package:dmg          # builds bin/limier.dmg
```

## License

Copyright (C) 2026 Nicolas Despres

This program is free software: you can redistribute it and/or modify it under the terms of the [GNU General Public License version 3](LICENSE) as published by the Free Software Foundation. It comes with no warranty.
