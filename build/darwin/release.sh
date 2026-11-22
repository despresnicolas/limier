#!/bin/sh
# Publishes a Limier release that installed apps pick up through the updater (update.go).
# Usage: build/darwin/release.sh 0.2.0 "Ce qui change, en une ou deux phrases."
# Needs: gh (logged in), the signing key ~/.config/limier/update-signing.key (go run ./build/updatesign keygen).
set -eu
VERSION=${1:?version, e.g. 0.2.0}
NOTES=${2:-}
REPO=despresnicolas/limier
ZIP=bin/limier-macos-arm64.zip

case $VERSION in v*) echo "version without v" >&2; exit 1 ;; esac
CURRENT=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' build/darwin/Info.plist)
# The updater only offers a strictly higher version.
if [ "$(printf '%s\n%s\n' "$CURRENT" "$VERSION" | sort -V | tail -1)" != "$VERSION" ] || [ "$CURRENT" = "$VERSION" ]; then
  echo "version $VERSION must be higher than $CURRENT" >&2; exit 1
fi

/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" -c "Set :CFBundleVersion $VERSION" build/darwin/Info.plist
wails3 task darwin:package:dmg
rm -f "$ZIP"
ditto -c -k --keepParent bin/limier.app "$ZIP"
go run ./build/updatesign manifest -version "$VERSION" -zip "$ZIP" \
  -url "https://github.com/$REPO/releases/download/v$VERSION/$(basename "$ZIP")" -notes "$NOTES" -out bin/update.json

gh release create "v$VERSION" -R "$REPO" --title "Limier $VERSION" --notes "${NOTES:-Limier $VERSION}" \
  "$ZIP" bin/limier.dmg bin/update.json
echo "Published Limier $VERSION. Commit build/darwin/Info.plist (version $VERSION)."
