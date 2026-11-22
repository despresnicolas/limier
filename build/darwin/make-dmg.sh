#!/bin/sh
# Builds the Limier installer DMG: the app, an Applications link, a branded background, nothing else.
# Only macOS tools (hdiutil, osascript). Finder lays out the window, so the first run may ask to let
# the terminal control Finder.
# Usage: build/darwin/make-dmg.sh bin/limier.app bin/limier.dmg
set -eu
APP=$1
OUT=$2
VOL=Limier
BG=build/darwin/dmg-background.tiff # 540x380 @1x + @2x (tiffutil -cathidpicheck)

WORK=$(mktemp -d)
trap 'hdiutil detach "/Volumes/$VOL" -quiet 2>/dev/null || true; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/src/.background"
cp -R "$APP" "$WORK/src/"
ln -s /Applications "$WORK/src/Applications"
cp "$BG" "$WORK/src/.background/background.tiff"

hdiutil detach "/Volumes/$VOL" -quiet 2>/dev/null || true
hdiutil create -quiet -srcfolder "$WORK/src" -volname "$VOL" -fs HFS+ -format UDRW "$WORK/rw.dmg"
hdiutil attach -quiet -readwrite -noautoopen "$WORK/rw.dmg"

APPNAME=$(basename "$APP")
osascript <<EOF
tell application "Finder"
  tell disk "$VOL"
    open
    set w to container window
    set current view of w to icon view
    set toolbar visible of w to false
    set statusbar visible of w to false
    set sidebar width of w to 0
    set bounds of w to {200, 140, 740, 520}
    set o to icon view options of w
    set arrangement of o to not arranged
    set icon size of o to 112
    set text size of o to 13
    set background picture of o to file ".background:background.tiff"
    set position of item "$APPNAME" of w to {150, 184}
    set position of item "Applications" of w to {390, 184}
    -- Off-window, in case Finder shows hidden files.
    set position of item ".background" of w to {150, 700}
    close
    open
    update without registering applications
    delay 1
    close
  end tell
end tell
EOF
chflags hidden "/Volumes/$VOL/.background"
rm -rf "/Volumes/$VOL/.fseventsd"
sync
hdiutil detach -quiet "/Volumes/$VOL"
rm -f "$OUT"
hdiutil convert -quiet "$WORK/rw.dmg" -format UDZO -imagekey zlib-level=9 -o "$OUT"
