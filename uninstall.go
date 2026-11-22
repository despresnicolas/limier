package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// bundleID must match CFBundleIdentifier in build/darwin/Info.plist (checked by a test).
const bundleID = "com.bh-technologies.limier"

// uninstallPaths lists everything Limier writes outside its app bundle. Git branches created by fixes
// stay: they belong to the user's repositories.
func uninstallPaths(home, configDir string) []string {
	lib := filepath.Join(home, "Library")
	return []string{
		filepath.Join(configDir, "limier"),     // limier.db, -wal, -shm, and any old PostgreSQL folder
		filepath.Join(lib, "WebKit", bundleID), // localStorage: theme, language, editors
		filepath.Join(lib, "Caches", bundleID),
		filepath.Join(lib, "HTTPStorages", bundleID),
		filepath.Join(lib, "HTTPStorages", bundleID+".binarycookies"),
		filepath.Join(lib, "Preferences", bundleID+".plist"),
		filepath.Join(lib, "Saved Application State", bundleID+".savedState"),
	}
}

// appBundle returns the .app holding exe, or "" when the binary does not run from a bundle (wails3 dev).
func appBundle(exe string) string {
	dir := filepath.Dir(exe) // …/limier.app/Contents/MacOS
	if filepath.Base(dir) != "MacOS" || filepath.Base(filepath.Dir(dir)) != "Contents" {
		return ""
	}
	app := filepath.Dir(filepath.Dir(dir))
	if !strings.HasSuffix(app, ".app") {
		return ""
	}
	return app
}

// uninstallScript runs detached once the app has quit: $1 is the app's pid, $2 the .app ("" to keep it),
// then the paths to delete. Arguments, never interpolation, so paths with spaces or quotes stay safe.
const uninstallScript = `pid=$1 app=$2; shift 2
while kill -0 "$pid" 2>/dev/null; do sleep 0.2; done
for p in "$@"; do rm -rf "$p"; done
PATH="$PATH:/usr/local/bin:/opt/homebrew/bin" docker image rm limier/node-tools >/dev/null 2>&1
if [ -n "$app" ] && [ -d "$app" ]; then
  dest="$HOME/.Trash/$(basename "$app")"
  [ -e "$dest" ] && dest="$HOME/.Trash/$(basename "$app" .app) $(date +%H.%M.%S).app"
  mv "$app" "$dest"
fi
`

// uninstall starts the detached cleanup, answers, then quits the app (which closes the database).
func uninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := startUninstall(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	go application.Get().Quit()
}

func startUninstall() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"-c", uninstallScript, "limier-uninstall", strconv.Itoa(os.Getpid()), appBundle(exe)}
	args = append(args, uninstallPaths(home, cfg)...)
	cmd := exec.Command("/bin/sh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // survives the app's exit
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start uninstall: %w", err)
	}
	return cmd.Process.Release()
}
