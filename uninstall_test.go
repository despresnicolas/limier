package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleIDMatchesInfoPlist(t *testing.T) {
	b, err := os.ReadFile("build/darwin/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "<string>"+bundleID+"</string>") {
		t.Fatalf("Info.plist does not declare %s: uninstall would miss the WebKit and cache folders", bundleID)
	}
}

func TestAppBundle(t *testing.T) {
	for exe, want := range map[string]string{
		"/Applications/limier.app/Contents/MacOS/limier": "/Applications/limier.app",
		"/Users/x/Dev/seckit/bin/limier":                 "",
		"/tmp/Contents/MacOS/limier":                     "",
	} {
		if got := appBundle(exe); got != want {
			t.Errorf("appBundle(%q) = %q, want %q", exe, got, want)
		}
	}
}

// TestUninstallScript runs the real script on a fake home: every trace goes, the app lands in the Trash,
// and files outside the list stay.
func TestUninstallScript(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, "Library", "Application Support")
	paths := uninstallPaths(home, cfg)
	db := filepath.Join(cfg, "limier", "limier.db")
	mustWrite(t, db+"-wal")
	mustWrite(t, filepath.Join(cfg, "limier", "pg", "PG_VERSION")) // old PostgreSQL left by a crash
	for _, p := range paths {
		if strings.HasSuffix(p, ".plist") || strings.HasSuffix(p, ".binarycookies") {
			mustWrite(t, p)
		} else {
			mustWrite(t, filepath.Join(p, "with space", "file"))
		}
	}
	app := filepath.Join(home, "Applications", "limier.app")
	mustWrite(t, filepath.Join(app, "Contents", "MacOS", "limier"))
	keep := filepath.Join(cfg, "other-app", "data")
	mustWrite(t, keep)
	if err := os.MkdirAll(filepath.Join(home, ".Trash"), 0o755); err != nil {
		t.Fatal(err)
	}

	// 999999: no such process, so the script does not wait.
	args := append([]string{"-c", uninstallScript, "limier-uninstall", "999999", app}, paths...)
	cmd := exec.Command("/bin/sh", args...)
	cmd.Env = append(os.Environ(), "HOME="+home, "PATH=/usr/bin:/bin") // no docker: that step is skipped
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script: %v\n%s", err, out)
	}

	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists", p)
		}
	}
	if _, err := os.Stat(app); !os.IsNotExist(err) {
		t.Errorf("app still in place")
	}
	if _, err := os.Stat(filepath.Join(home, ".Trash", "limier.app", "Contents", "MacOS", "limier")); err != nil {
		t.Errorf("app not in the Trash: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("deleted a file outside the list: %v", err)
	}
}

func mustWrite(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPlistVersion(t *testing.T) {
	b, err := os.ReadFile("build/darwin/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if v := plistVersion(b); v == "" {
		t.Fatal("no CFBundleShortVersionString in Info.plist: the updater would stay off")
	}
	if v := plistVersion([]byte("<key>CFBundleShortVersionString</key>\n\t<string>1.2.3</string>")); v != "1.2.3" {
		t.Fatalf("got %q", v)
	}
}
