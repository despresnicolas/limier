package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"limier/internal/config"
)

func localApp(t *testing.T) (*App, string) {
	t.Helper()
	root := t.TempDir()
	write := func(p, content string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app/package.json", `{"name":"app","dependencies":{"express":"^4"}}`)
	write("app/package-lock.json", `{"lockfileVersion":3,"packages":{}}`)
	write("app/node_modules/x/package.json", `{}`)
	write("team/mono/package.json", `{"name":"mono","workspaces":["packages/*"]}`)
	write("team/mono/pnpm-lock.yaml", ``)
	write("team/mono/packages/a/package.json", `{"name":"a"}`)
	write("team/mono/packages/b/package.json", `{"name":"b"}`)
	write("docs/readme.md", `no package.json`)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.json"), []byte(`{"name":"secret"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "linked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.json"), filepath.Join(root, "linked", "package.json")); err != nil {
		t.Fatal(err)
	}
	return &App{cfg: config.Config{LocalReposRoot: root}}, root
}

func TestResolveLocal(t *testing.T) {
	a, root := localApp(t)
	ok := map[string]string{
		"app":                      "app",
		"./app/":                   "app",
		"team/mono":                "team/mono",
		filepath.Join(root, "app"): "app",
		"../../../" + "app":        "app", // cleaned before joining: cannot climb above the root
	}
	for in, want := range ok {
		got, err := a.resolveLocal(in)
		if err != nil || got != want {
			t.Errorf("resolveLocal(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"escape", "missing", "app/package.json", "/etc", "/app", filepath.Dir(root)} {
		if _, err := a.resolveLocal(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("resolveLocal(%q) should be rejected, got %v", in, err)
		}
	}
	if _, err := (&App{}).resolveLocal("app"); !errors.Is(err, ErrLocalDisabled) {
		t.Errorf("disabled root: %v", err)
	}
}

func TestDetectLocal(t *testing.T) {
	a, _ := localApp(t)
	d, err := a.detectLocal("team/mono")
	if err != nil || !d.NodeProject || d.PackageManager != "pnpm" || len(d.Workspaces) != 2 {
		t.Fatalf("mono: %+v %v", d, err)
	}
	d, err = a.detectLocal("app")
	if err != nil || d.PackageManager != "npm" || len(d.Workspaces) != 0 {
		t.Fatalf("app: %+v %v", d, err)
	}
	// package.json symlinked outside the root is not read.
	if d, err := a.detectLocal("linked"); err != nil || d.NodeProject {
		t.Fatalf("linked manifest outside root must be ignored: %+v %v", d, err)
	}
}

func TestListLocalDir(t *testing.T) {
	a, root := localApp(t)
	if err := os.MkdirAll(filepath.Join(root, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "app", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := a.listLocalDir("")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range b.Dirs {
		names = append(names, d.Name)
	}
	// Hidden folders and symlinks (escape) are not listed.
	if got := strings.Join(names, ","); got != "app,docs,linked,team" {
		t.Fatalf("root dirs: %s", got)
	}
	if !b.Dirs[0].Node || !b.Dirs[0].Git || b.Dirs[1].Node {
		t.Fatalf("flags: %+v", b.Dirs[:2])
	}
	b, err = a.listLocalDir("team")
	if err != nil || len(b.Dirs) != 1 || b.Dirs[0].Path != "team/mono" || !b.Dirs[0].Node {
		t.Fatalf("team: %+v %v", b, err)
	}
	b, err = a.listLocalDir("app")
	if err != nil || len(b.Dirs) != 0 || !b.Node || !b.Git {
		t.Fatalf("app (node_modules and .git hidden): %+v %v", b, err)
	}
	for _, bad := range []string{".ssh", "app/.git", "escape"} {
		if b, err := a.listLocalDir(bad); err == nil {
			t.Errorf("%s should be refused, got %+v", bad, b)
		}
	}
}
