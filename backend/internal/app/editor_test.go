package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"limier/internal/config"
	"limier/internal/db/dbq"
)

func TestEditorURL(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "my repo")
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"my repo/src/a b.js", "secret.txt"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "secret.txt"), filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: config.Config{LocalReposRoot: root}}
	p := dbq.Project{LocalPath: "my repo"}
	abs := filepath.ToSlash(filepath.Join(dir, "src", "a b.js"))

	for _, c := range []struct{ editor, want string }{
		{"vscode", "vscode://file" + strings.ReplaceAll(abs, " ", "%20") + ":12"},
		{"webstorm", "webstorm://open?file=" + strings.NewReplacer("/", "%2F", " ", "%20").Replace(abs) + "&line=12"},
	} {
		got, err := a.EditorURL(p, c.editor, "src/a b.js", 12)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.editor, got, err, c.want)
		}
	}
	for _, c := range []struct{ editor, file string }{
		{"vscode", "../secret.txt"},
		{"vscode", "src/../../secret.txt"},
		{"vscode", abs},
		{"vscode", "link.txt"},
		{"vscode", "src"},
		{"vscode", "missing.js"},
		{"emacs", "src/a b.js"},
	} {
		if got, err := a.EditorURL(p, c.editor, c.file, 1); err == nil {
			t.Errorf("%s %s: got %q, want an error", c.editor, c.file, got)
		}
	}
}
