package churn

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestCount(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	wt, _ := repo.Worktree()
	now := time.Now()
	commit := func(when time.Time, files map[string]string, parents ...plumbing.Hash) plumbing.Hash {
		t.Helper()
		for name, body := range files {
			p := filepath.Join(dir, name)
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := wt.Add(name); err != nil {
				t.Fatal(err)
			}
		}
		sig := &object.Signature{Name: "t", Email: "t@t", When: when}
		h, err := wt.Commit("c", &git.CommitOptions{Author: sig, Committer: sig, Parents: parents, AllowEmptyCommits: true})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	// too old: ignored, and the walk stops there.
	commit(now.AddDate(-2, 0, 0), map[string]string{"old.js": "1", "pkg/a.js": "0"})
	commit(now.AddDate(0, -3, 0), map[string]string{"pkg/a.js": "1", "root.js": "1"})
	side := commit(now.AddDate(0, -2, 0), map[string]string{"pkg/a.js": "2", "pkg/b.js": "1"})
	head, _ := repo.Head()
	// a merge commit: skipped, its first parent is followed.
	commit(now.AddDate(0, -1, 0), map[string]string{"pkg/merged.js": "1"}, side, head.Hash())
	commit(now, map[string]string{"pkg/a.js": "3"})

	got, err := Count(dir, now.AddDate(-1, 0, 0), 2000)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"pkg/a.js": 3, "pkg/b.js": 1, "root.js": 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("root: got %v, want %v", got, want)
	}
	// a workspace subfolder gets paths relative to itself.
	got, _ = Count(filepath.Join(dir, "pkg"), now.AddDate(-1, 0, 0), 2000)
	if want := map[string]int{"a.js": 3, "b.js": 1}; !reflect.DeepEqual(got, want) {
		t.Errorf("subfolder: got %v, want %v", got, want)
	}
	// maxCommits stops early.
	got, _ = Count(dir, now.AddDate(-1, 0, 0), 1)
	if want := map[string]int{"pkg/a.js": 1}; !reflect.DeepEqual(got, want) {
		t.Errorf("max: got %v, want %v", got, want)
	}
}

func TestCountNoGit(t *testing.T) {
	dir := t.TempDir()
	if got, err := Count(dir, time.Time{}, 10); err != nil || len(got) != 0 {
		t.Errorf("no git: %v %v", got, err)
	}
	if _, err := git.PlainInit(dir, false); err != nil {
		t.Fatal(err)
	}
	if got, err := Count(dir, time.Time{}, 10); err != nil || len(got) != 0 {
		t.Errorf("empty repo: %v %v", got, err)
	}
}
