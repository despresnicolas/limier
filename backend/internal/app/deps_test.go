package app

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadLockGraph(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := readLockGraph(dir, "npm", nil); !errors.Is(err, errNoLockfile) || !isPermanent(err) {
		t.Fatalf("no lockfile: %v", err)
	}
	lock, err := os.ReadFile("../scanners/testdata/pnpm-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), lock, 0o644); err != nil {
		t.Fatal(err)
	}
	// The detected manager is only a preference: the pnpm lockfile is still found.
	g, _, err := readLockGraph(dir, "npm", nil)
	if err != nil || len(g.Packages()) == 0 {
		t.Fatalf("pnpm: %v %v", g, err)
	}
}
