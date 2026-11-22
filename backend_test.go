package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Starts the embedded backend twice on the same data, as two app launches do, and calls the API through the middleware.
// The first start also removes the folders of the PostgreSQL used before SQLite.
func TestBackendStartsTwice(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LOCAL_REPOS_ROOT", home)
	cfg, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(cfg, "limier")
	oldPG := []string{"pg", "pg-runtime", "pg-cache"}
	for _, d := range oldPG {
		if err := os.MkdirAll(filepath.Join(base, d, "x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		ctx, cancel := context.WithCancel(context.Background())
		b := &backend{}
		b.setState("starting")
		t0 := time.Now()
		if err := b.run(ctx); err != nil {
			cancel()
			t.Fatalf("start %d: %v", i+1, err)
		}
		t.Logf("start %d ready in %v", i+1, time.Since(t0))
		rec := httptest.NewRecorder()
		b.middleware(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/features", nil))
		cancel()
		b.shutdown()
		if rec.Code != http.StatusOK {
			t.Fatalf("start %d: /api/v1/features = %d %s", i+1, rec.Code, rec.Body)
		}
	}
	for _, d := range oldPG {
		if _, err := os.Stat(filepath.Join(base, d)); !os.IsNotExist(err) {
			t.Errorf("old PostgreSQL folder %s not removed: %v", d, err)
		}
	}
	if _, err := os.Stat(filepath.Join(base, "limier.db")); err != nil {
		t.Errorf("database file: %v", err)
	}
}
