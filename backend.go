package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"limier/internal/app"
	"limier/internal/config"
	"limier/internal/db"
	"limier/internal/httpapi"
	"limier/internal/observability"
	nodetools "limier/scanners/node-tools"
)

const nodeToolsImage = "limier/node-tools:latest"

// backend runs the Limier API and workers in this process, on a SQLite file.
// Until it is ready, /api answers 503 with the startup state.
type backend struct {
	handler atomic.Pointer[http.Handler]
	state   atomic.Pointer[string]
	// notify shows a desktop notification (nil in tests).
	notify  func(title, body string) error
	updates updates

	mu     sync.Mutex
	stop   func()
	closed bool
}

func (b *backend) setState(s string) { b.state.Store(&s) }

// setStop records how to stop what has started so far; after shutdown it stops it right away.
func (b *backend) setStop(f func()) {
	b.mu.Lock()
	closed := b.closed
	if !closed {
		b.stop = f
	}
	b.mu.Unlock()
	if closed {
		f()
	}
}

// shutdown stops the workers and closes the database, once.
func (b *backend) shutdown() {
	b.mu.Lock()
	f := b.stop
	b.stop, b.closed = nil, true
	b.mu.Unlock()
	if f != nil {
		f()
	}
}

// middleware sends /api to the backend and everything else to the Wails asset server.
func (b *backend) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		// Handled here, not by the backend: uninstalling must work even when the backend failed to start.
		if r.URL.Path == "/api/v1/uninstall" {
			uninstall(w, r)
			return
		}
		if r.URL.Path == "/api/v1/update" || strings.HasPrefix(r.URL.Path, "/api/v1/update/") {
			b.updates.serve(w, r)
			return
		}
		h := b.handler.Load()
		if h == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": *b.state.Load(), "starting": "true"})
			return
		}
		// Only this app's webview reaches the asset server (server builds are refused, see server_guard.go):
		// the API has no authentication of its own.
		(*h).ServeHTTP(w, r)
	})
}

func (b *backend) start(ctx context.Context) {
	if err := b.run(ctx); err != nil {
		slog.Error("backend", "err", err)
		b.setState(err.Error())
	}
}

func (b *backend) run(ctx context.Context) error {
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	base = filepath.Join(base, "limier") // uninstallPaths must list it
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(base, 0o755); err != nil {
		return err
	}
	removeOldPostgres(ctx, base)

	// Defaults the environment may override.
	defaults := map[string]string{"LOCAL_REPOS_ROOT": home}
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		defaults["DOCKER_HOST"] = "unix://" + filepath.Join(home, ".docker/run/docker.sock") // Docker Desktop without the default socket
	}
	for k, v := range defaults {
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	observability.SetupLogger(cfg.LogLevel)

	pool, err := db.Open(ctx, filepath.Join(base, "limier.db"))
	if err != nil {
		return err
	}
	b.setStop(func() { _ = pool.Close() })
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	a, err := app.New(ctx, cfg, pool, app.Options{Worker: true, OpenURL: openURL, Notify: b.notify})
	if err != nil {
		return err
	}
	if err := a.Start(ctx); err != nil {
		return fmt.Errorf("start workers: %w", err)
	}
	srv, err := httpapi.New(ctx, a)
	if err != nil {
		return err
	}
	h := srv.Handler()
	b.setStop(func() {
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = a.Stop(sctx)
		_ = pool.Close()
	})
	b.handler.Store(&h)
	slog.Info("limier backend ready", "repos", cfg.LocalReposRoot)

	go ensureNodeTools(ctx)
	return nil
}

// removeOldPostgres deletes the data of the PostgreSQL that Limier used before SQLite: the new
// database starts empty, nothing is imported. A crash may have left that PostgreSQL running: stop it first.
func removeOldPostgres(ctx context.Context, base string) {
	data := filepath.Join(base, "pg")
	dirs := []string{data, filepath.Join(base, "pg-runtime"), filepath.Join(base, "pg-cache")}
	found := false
	for _, d := range dirs {
		if _, err := os.Stat(d); err == nil {
			found = true
		}
	}
	if !found {
		return
	}
	if _, err := os.Stat(filepath.Join(data, "postmaster.pid")); err == nil {
		// Best effort: if pg_ctl is gone, the deletion below still frees the disk.
		out, err := exec.CommandContext(ctx, filepath.Join(dirs[1], "bin/pg_ctl"), "stop", "-D", data, "-m", "fast").CombinedOutput()
		slog.Warn("stopped the old PostgreSQL", "err", err, "out", string(out))
	}
	for _, d := range dirs {
		if err := os.RemoveAll(d); err != nil {
			slog.Warn("remove old PostgreSQL data", "dir", d, "err", err)
		}
	}
	slog.Info("removed the old PostgreSQL data: Limier now uses SQLite and starts with an empty database", "dir", base)
}

// ensureNodeTools builds the code analysis image on first run; scans that need it fail until it exists.
func ensureNodeTools(ctx context.Context) {
	// Apps opened from the Finder get a minimal PATH, without the usual docker locations.
	os.Setenv("PATH", os.Getenv("PATH")+":/usr/local/bin:/opt/homebrew/bin")
	if exec.CommandContext(ctx, "docker", "image", "inspect", nodeToolsImage).Run() == nil {
		return
	}
	slog.Info("building " + nodeToolsImage)
	cmd := exec.CommandContext(ctx, "docker", "build", "-t", nodeToolsImage, "-")
	cmd.Stdin = bytes.NewReader(nodetools.Dockerfile)
	if out, err := cmd.CombinedOutput(); err != nil {
		slog.Error("build "+nodeToolsImage, "err", err, "out", string(out))
	}
}

// openURL hands a URL (an editor link) to the desktop. On macOS, `open` waits for Launch Services,
// so a missing editor comes back as an error instead of failing silently.
func openURL(u string) error {
	if runtime.GOOS != "darwin" {
		return application.Get().Browser.OpenURL(u)
	}
	if out, err := exec.Command("open", u).CombinedOutput(); err != nil {
		return fmt.Errorf("open %s: %w: %s", u, err, strings.TrimSpace(string(out)))
	}
	return nil
}
