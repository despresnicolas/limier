package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/updater"
	"github.com/wailsapp/wails/v3/pkg/updater/providers/endpoint"
)

// Releases are published on the public repository despresnicolas/limier.
// update.json is signed release by release with build/updatesign (see build/darwin/release.sh).
const updateManifestURL = "https://github.com/despresnicolas/limier/releases/latest/download/update.json"

// updatePublicKey verifies every update (ed25519 over the zip's SHA-256). The private key stays on the
// publisher's machine (~/.config/limier/update-signing.key); losing it means users reinstall by hand.
const updatePublicKey = "ON7XUHiJtCC1syudnC6rN4/fB1QQh1GT5y1U0dDCr+o="

// appVersion reads CFBundleShortVersionString from the bundle the binary runs from, so Info.plist is the
// only place a version is written. Outside a bundle (wails3 dev, tests) it returns "".
func appVersion(exe string) string {
	app := appBundle(exe)
	if app == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(app, "Contents", "Info.plist"))
	if err != nil {
		return ""
	}
	return plistVersion(b)
}

var versionKey = regexp.MustCompile(`<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>`)

func plistVersion(plist []byte) string {
	if m := versionKey.FindSubmatch(plist); m != nil {
		return string(m[1])
	}
	return ""
}

// updates drives the Wails updater for the UI: a quiet check at start and every 24 h, nothing installed
// without a click.
type updates struct {
	version string
	mu      sync.Mutex
	release *updater.Release
	err     string
	busy    bool
}

func (u *updates) init(app *application.App) {
	exe, _ := os.Executable()
	u.version = appVersion(exe)
	if u.version == "" {
		return // not a bundle: nothing to replace
	}
	key, err := base64.StdEncoding.DecodeString(updatePublicKey)
	if err != nil {
		slog.Error("update public key", "err", err)
		return
	}
	p, err := endpoint.New(endpoint.Config{URL: updateManifestURL})
	if err == nil {
		err = app.Updater.Init(updater.Config{
			CurrentVersion: u.version, Providers: []updater.Provider{p}, PublicKey: key,
			CheckInterval: 24 * time.Hour, Window: updater.WindowNone,
		})
	}
	if err != nil {
		slog.Error("updater", "err", err)
		return
	}
	// The periodic check emits the release it found.
	app.Event.On(updater.EventUpdateAvailable, func(e *application.CustomEvent) {
		if rel, ok := e.Data.(*updater.Release); ok {
			u.mu.Lock()
			u.release, u.err = rel, ""
			u.mu.Unlock()
		}
	})
	go u.check(app)
}

func (u *updates) check(app *application.App) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rel, err := app.Updater.Check(ctx)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.release, u.err = rel, ""
	if err != nil {
		u.err = err.Error()
		slog.Warn("update check", "err", err)
	}
}

// install downloads, verifies the signature, swaps the bundle and restarts. It runs in the background:
// the UI polls the status.
func (u *updates) install(app *application.App) {
	u.mu.Lock()
	if u.busy || u.release == nil {
		u.mu.Unlock()
		return
	}
	u.busy, u.err = true, ""
	u.mu.Unlock()
	ctx := context.Background()
	err := app.Updater.DownloadAndInstall(ctx)
	if err == nil {
		err = app.Updater.Restart(ctx)
	}
	if err != nil {
		slog.Error("update install", "err", err)
		u.mu.Lock()
		u.busy, u.err = false, err.Error()
		u.mu.Unlock()
	}
}

type updateStatus struct {
	Current   string `json:"current"`
	Enabled   bool   `json:"enabled"`
	State     string `json:"state"`
	Available string `json:"available,omitempty"`
	Notes     string `json:"notes,omitempty"`
	Error     string `json:"error,omitempty"`
}

// serve answers /api/v1/update (GET status), /update/check and /update/install (POST). Served by the
// root middleware, like uninstall: it must work even when the backend failed to start.
func (u *updates) serve(w http.ResponseWriter, r *http.Request) {
	app := application.Get()
	enabled := u.version != ""
	switch {
	case r.URL.Path == "/api/v1/update" && r.Method == http.MethodGet:
	case r.URL.Path == "/api/v1/update/check" && r.Method == http.MethodPost && enabled:
		u.check(app)
	case r.URL.Path == "/api/v1/update/install" && r.Method == http.MethodPost && enabled:
		go u.install(app)
	default:
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	st := updateStatus{Current: u.version, Enabled: enabled, State: "unconfigured"}
	if enabled {
		st.State = string(app.Updater.State())
	}
	u.mu.Lock()
	if u.release != nil {
		st.Available, st.Notes = u.release.Version, u.release.Notes
	}
	st.Error = u.err
	u.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}
