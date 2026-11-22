package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wailsapp/wails/v3/pkg/updater"
	"github.com/wailsapp/wails/v3/pkg/updater/providers/endpoint"
)

// The manifest we sign must be read by the real Wails endpoint provider and verify with the public key.
func TestManifestReadByWailsEndpoint(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k")
	pubB64, err := keygen(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keygen(keyPath); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	if st, _ := os.Stat(keyPath); st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v, want 0600", st.Mode().Perm())
	}
	zip := filepath.Join(dir, "limier-macos-arm64.zip")
	payload := []byte("not really a zip")
	if err := os.WriteFile(zip, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	priv, err := readKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest(priv, "0.2.0", zip, "https://example.invalid/limier.zip", "notes", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(m) }))
	defer srv.Close()

	p, err := endpoint.New(endpoint.Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	rel, err := p.Check(context.Background(), updater.CheckRequest{CurrentVersion: "0.1.0", Platform: "darwin", Arch: "arm64"})
	if err != nil || rel == nil {
		t.Fatalf("Check = %v, %v", rel, err)
	}
	sum := sha256.Sum256(payload)
	pub, _ := base64.StdEncoding.DecodeString(pubB64)
	v := rel.Verification
	if rel.Version != "0.2.0" || v == nil || !bytes.Equal(v.Digest, sum[:]) || v.SignatureAlgo != "ed25519" {
		t.Fatalf("release %+v, verification %+v", rel, v)
	}
	if !ed25519.Verify(pub, v.Digest, v.Signature) {
		t.Fatal("signature does not verify with the public key")
	}
	if rel, _ := p.Check(context.Background(), updater.CheckRequest{CurrentVersion: "0.2.0", Platform: "darwin", Arch: "arm64"}); rel != nil {
		t.Fatal("same version reported as an update")
	}
}
