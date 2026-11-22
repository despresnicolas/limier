// Command updatesign makes the signing key and the signed update.json of a Limier release.
//
//	go run ./build/updatesign keygen                      # once; prints the public key for update.go
//	go run ./build/updatesign manifest -version 0.2.0 -zip bin/limier-macos-arm64.zip -url <zip URL> -out bin/update.json
//
// The manifest follows the Wails update manifest (schemaVersion 1): the signature is raw ed25519 over the
// zip's SHA-256, which is what updater.Config.PublicKey checks.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func defaultKeyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "limier", "update-signing.key")
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: updatesign keygen | manifest -version V -zip FILE -url URL -out FILE [-notes TEXT] [-key FILE]"))
	}
	switch os.Args[1] {
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		key := fs.String("key", defaultKeyPath(), "private key file to create")
		_ = fs.Parse(os.Args[2:])
		pub, err := keygen(*key)
		fail(err)
		fmt.Printf("private key: %s (back it up: without it, no more updates)\npublic key (update.go updatePublicKey): %s\n", *key, pub)
	case "manifest":
		fs := flag.NewFlagSet("manifest", flag.ExitOnError)
		version := fs.String("version", "", "release version, without v")
		zip := fs.String("zip", "", "zip of limier.app")
		url := fs.String("url", "", "public download URL of the zip")
		out := fs.String("out", "update.json", "manifest to write")
		notes := fs.String("notes", "", "release notes shown to the user")
		key := fs.String("key", defaultKeyPath(), "private key file")
		_ = fs.Parse(os.Args[2:])
		if *version == "" || *zip == "" || *url == "" {
			fail(errors.New("manifest needs -version, -zip and -url"))
		}
		priv, err := readKey(*key)
		fail(err)
		m, err := manifest(priv, *version, *zip, *url, *notes, time.Now())
		fail(err)
		fail(os.WriteFile(*out, m, 0o644))
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}

// keygen writes a new private key (0600, refusing to overwrite one) and returns the public key in base64.
func keygen(path string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("%w (a key already exists: keep it, installed apps trust only it)", err)
	}
	defer f.Close()
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not an updatesign key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func manifest(priv ed25519.PrivateKey, version, zip, url, notes string, now time.Time) ([]byte, error) {
	f, err := os.Open(zip)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return nil, err
	}
	digest := h.Sum(nil)
	return json.MarshalIndent(map[string]any{
		"schemaVersion": 1,
		"version":       version,
		"name":          "Limier " + version,
		"notes":         notes,
		"publishedAt":   now.UTC().Format(time.RFC3339),
		"artifacts": []map[string]any{{
			"url": url, "filename": filepath.Base(zip), "filetype": "zip", "size": size,
			"platform": "darwin", "arch": "arm64",
			"digestAlgo": "sha256", "digest": base64.StdEncoding.EncodeToString(digest),
			"signatureAlgo": "ed25519", "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest)),
		}},
	}, "", "  ")
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "updatesign:", err)
		os.Exit(1)
	}
}
