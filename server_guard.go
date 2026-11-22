//go:build server

package main

// The /api middleware signs every request in as the local admin, which is only safe when the
// webview is the sole client. Wails server mode exposes it over HTTP: refuse to run.
func init() {
	panic("limier cannot run in Wails server mode: its API trusts every request as the local admin")
}
