package main

import (
	"context"
	"embed"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	n := newNotifier()
	b := &backend{notify: n.send}
	b.setState("starting")
	go b.start(ctx)

	app := application.New(application.Options{
		Name:        "Limier",
		Description: "limier",
		Services:    []application.Service{application.NewService(n)},
		Assets: application.AssetOptions{
			Handler:    application.AssetFileServerFS(assets),
			Middleware: b.middleware,
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
		OnShutdown: func() {
			cancel()
			b.shutdown()
		},
	})

	// Wails handles signals only in server mode: without this, Ctrl+C or a kill skips the clean shutdown (workers, database).
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sig
		app.Quit()
	}()

	w := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  "Limier",
		Width:  1200,
		Height: 800,
		Mac: application.MacWindow{
			TitleBar: application.MacTitleBarHiddenInset,
		},
		URL: "/",
	})
	n.window.Store(w)
	b.updates.init(app)

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
