package main

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

// notifier wraps the Wails notifications service so that a failed start (no bundle identifier
// under `wails3 dev`, no notification daemon on Linux) disables notifications instead of
// stopping the app.
type notifier struct {
	ns     *notifications.NotificationService
	ok     atomic.Bool
	window atomic.Pointer[application.WebviewWindow]
}

func newNotifier() *notifier { return &notifier{ns: notifications.New()} }

func (n *notifier) ServiceStartup(ctx context.Context, opts application.ServiceOptions) error {
	if err := n.ns.ServiceStartup(ctx, opts); err != nil {
		slog.Warn("desktop notifications disabled", "err", err)
		return nil
	}
	n.ok.Store(true)
	// A click on the notification shows the new findings.
	n.ns.OnNotificationResponse(func(r notifications.NotificationResult) {
		w := n.window.Load()
		if r.Error != nil || w == nil {
			return
		}
		w.Show()
		w.Focus()
		w.ExecJS(`location.hash = '#/findings?new=true'`)
	})
	return nil
}

func (n *notifier) ServiceShutdown() error {
	if !n.ok.Load() {
		return nil
	}
	return n.ns.ServiceShutdown()
}

// send shows one notification. The first call asks the user for permission (macOS).
func (n *notifier) send(title, body string) error {
	if !n.ok.Load() {
		return nil
	}
	allowed, err := n.ns.RequestNotificationAuthorization()
	if err != nil {
		return err
	}
	if !allowed {
		return errors.New("notifications not allowed by the user")
	}
	return n.ns.SendNotification(notifications.NotificationOptions{ID: "limier-new-vulns", Title: title, Body: body})
}
