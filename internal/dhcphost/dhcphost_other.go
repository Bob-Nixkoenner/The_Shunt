//go:build !linux

package dhcphost

import (
	"context"
	"log/slog"
)

// Apply: NetworkManager only (Linux).
func Apply(context.Context, Policy, *slog.Logger) {}

// WatchNew: NetworkManager only (Linux).
func WatchNew(ctx context.Context, _ func(), _ func() (Policy, bool), _ *slog.Logger) error {
	<-ctx.Done()
	return nil
}
