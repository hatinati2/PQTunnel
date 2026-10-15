//go:build !linux

package main

import (
	"context"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

// The local systemd manager/control socket is a Linux server feature. Other
// clients retain normal tunnel behavior without trying to create a Unix socket.
func startClientAdminIPC(_ context.Context, _ adminapi.Controller) (func(), error) {
	return func() {}, nil
}
