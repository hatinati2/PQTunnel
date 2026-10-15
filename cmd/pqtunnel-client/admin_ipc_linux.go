//go:build linux

package main

import (
	"context"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
	"github.com/hatinati2/PQTunnel/internal/adminipc"
)

const clientControlSocket = "/run/pqtunnel/client-control.sock"

func startClientAdminIPC(ctx context.Context, controller adminapi.Controller) (func(), error) {
	listener, err := adminipc.Listen(clientControlSocket)
	if err != nil {
		return nil, err
	}
	go adminipc.Serve(ctx, listener, controller)
	return func() { _ = listener.Close() }, nil
}

