package adminipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

const maxMessageBytes = 8192

type request struct {
	Action   string `json:"action"`
	Identity string `json:"identity,omitempty"`
}

type Response struct {
	OK       bool                `json:"ok"`
	Error    string              `json:"error,omitempty"`
	Snapshot *adminapi.Snapshot  `json:"snapshot,omitempty"`
}

func Listen(path string) (net.Listener, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("admin IPC socket path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("create admin IPC directory: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace non-socket admin IPC path")
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale admin IPC socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect admin IPC path: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on admin IPC socket: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("restrict admin IPC socket permissions: %w", err)
	}
	return ln, nil
}

func Serve(ctx context.Context, ln net.Listener, controller adminapi.Controller) {
	if ln == nil || controller == nil {
		return
	}
	stopClose := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stopClose()
	defer func() {
		_ = ln.Close()
		if unixAddr, ok := ln.Addr().(*net.UnixAddr); ok {
			_ = os.Remove(unixAddr.Name)
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go serveConn(ctx, conn, controller)
	}
}

func serveConn(ctx context.Context, conn net.Conn, controller adminapi.Controller) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var req request
	dec := json.NewDecoder(io.LimitReader(conn, maxMessageBytes))
	if err := dec.Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: "invalid request"})
		return
	}
	if ctx.Err() != nil {
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: "service stopping"})
		return
	}
	switch req.Action {
	case "snapshot":
		snapshot := controller.AdminSnapshot()
		_ = json.NewEncoder(conn).Encode(Response{OK: true, Snapshot: &snapshot})
	case "disconnect":
		if len(req.Identity) == 0 || len(req.Identity) > 128 {
			_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: "invalid peer identity"})
			return
		}
		if !controller.DisconnectPeer(req.Identity) {
			_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: "peer not found"})
			return
		}
		_ = json.NewEncoder(conn).Encode(Response{OK: true})
	default:
		_ = json.NewEncoder(conn).Encode(Response{OK: false, Error: "unsupported action"})
	}
}

func Call(ctx context.Context, path, action, identity string) (Response, error) {
	if path == "" || !filepath.IsAbs(path) {
		return Response{}, errors.New("admin IPC socket path must be absolute")
	}
	if action != "snapshot" && action != "disconnect" {
		return Response{}, errors.New("unsupported admin IPC action")
	}
	if action == "disconnect" && (identity == "" || len(identity) > 128) {
		return Response{}, errors.New("invalid peer identity")
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return Response{}, fmt.Errorf("connect to local tunnel control socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(request{Action: action, Identity: identity}); err != nil {
		return Response{}, fmt.Errorf("send local tunnel control request: %w", err)
	}
	var result Response
	if err := json.NewDecoder(io.LimitReader(conn, maxMessageBytes)).Decode(&result); err != nil {
		return Response{}, fmt.Errorf("read local tunnel control response: %w", err)
	}
	if !result.OK {
		if result.Error == "" {
			result.Error = "local tunnel control request failed"
		}
		return result, errors.New(result.Error)
	}
	return result, nil
}
