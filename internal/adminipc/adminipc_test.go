package adminipc

import (
	"context"
	"net"
	"sync"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

type testController struct {
	mu sync.Mutex
	snapshot adminapi.Snapshot
	disconnected string
}

func (c *testController) AdminSnapshot() adminapi.Snapshot { return c.snapshot }
func (c *testController) DisconnectPeer(identity string) bool {
	if identity != "" && identity == "peer-1" {
		c.mu.Lock()
		c.disconnected = identity
		c.mu.Unlock()
		return true
	}
	return false
}
func (c *testController) disconnectedIdentity() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disconnected
}

func TestPrivateSocketStatusAndDisconnect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "pqtunnel", "control.sock")
	ln, err := Listen(path)
	if err != nil { t.Fatal(err) }
	info, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("socket permissions=%o, want 0600", info.Mode().Perm()) }

	controller := &testController{snapshot: adminapi.Snapshot{
		Running: true, ListenAddress: "0.0.0.0:8443",
		Peers: []adminapi.Peer{{Identity: "peer-1", ConnectedFor: "3s"}},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); Serve(ctx, ln, controller) }()

	callCtx, callCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer callCancel()
	result, err := Call(callCtx, path, "snapshot", "")
	if err != nil { t.Fatalf("snapshot call: %v", err) }
	if result.Snapshot == nil || !result.Snapshot.Running || len(result.Snapshot.Peers) != 1 {
		t.Fatalf("unexpected snapshot response: %#v", result)
	}
	if _, err := Call(callCtx, path, "disconnect", "peer-1"); err != nil {
		t.Fatalf("disconnect call: %v", err)
	}
	if got := controller.disconnectedIdentity(); got != "peer-1" { t.Fatalf("disconnected identity=%q", got) }
	if _, err := Call(callCtx, path, "disconnect", "systemctl"); err == nil {
		t.Fatal("unknown peer identity must not be accepted")
	}
	cancel()
	_ = ln.Close()
	select {
	case <-done:
	case <-time.After(2*time.Second):
		t.Fatal("IPC server did not stop")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket file remained after shutdown: %v", err)
	}
}

func TestListenRefusesRegularFileAndLiveSocket(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(regular, []byte("preserve"), 0600); err != nil { t.Fatal(err) }
	if _, err := Listen(regular); err == nil { t.Fatal("regular file must not be replaced") }

	path := filepath.Join(dir, "live.sock")
	ln, err := net.Listen("unix", path)
	if err != nil { t.Fatal(err) }
	defer ln.Close()
	if _, err := Listen(path); err == nil { t.Fatal("second server must not unlink a live socket") }
}
