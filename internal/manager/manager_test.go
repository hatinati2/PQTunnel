package manager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

type fakeRunner struct {
	mu sync.Mutex
	state string
	calls [][]string
	restartCount int
	failFirstRestart bool
}

func (f *fakeRunner) Run(_ context.Context, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(args) >= 2 && args[0] == "systemctl" && args[1] == "show" {
		return "LoadState=loaded\nActiveState=" + f.state + "\nSubState=running\nMainPID=1234", nil
	}
	if len(args) != 3 || args[0] != "systemctl" {
		return "", errors.New("unexpected command")
	}
	switch args[1] {
	case "start":
		f.state = "active"
	case "stop":
		f.state = "inactive"
	case "restart":
		f.restartCount++
		if f.failFirstRestart && f.restartCount == 1 {
			f.state = "failed"
			return "simulated restart failure", errors.New("restart failed")
		}
		f.state = "active"
	default:
		return "", errors.New("unexpected systemd action")
	}
	return "", nil
}

func (f *fakeRunner) recorded() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = append([]string(nil), c...)
	}
	return out
}

func newTestController(t *testing.T, role Role, config string, runner *fakeRunner) (*Controller, string) {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "etc", "default", "pqtunnel")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(root, "backups")
	m, err := New(Options{Role: role, ConfigPath: configPath, BackupDir: backupDir, IPCSocket: filepath.Join(root, "run", "control.sock"), Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	return m, configPath
}

func validGatewayConfig() adminapi.TunnelConfiguration {
	return adminapi.TunnelConfiguration{
		ListenAddress: "0.0.0.0:8443,[::]:8443",
		MaxClients: 1,
		PeerPrefixes: "10.66.0.2/32,192.0.2.0/24",
		LocalPrefixes: "10.66.0.1/32,198.51.100.0/24,2001:db8:1::/48",
		PeerIdentity: "iran-1",
		AllowedDstPorts: "tcp:443,udp:53",
	}
}

func validDialerConfig() adminapi.TunnelConfiguration {
	return adminapi.TunnelConfiguration{
		ServerAddress: "vpn.example.test:8443",
		ServerName: "vpn.example.test",
		LocalPrefixes: "10.66.0.2/32,192.0.2.0/24",
		RemotePrefixes: "10.66.0.1/32,198.51.100.0/24,2001:db8:1::/48",
		AllowedDstPorts: "tcp:443,udp:53",
	}
}

func TestRoleSelectsOnlyFixedServiceAndConfig(t *testing.T) {
	gateway, err := New(Options{Role: RoleGateway, ConfigPath: "/tmp/test-gateway", BackupDir: "/tmp/b", IPCSocket: "/tmp/sock", Runner: &fakeRunner{state: "active"}})
	if err != nil { t.Fatal(err) }
	if gateway.unit != "pqtunneld.service" { t.Fatalf("gateway unit=%q", gateway.unit) }

	dialer, err := New(Options{Role: RoleDialer, ConfigPath: "/tmp/test-dialer", BackupDir: "/tmp/b", IPCSocket: "/tmp/sock", Runner: &fakeRunner{state: "active"}})
	if err != nil { t.Fatal(err) }
	if dialer.unit != "pqtunnel-client.service" { t.Fatalf("dialer unit=%q", dialer.unit) }

	if _, err := New(Options{Role: Role("arbitrary"), ConfigPath: "/tmp/a", BackupDir: "/tmp/b", IPCSocket: "/tmp/s", Runner: &fakeRunner{}}); err == nil {
		t.Fatal("unknown role must be rejected")
	}
}

func TestValidateGatewayAndDialerConfiguration(t *testing.T) {
	gateway, _ := New(Options{Role: RoleGateway, ConfigPath: "/tmp/g", BackupDir: "/tmp/b", IPCSocket: "/tmp/s", Runner: &fakeRunner{state: "active"}})
	if _, err := gateway.configurationChanges(validGatewayConfig()); err != nil {
		t.Fatalf("valid gateway config rejected: %v", err)
	}
	badGateway := validGatewayConfig()
	badGateway.MaxClients = 2
	if _, err := gateway.configurationChanges(badGateway); err == nil {
		t.Fatal("site-to-site config with multiple clients must be rejected")
	}
	badGateway = validGatewayConfig()
	badGateway.PeerPrefixes = "10.0.0.0/8"
	badGateway.LocalPrefixes = "10.1.0.0/16"
	if _, err := gateway.configurationChanges(badGateway); err == nil {
		t.Fatal("overlapping peer/local prefixes must be rejected")
	}
	badGateway = validGatewayConfig()
	badGateway.ListenAddress = "0.0.0.0:8443;systemctl restart ssh"
	if _, err := gateway.configurationChanges(badGateway); err == nil {
		t.Fatal("command-shaped listen value must be rejected")
	}

	dialer, _ := New(Options{Role: RoleDialer, ConfigPath: "/tmp/d", BackupDir: "/tmp/b", IPCSocket: "/tmp/s", Runner: &fakeRunner{state: "active"}})
	if _, err := dialer.configurationChanges(validDialerConfig()); err != nil {
		t.Fatalf("valid dialer config rejected: %v", err)
	}
	badDialer := validDialerConfig()
	badDialer.ServerAddress = "localhost:abc"
	if _, err := dialer.configurationChanges(badDialer); err == nil {
		t.Fatal("invalid endpoint must be rejected")
	}
	badDialer = validDialerConfig()
	badDialer.LocalPrefixes = "10.0.0.0/8"
	badDialer.RemotePrefixes = "10.1.0.0/16"
	if _, err := dialer.configurationChanges(badDialer); err == nil {
		t.Fatal("overlapping dialer prefixes must be rejected")
	}
}

func TestUpdateEnvFilePreservesCommentsAndSecretSettings(t *testing.T) {
	original := []byte("# keep this comment\nPQTUNNEL_LISTEN=:8443\nPQTUNNEL_ADMIN_TOKEN=abcdef0123456789abcdef0123456789\nPQTUNNEL_MAX_CLIENTS=128\n")
	entries, err := parseEnvFile(original)
	if err != nil { t.Fatal(err) }
	updated, err := updateEnvFile(original, entries, map[string]string{
		"PQTUNNEL_LISTEN": "0.0.0.0:8443",
		"PQTUNNEL_MAX_CLIENTS": "1",
		"PQTUNNEL_PEER_NAME": "iran-1",
	})
	if err != nil { t.Fatal(err) }
	result := string(updated)
	for _, expected := range []string{
		"# keep this comment", "PQTUNNEL_LISTEN=0.0.0.0:8443",
		"PQTUNNEL_ADMIN_TOKEN=abcdef0123456789abcdef0123456789",
		"PQTUNNEL_MAX_CLIENTS=1", "PQTUNNEL_PEER_NAME=iran-1",
	} {
		if !strings.Contains(result, expected) { t.Fatalf("updated config lacks %q:\n%s", expected, result) }
	}
	if strings.Contains(result, "PQTUNNEL_LISTEN=:8443") { t.Fatal("old target value still present") }
}

func TestApplyConfigurationBacksUpAndRestartsOnlyTheSelectedUnit(t *testing.T) {
	original := "# gateway settings\nPQTUNNEL_LISTEN=:8443\nPQTUNNEL_MAX_CLIENTS=1\nPQTUNNEL_PEER_PREFIXES=10.66.0.2/32,192.0.2.0/24\nPQTUNNEL_LOCAL_PREFIXES=10.66.0.1/32,198.51.100.0/24,2001:db8:1::/48\nPQTUNNEL_PEER_NAME=iran-1\nPQTUNNEL_ALLOWED_DST_PORTS=tcp:443\nPQTUNNEL_ADMIN_TOKEN=abcdef0123456789abcdef0123456789\n"
	runner := &fakeRunner{state: "active"}
	m, path := newTestController(t, RoleGateway, original, runner)
	if err := m.ApplyConfiguration(context.Background(), validGatewayConfig()); err != nil {
		t.Fatalf("ApplyConfiguration: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	for _, want := range []string{"PQTUNNEL_LISTEN=0.0.0.0:8443,[::]:8443", "PQTUNNEL_MAX_CLIENTS=1", "PQTUNNEL_ADMIN_TOKEN=abcdef0123456789abcdef0123456789"} {
		if !strings.Contains(string(got), want) { t.Fatalf("saved config lacks %q:\n%s", want, got) }
	}
	backupFiles, err := filepath.Glob(filepath.Join(filepath.Dir(filepath.Dir(path)), "backups", "*.env"))
	if err != nil { t.Fatal(err) }
	if len(backupFiles) != 1 { t.Fatalf("backup count=%d, want 1", len(backupFiles)) }
	if info, err := os.Stat(backupFiles[0]); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("backup permissions=%v err=%v, want 0600", info, err)
	}
	foundRestart := false
	for _, call := range runner.recorded() {
		if len(call) == 3 && call[0] == "systemctl" && call[1] == "restart" && call[2] == "pqtunneld.service" {
			foundRestart = true
		}
	}
	if !foundRestart { t.Fatal("active gateway service was not restarted") }
}

func TestApplyConfigurationRestoresPreviousFileWhenRestartFails(t *testing.T) {
	original := "PQTUNNEL_LISTEN=:8443\nPQTUNNEL_MAX_CLIENTS=1\nPQTUNNEL_PEER_PREFIXES=10.66.0.2/32,192.0.2.0/24\nPQTUNNEL_LOCAL_PREFIXES=10.66.0.1/32,198.51.100.0/24,2001:db8:1::/48\nPQTUNNEL_PEER_NAME=iran-1\nPQTUNNEL_ALLOWED_DST_PORTS=tcp:443\n"
	runner := &fakeRunner{state: "active", failFirstRestart: true}
	m, path := newTestController(t, RoleGateway, original, runner)
	err := m.ApplyConfiguration(context.Background(), validGatewayConfig())
	if err == nil || !strings.Contains(err.Error(), "previous configuration was restored") {
		t.Fatalf("expected rollback message, got %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil { t.Fatal(readErr) }
	if string(got) != original { t.Fatalf("config not rolled back:\ngot %q\nwant %q", got, original) }
	if runner.restartCount != 2 { t.Fatalf("restart count=%d, want failed apply restart + rollback restart", runner.restartCount) }
}

func TestServiceActionsAreAllowlistedAndUseFixedUnit(t *testing.T) {
	runner := &fakeRunner{state: "inactive"}
	m, err := New(Options{Role: RoleDialer, ConfigPath: "/tmp/dialer", BackupDir: "/tmp/b", IPCSocket: "/tmp/sock", Runner: runner})
	if err != nil { t.Fatal(err) }
	if err := m.ServiceAction(context.Background(), "systemctl restart ssh"); err == nil {
		t.Fatal("arbitrary action string must be rejected")
	}
	if len(runner.recorded()) != 0 { t.Fatal("invalid action unexpectedly reached systemctl") }
	if err := m.ServiceAction(context.Background(), "start"); err != nil { t.Fatalf("start: %v", err) }
	calls := runner.recorded()
	if len(calls) < 2 || strings.Join(calls[0], " ") != "systemctl start pqtunnel-client.service" {
		t.Fatalf("unexpected command calls: %#v", calls)
	}
}

func TestManagerWaitRespectsContextCancellation(t *testing.T) {
	runner := &fakeRunner{state: "activating"}
	m, err := New(Options{Role: RoleGateway, ConfigPath: "/tmp/g", BackupDir: "/tmp/b", IPCSocket: "/tmp/sock", Runner: runner})
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := m.waitForState(ctx, "active"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitForState error=%v, want deadline exceeded", err)
	}
}

func TestReadSecureConfigRejectsSymlinksAndWritableFiles(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("PQTUNNEL_LISTEN=:8443\n"), 0600); err != nil { t.Fatal(err) }
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil { t.Fatal(err) }
	if _, _, err := readSecureConfig(link); err == nil { t.Fatal("symlink config path must be rejected") }
	if err := os.Chmod(real, 0666); err != nil { t.Fatal(err) }
	if _, _, err := readSecureConfig(real); err == nil { t.Fatal("group/world-writable config must be rejected") }
}
