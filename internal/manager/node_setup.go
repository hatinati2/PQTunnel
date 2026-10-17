package manager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

const (
	nodeSetupUnit = "pqtunnel-node-setup.service"
	nodeSetupWorkerPath = "/usr/local/lib/pqtunnel/pqtunnel-node-setup-worker.py"
	nodeSetupServicePath = "/etc/systemd/system/pqtunnel-node-setup.service"
	nodeSetupEnvPath = "/var/lib/pqtunnel-manager/node-setup.env"
	nodeSetupStatePath = "/var/lib/pqtunnel-manager/node-setup-state"
	nodeSetupLogPath = "/var/lib/pqtunnel-manager/node-setup.log"
	nodeSetupRawLogPath = "/var/lib/pqtunnel-manager/node-setup-raw.log"
	nodeSetupBundlePath = "/var/lib/pqtunnel-manager/node-setup-bundle.tar.gz"
	nodeSetupUploadPath = "/var/lib/pqtunnel-manager/node-setup-upload.tar.gz"
)

const maxNodeBundleBytes = 1 << 20

func ValidateNodeSetupRequest(role string, req adminapi.NodeSetupRequest) error {
	switch req.Operation {
	case "gateway-init":
		if role != string(RoleGateway) {
			return errors.New("gateway profile generation is available only on a Gateway panel")
		}
		if !validSetupHost(req.PublicName) {
			return errors.New("public endpoint must be a valid IPv4 address or DNS name")
		}
		if req.ListenPort < 1 || req.ListenPort > 65535 {
			return errors.New("listener port must be between 1 and 65535")
		}
		tcp, err := validateSetupPorts(req.TCPPorts, true)
		if err != nil {
			return errors.New("TCP ports must be comma-separated port numbers or none")
		}
		udp, err := validateSetupPorts(req.UDPPorts, true)
		if err != nil {
			return errors.New("UDP ports must be comma-separated port numbers or none")
		}
		if tcp == "" && udp == "" {
			return errors.New("select at least one TCP or UDP destination port")
		}
	case "dialer-import-gateway":
		if role != string(RoleDialer) {
			return errors.New("Gateway profile import is available only on a Dialer panel")
		}
	case "gateway-import-dialer":
		if role != string(RoleGateway) {
			return errors.New("Dialer profile import is available only on a Gateway panel")
		}
	default:
		return errors.New("unsupported local endpoint setup operation")
	}
	return nil
}

// StartNodeSetup invokes a fixed root-owned worker. All browser-supplied values
// are validated here and encoded as JSON; they are never treated as shell code.
func (m *Controller) StartNodeSetup(ctx context.Context, req adminapi.NodeSetupRequest) error {
	if err := ValidateNodeSetupRequest(string(m.role), req); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.speedRunMu.TryLock() {
		return errors.New("another management operation is in progress")
	}
	defer m.speedRunMu.Unlock()

	for _, path := range []string{nodeSetupWorkerPath, nodeSetupServicePath} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("the per-node setup worker is not installed; install or upgrade the PQTunnel node package first")
		}
	}
	if req.Operation == "dialer-import-gateway" || req.Operation == "gateway-import-dialer" {
		info, err := os.Lstat(nodeSetupUploadPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("upload the matching public peer profile bundle before importing it")
		}
	}
	active, err := m.runner.Run(ctx, "systemctl", "show", "--property=ActiveState", "--value", nodeSetupUnit)
	if err != nil {
		return errors.New("could not inspect the local endpoint setup worker")
	}
	if stateData, stateErr := os.ReadFile(nodeSetupStatePath); stateErr == nil {
		switch strings.TrimSpace(string(stateData)) {
		case "queued", "running":
			return errors.New("a local endpoint setup operation is already queued or running")
		}
	}
	if state := strings.TrimSpace(active); state == "active" || state == "activating" {
		return errors.New("a local endpoint setup operation is already running")
	}

	data, err := json.Marshal(req)
	if err != nil {
		return errors.New("could not encode the endpoint setup request")
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	if err := atomicWrite(nodeSetupEnvPath, []byte("PQTUNNEL_NODE_SETUP_INPUT_B64="+encoded+"\n"), 0600); err != nil {
		return errors.New("could not securely stage the endpoint setup request")
	}
	for _, path := range []string{nodeSetupLogPath, nodeSetupRawLogPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(nodeSetupEnvPath)
			return errors.New("could not clear previous endpoint setup state")
		}
	}
	if err := atomicWrite(nodeSetupStatePath, []byte("queued\n"), 0600); err != nil {
		_ = os.Remove(nodeSetupEnvPath)
		return errors.New("could not record local endpoint setup state")
	}
	_, _ = m.runner.Run(ctx, "systemctl", "reset-failed", nodeSetupUnit)
	if _, err := m.runner.Run(ctx, "systemctl", "start", "--no-block", nodeSetupUnit); err != nil {
		_ = atomicWrite(nodeSetupStatePath, []byte("failed\n"), 0600)
		return errors.New("systemd could not start the local endpoint setup worker")
	}
	return nil
}

// UploadNodeSetupBundle accepts only a small gzip bundle. Its member names and
// content are validated by the root worker before anything is installed.
func (m *Controller) UploadNodeSetupBundle(ctx context.Context, data []byte) error {
	_ = ctx
	if len(data) < 2 || len(data) > maxNodeBundleBytes || data[0] != 0x1f || data[1] != 0x8b {
		return errors.New("profile bundle must be a gzip archive smaller than 1 MiB")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.speedRunMu.TryLock() {
		return errors.New("another management operation is in progress")
	}
	defer m.speedRunMu.Unlock()
	if err := atomicWrite(nodeSetupUploadPath, data, 0600); err != nil {
		return errors.New("could not securely stage the public profile bundle")
	}
	return nil
}

func (m *Controller) NodeSetupStatus(ctx context.Context) (adminapi.NodeSetupStatus, error) {
	_ = ctx
	out := adminapi.NodeSetupStatus{Role: string(m.role), State: "idle"}
	for _, path := range []string{nodeSetupWorkerPath, nodeSetupServicePath, "/usr/local/bin/pqtunnel-pki"} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return out, nil
		}
	}
	if m.role == RoleGateway {
		for _, path := range []string{"/usr/local/sbin/pqtunneld", "/etc/systemd/system/pqtunneld-transport.service"} {
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() {
				return out, nil
			}
		}
	} else {
		for _, path := range []string{"/usr/local/bin/pqtunnel-client", "/usr/local/lib/pqtunnel/run-client.sh", "/etc/systemd/system/pqtunnel-client-transport.service"} {
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() {
				return out, nil
			}
		}
	}
	out.Available = true
	if data, err := os.ReadFile(nodeSetupStatePath); err == nil {
		state := strings.TrimSpace(string(data))
		switch state {
		case "queued", "running", "waiting-for-peer", "ready", "failed":
			out.State = state
		}
	}
	if data, err := os.ReadFile(nodeSetupLogPath); err == nil {
		if len(data) > 18000 {
			data = data[len(data)-18000:]
		}
		out.Output = redactSetupOutput(string(data))
	}
	if info, err := os.Lstat(nodeSetupBundlePath); err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && info.Size() > 0 && info.Size() <= maxNodeBundleBytes {
		out.BundleAvailable = true
	}
	return out, nil
}

func (m *Controller) ReadNodeSetupBundle(ctx context.Context) ([]byte, error) {
	_ = ctx
	info, err := os.Lstat(nodeSetupBundlePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > maxNodeBundleBytes {
		return nil, errors.New("no public profile bundle is available; generate or import the matching endpoint profile first")
	}
	data, err := os.ReadFile(filepath.Clean(nodeSetupBundlePath))
	if err != nil || len(data) < 2 || len(data) > maxNodeBundleBytes || data[0] != 0x1f || data[1] != 0x8b {
		return nil, errors.New("the saved endpoint profile bundle is invalid")
	}
	return data, nil
}

var _ adminapi.NodeSetupController = (*Controller)(nil)
