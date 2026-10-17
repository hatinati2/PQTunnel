package manager

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
	"github.com/hatinati2/PQTunnel/internal/adminipc"
	"github.com/hatinati2/PQTunnel/internal/portpolicy"
	"github.com/hatinati2/PQTunnel/internal/prefixset"
	"github.com/hatinati2/PQTunnel/internal/speedtest"
)

type Role string

const (
	RoleGateway Role = "gateway"
	RoleDialer  Role = "dialer"
	defaultIPCSocket = "/run/pqtunnel/control.sock"
)

type Runner interface {
	Run(ctx context.Context, args ...string) (string, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, args ...string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("empty command")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

type Options struct {
	Role       Role
	ConfigPath string
	BackupDir  string
	IPCSocket  string
	SpeedTestPeer string
	SpeedTestToken string
	Runner     Runner
}

type Controller struct {
	role       Role
	unit       string
	configPath string
	backupDir  string
	ipcSocket  string
	runner     Runner
	mu              sync.Mutex
	speedRunMu      sync.Mutex
	lastSpeedTestMu sync.Mutex
	speedTestPeer   string
	speedTestToken  string
	defaultRouteApprovalPath string
	lastSpeedTest   *adminapi.SpeedTestResult
	now        func() time.Time
}

var (
	envKeyPattern = regexp.MustCompile(`^PQTUNNEL_[A-Z0-9_]+$`)
	safeValuePattern = regexp.MustCompile(`^[A-Za-z0-9_.,:/=\-\[\]]*$`)
	dnsLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

func New(opts Options) (*Controller, error) {
	if opts.Role != RoleGateway && opts.Role != RoleDialer {
		return nil, errors.New("manager role must be gateway or dialer")
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	if opts.IPCSocket == "" {
		opts.IPCSocket = defaultIPCSocket
	}
	if !filepath.IsAbs(opts.IPCSocket) {
		return nil, errors.New("manager IPC socket path must be absolute")
	}
	unit := "pqtunneld.service"
	defaultConfig := "/etc/default/pqtunneld"
	if opts.Role == RoleDialer {
		unit = "pqtunnel-client.service"
		defaultConfig = "/etc/default/pqtunnel-client"
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = defaultConfig
	}
	if !filepath.IsAbs(opts.ConfigPath) {
		return nil, errors.New("manager config path must be absolute")
	}
	if opts.BackupDir == "" {
		opts.BackupDir = "/var/lib/pqtunnel-manager/backups"
	}
	if !filepath.IsAbs(opts.BackupDir) {
		return nil, errors.New("manager backup directory must be absolute")
	}
	return &Controller{
		role: opts.Role, unit: unit, configPath: opts.ConfigPath, backupDir: opts.BackupDir,
		ipcSocket: opts.IPCSocket, speedTestPeer: strings.TrimSpace(opts.SpeedTestPeer),
		speedTestToken: opts.SpeedTestToken, runner: opts.Runner,
		defaultRouteApprovalPath: defaultRouteApprovalFile, now: time.Now,
	}, nil
}

func (m *Controller) Role() Role { return m.role }

func (m *Controller) managementSnapshot(ctx context.Context) adminapi.ManagerSnapshot {
	view := adminapi.ManagerSnapshot{Role: string(m.role), ServiceUnit: m.unit, ActiveState: "unknown", SubState: "unknown"}
	state, props, err := m.readServiceState(ctx)
	if err != nil {
		view.ConfigError = "service state unavailable: " + err.Error()
	} else {
		view.ActiveState = state
		view.SubState = props["SubState"]
		view.MainPID = props["MainPID"]
	}
	cfg, _, err := m.readConfiguration()
	if err != nil {
		view.ConfigError = strings.TrimSpace(strings.TrimPrefix(view.ConfigError, "service state unavailable:"))
		if view.ConfigError != "" {
			view.ConfigError += "; "
		}
		view.ConfigError += "configuration unavailable: " + err.Error()
	} else {
		view.Config = cfg
		if _, validationErr := m.configurationChanges(cfg); validationErr != nil {
			view.ConfigReady = false
			if view.ConfigError != "" { view.ConfigError += "; " }
			view.ConfigError += "configuration validation: " + validationErr.Error()
		} else {
			view.ConfigReady = true
		}
	}
	if m.role == RoleGateway && view.Config.ListenAddress == "" {
		view.ConfigReady = false
	}
	if m.role == RoleDialer && view.Config.ServerAddress == "" {
		view.ConfigReady = false
	}
	view.CredentialsReady, view.CredentialMessage, view.PeerBundleAvailable = m.credentialStatus(view.Config)
	view.SpeedTestPeer = m.speedTestPeer
	view.SpeedTestReady = m.speedTestReady(view.Config)

	// Peer state is read from the fixed root-owned control socket, never guessed
	// from systemd ActiveState. An active service can still be disconnected.
	ipcCtx, ipcCancel := context.WithTimeout(ctx, 2*time.Second)
	response, ipcErr := adminipc.Call(ipcCtx, m.ipcSocket, "snapshot", "")
	ipcCancel()
	if ipcErr == nil && response.Snapshot != nil {
		view.PeerDataReady = true
		view.TransportConnected = response.Snapshot.TransportConnected
		view.Uptime = response.Snapshot.Uptime
		view.Peers = append([]adminapi.Peer(nil), response.Snapshot.Peers...)
	}
	m.lastSpeedTestMu.Lock()
	if m.lastSpeedTest != nil {
		last := *m.lastSpeedTest
		view.LastSpeedTest = &last
	}
	m.lastSpeedTestMu.Unlock()
	return view
}

func (m *Controller) ManagementSnapshot() adminapi.ManagerSnapshot {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return m.managementSnapshot(ctx)
}

func (m *Controller) AdminSnapshot() adminapi.Snapshot {
	view := m.ManagementSnapshot()
	snapshot := adminapi.Snapshot{
		Running: view.ActiveState == "active",
		TransportConnected: view.TransportConnected,
		Uptime: view.Uptime,
		MaxClients: view.Config.MaxClients,
		SiteToSite: true,
		PeerIdentity: view.Config.PeerIdentity,
		Peers: append([]adminapi.Peer(nil), view.Peers...),
	}
	if m.role == RoleGateway {
		snapshot.ListenAddress = view.Config.ListenAddress
	} else {
		snapshot.ListenAddress = view.Config.ServerAddress
		snapshot.PeerIdentity = view.Config.ServerName
		if snapshot.MaxClients <= 0 {
			snapshot.MaxClients = 1
		}
	}
	if len(snapshot.Peers) > 0 && snapshot.Peers[0].Identity != "" {
		snapshot.PeerIdentity = snapshot.Peers[0].Identity
	}
	return snapshot
}

func (m *Controller) DisconnectPeer(identity string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := adminipc.Call(ctx, m.ipcSocket, "disconnect", identity)
	return err == nil
}

var logSecretPattern = regexp.MustCompile(`(?i)((?:PQTUNNEL_)?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*=)[^[:space:]]+`)

// RecentLogs returns a bounded, redacted tail for this role's fixed systemd unit.
// It does not accept a unit name or journalctl arguments from the HTTP request.
func (m *Controller) RecentLogs(ctx context.Context) (string, error) {
	out, err := m.runner.Run(ctx, "journalctl", "-u", m.unit, "-n", "100", "--no-pager", "-o", "short-iso")
	if err != nil {
		return "", errors.New("could not read recent service logs")
	}
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "PRIVATE KEY") || strings.Contains(upper, "-----BEGIN") {
			lines[i] = "[redacted sensitive log line]"
			continue
		}
		line = logSecretPattern.ReplaceAllString(line, "$1[REDACTED]")
		if len(line) > 1000 {
			line = line[:1000] + " … [truncated]"
		}
		lines[i] = line
	}
	result := strings.Join(lines, "\n")
	if len(result) > 24000 {
		result = result[len(result)-24000:]
		if idx := strings.IndexByte(result, '\n'); idx >= 0 {
			result = result[idx+1:]
		}
	}
	return result, nil
}

func (m *Controller) speedTestReady(cfg adminapi.TunnelConfiguration) bool {
	if m.speedTestToken == "" || len([]byte(m.speedTestToken)) < 32 {
		return false
	}
	ip, port, err := speedtest.ParseEndpointAddress(m.speedTestPeer)
	if err != nil || speedtest.ValidatePrivateEndpoint(m.speedTestPeer) != nil {
		return false
	}
	var targetPrefixes []netip.Prefix
	if m.role == RoleGateway {
		targetPrefixes, err = prefixset.ParseCSV(cfg.PeerPrefixes)
	} else {
		targetPrefixes, err = prefixset.ParseCSV(cfg.RemotePrefixes)
	}
	if err != nil || !prefixset.Contains(targetPrefixes, ip) {
		return false
	}
	rules, err := portpolicy.ParseCSV(cfg.AllowedDstPorts)
	if err != nil || !rules.AllowsPacket(tcpPortProbe(ip, port)) {
		return false
	}
	return true
}

func (m *Controller) ValidateSpeedTestListener(address, token string) error {
	if err := speedtest.ValidatePrivateEndpoint(address); err != nil {
		return err
	}
	if _, err := speedtest.NewHandler(token); err != nil {
		return err
	}
	ip, port, err := speedtest.ParseEndpointAddress(address)
	if err != nil { return err }
	cfg, _, err := m.readConfiguration()
	if err != nil { return fmt.Errorf("read tunnel configuration for speed-test bind: %w", err) }
	local, err := prefixset.ParseCSV(cfg.LocalPrefixes)
	if err != nil || !prefixset.Contains(local, ip) {
		return errors.New("speed-test listen IP must be included in this server's local tunnel prefixes")
	}
	rules, err := portpolicy.ParseCSV(cfg.AllowedDstPorts)
	if err != nil || !rules.AllowsPacket(tcpPortProbe(ip, port)) {
		return errors.New("speed-test TCP port must be included in PQTUNNEL_ALLOWED_DST_PORTS on this server")
	}
	return nil
}

func (m *Controller) RunSpeedTest(ctx context.Context, sizeMiB int) (adminapi.SpeedTestResult, error) {
	if !m.speedRunMu.TryLock() {
		return adminapi.SpeedTestResult{}, errors.New("a speed test is already running")
	}
	defer m.speedRunMu.Unlock()

	cfg, _, err := m.readConfiguration()
	if err != nil {
		return adminapi.SpeedTestResult{}, fmt.Errorf("cannot read tunnel config: %w", err)
	}
	if !m.speedTestReady(cfg) {
		return adminapi.SpeedTestResult{}, errors.New("speed test is not ready: configure a private peer tunnel IP, shared speed-test token, matching route prefix and tcp port allowlist on both servers")
	}
	result, err := speedtest.Run(ctx, m.speedTestPeer, m.speedTestToken, sizeMiB)
	if err != nil {
		return adminapi.SpeedTestResult{}, err
	}
	stored := adminapi.SpeedTestResult{
		Peer: result.Peer, SizeMiB: result.SizeMiB, RTTMillis: result.RTTMillis,
		UploadMbps: result.UploadMbps, DownloadMbps: result.DownloadMbps,
		UploadSeconds: result.UploadSeconds, DownloadSeconds: result.DownloadSeconds,
		CompletedAt: result.CompletedAt.Format(time.RFC3339),
	}
	m.lastSpeedTestMu.Lock()
	m.lastSpeedTest = &stored
	m.lastSpeedTestMu.Unlock()
	return stored, nil
}

func tcpPortProbe(dst netip.Addr, port uint16) []byte {
	if dst.Is4() {
		p := make([]byte, 40)
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		p[8] = 64
		p[9] = 6
		src := netip.MustParseAddr("192.0.2.1").As4()
		target := dst.As4()
		copy(p[12:16], src[:])
		copy(p[16:20], target[:])
		binary.BigEndian.PutUint16(p[20:22], 40000)
		binary.BigEndian.PutUint16(p[22:24], port)
		p[32] = 0x50
		return p
	}
	p := make([]byte, 60)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], 20)
	p[6] = 6
	p[7] = 64
	src := netip.MustParseAddr("fd00::1").As16()
	target := dst.As16()
	copy(p[8:24], src[:])
	copy(p[24:40], target[:])
	binary.BigEndian.PutUint16(p[40:42], 40000)
	binary.BigEndian.PutUint16(p[42:44], port)
	p[52] = 0x50
	return p
}

func (m *Controller) ServiceAction(ctx context.Context, action string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.speedRunMu.TryLock() {
		return errors.New("a speed test is running; service actions are temporarily blocked")
	}
	defer m.speedRunMu.Unlock()
	switch action {
	case "start", "stop", "restart":
	default:
		return errors.New("unsupported service action")
	}

	isProductionEndpoint := m.configPath == "/etc/default/pqtunneld" ||
		m.configPath == "/etc/default/pqtunnel-client"
	if (action == "start" || action == "restart") && isProductionEndpoint {
		cfg, _, err := m.readConfiguration()
		if err != nil {
			return errors.New("tunnel endpoint configuration is not ready")
		}
		if _, validationErr := m.configurationChanges(cfg); validationErr != nil {
			return fmt.Errorf("cannot %s tunnel: invalid endpoint configuration: %w", action, validationErr)
		}
		if requiresDefaultRouteReview(m.role, cfg) && !m.defaultRoutesApproved(cfg) {
			return errors.New("default-route prefixes require explicit approval: review the settings, select the default-route confirmation, and save before starting")
		}
		ready, message, _ := m.credentialStatus(cfg)
		if !ready {
			return fmt.Errorf("cannot %s tunnel: %s", action, message)
		}
	}

	if m.role == RoleGateway && m.configPath == "/etc/default/pqtunneld" {
		switch action {
		case "start":
			return m.startManagedGateway(ctx)
		case "stop":
			return m.stopManagedGateway(ctx)
		case "restart":
			state, _, err := m.readServiceState(ctx)
			if err != nil {
				return errors.New("could not verify Gateway service state")
			}
			if state != "active" {
				return errors.New("Gateway is not active; use Start after resolving any previous network-preflight failure")
			}
		}
	}

	if action == "stop" {
		if _, err := m.runner.Run(ctx, "systemctl", "stop", m.unit); err != nil {
			return fmt.Errorf("systemd stop failed for %s", m.unit)
		}
		if err := m.waitForState(ctx, "inactive"); err != nil {
			return err
		}
		return nil
	}
	if _, err := m.runner.Run(ctx, "systemctl", action, m.unit); err != nil {
		return fmt.Errorf("systemd %s failed for %s", action, m.unit)
	}
	if err := m.waitForState(ctx, "active"); err != nil {
		return err
	}
	return nil
}

func (m *Controller) startManagedGateway(ctx context.Context) error {
	state, _, err := m.readServiceState(ctx)
	if err != nil {
		return errors.New("could not verify Gateway service state")
	}
	if state == "active" {
		return nil
	}
	if state == "activating" {
		return errors.New("Gateway service is already starting")
	}

	// Recover only a marker left by this panel's own guarded start attempt.
	// A pre-existing Gateway network state without the marker is never cleared
	// automatically because it may belong to an older, separately managed setup.
	if pathIsSafeRegularFile("/var/lib/pqtunnel-manager/gateway-tun-owned") {
		if _, err := m.runner.Run(ctx, "systemctl", "start", "pqtunnel-gateway-cleanup.service"); err != nil {
			return errors.New("a previous Gateway start left managed network state; cleanup failed")
		}
	}

	if _, err := m.runner.Run(ctx, "systemctl", "start", "pqtunnel-gateway-prepare.service"); err != nil {
		return errors.New("Gateway network preflight refused to start the endpoint; existing firewall, routes, forwarding, or TUN state must be reviewed")
	}
	if _, err := m.runner.Run(ctx, "systemctl", "start", m.unit); err != nil {
		_, _ = m.runner.Run(context.Background(), "systemctl", "start", "pqtunnel-gateway-cleanup.service")
		return errors.New("Gateway endpoint did not start; its owned startup state was cleaned up where safe")
	}
	if err := m.waitForState(ctx, "active"); err != nil {
		_, _ = m.runner.Run(context.Background(), "systemctl", "stop", m.unit)
		_, _ = m.runner.Run(context.Background(), "systemctl", "start", "pqtunnel-gateway-cleanup.service")
		return err
	}
	if _, err := m.runner.Run(ctx, "systemctl", "start", "pqtunnel-gateway-network.service"); err != nil {
		_, _ = m.runner.Run(context.Background(), "systemctl", "stop", m.unit)
		_ = m.waitForState(context.Background(), "inactive")
		_, _ = m.runner.Run(context.Background(), "systemctl", "start", "pqtunnel-gateway-cleanup.service")
		return errors.New("Gateway network activation failed; the endpoint was stopped and owned startup state was cleaned up where safe")
	}
	return nil
}

func (m *Controller) stopManagedGateway(ctx context.Context) error {
	if _, err := m.runner.Run(ctx, "systemctl", "stop", m.unit); err != nil {
		return errors.New("systemd could not stop the Gateway endpoint")
	}
	if err := m.waitForState(ctx, "inactive"); err != nil {
		return err
	}
	if pathIsSafeRegularFile("/var/lib/pqtunnel/site-selective-gateway.state") ||
		pathIsSafeRegularFile("/var/lib/pqtunnel-manager/gateway-tun-owned") {
		// The network unit has the narrowly scoped CAP_NET_ADMIN rights needed
		// for nftables, routes, forwarding and TUN cleanup; the web manager does not.
		_, _ = m.runner.Run(ctx, "systemctl", "stop", "pqtunnel-gateway-network.service")
		if _, err := m.runner.Run(ctx, "systemctl", "start", "pqtunnel-gateway-cleanup.service"); err != nil {
			return errors.New("Gateway endpoint is stopped, but network cleanup failed; inspect the saved PQTunnel state before retrying")
		}
	}
	return nil
}

func pathIsSafeRegularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0022 == 0
}

func (m *Controller) ApplyConfiguration(ctx context.Context, config adminapi.TunnelConfiguration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.speedRunMu.TryLock() {
		return errors.New("a speed test is running; configuration changes are temporarily blocked")
	}
	defer m.speedRunMu.Unlock()

	changes, err := m.configurationChanges(config)
	if err != nil {
		return err
	}
	if err := m.saveDefaultRouteApproval(config, config.AllowDefaultRoutes); err != nil {
		return err
	}

	original, info, err := readSecureConfig(m.configPath)
	if err != nil {
		return fmt.Errorf("read current configuration: %w", err)
	}
	entries, err := parseEnvFile(original)
	if err != nil {
		return fmt.Errorf("refusing to edit configuration with unsupported syntax: %w", err)
	}
	updated, err := updateEnvFile(original, entries, changes)
	if err != nil {
		return err
	}
	appChanged := !bytes.Equal(original, updated)

	var networkOriginal, networkUpdated []byte
	var networkInfo os.FileInfo
	networkPath := ""
	networkChanged := false
	if m.role == RoleDialer && m.configPath == "/etc/default/pqtunnel-client" {
		candidatePath := "/etc/pqtunnel/site-to-site.env"
		if _, statErr := os.Lstat(candidatePath); statErr == nil {
			networkPath = candidatePath
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("could not safely inspect the Dialer network configuration")
		}
	}
	if networkPath != "" {
		networkOriginal, networkInfo, err = readSecureConfig(networkPath)
		if err != nil {
			return fmt.Errorf("read Dialer network configuration: %w", err)
		}
		networkEntries, parseErr := parseEnvFile(networkOriginal)
		if parseErr != nil || networkEntries["PQTUNNEL_ROLE"] != "dialer" {
			return errors.New("Dialer network configuration is invalid; no settings were changed")
		}
		egressChanges, mapErr := dialerNetworkEgressChanges(config.AllowedDstPorts)
		if mapErr != nil {
			return fmt.Errorf("cannot synchronize Dialer network port policy: %w", mapErr)
		}
		networkUpdated, err = updateEnvFile(networkOriginal, networkEntries, egressChanges)
		if err != nil {
			return fmt.Errorf("prepare synchronized Dialer network config: %w", err)
		}
		networkChanged = !bytes.Equal(networkOriginal, networkUpdated)
	}
	if !appChanged && !networkChanged {
		return nil
	}

	state, _, err := m.readServiceState(ctx)
	if err != nil {
		return fmt.Errorf("cannot verify service state; configuration was not changed: %w", err)
	}
	if appChanged {
		if err := m.writeBackup(original); err != nil {
			return fmt.Errorf("cannot create protected backup; configuration was not changed: %w", err)
		}
	}
	if networkChanged {
		if err := m.writeBackup(networkOriginal); err != nil {
			return fmt.Errorf("cannot create protected backup for Dialer network settings; configuration was not changed: %w", err)
		}
	}

	networkWritten := false
	if networkChanged {
		if err := atomicWrite(networkPath, networkUpdated, networkInfo.Mode().Perm()); err != nil {
			return fmt.Errorf("write synchronized Dialer network settings: %w", err)
		}
		networkWritten = true
	}
	if appChanged {
		if err := atomicWrite(m.configPath, updated, info.Mode().Perm()); err != nil {
			if networkWritten {
				if rollbackErr := atomicWrite(networkPath, networkOriginal, networkInfo.Mode().Perm()); rollbackErr != nil {
					return errors.New("Dialer app config write failed and network config rollback failed; manual recovery is required")
				}
			}
			return fmt.Errorf("write validated configuration: %w", err)
		}
	}
	if state != "active" {
		return nil
	}

	restartErr := m.restartAndWait(ctx)
	if restartErr == nil {
		return nil
	}
	var appRollbackErr error
	if appChanged {
		appRollbackErr = atomicWrite(m.configPath, original, info.Mode().Perm())
	}
	var networkRollbackErr error
	if networkChanged {
		networkRollbackErr = atomicWrite(networkPath, networkOriginal, networkInfo.Mode().Perm())
	}
	if appRollbackErr != nil || networkRollbackErr != nil {
		return errors.New("new configuration failed to start and automatic rollback failed; manual recovery required")
	}
	// A request deadline/cancellation must not prevent recovery of the known-good
	// config. Use a fresh bounded context for the rollback restart.
	rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer rollbackCancel()
	if _, err := m.runner.Run(rollbackCtx, "systemctl", "restart", m.unit); err != nil {
		return errors.New("new configuration failed; previous files were restored but service rollback restart failed")
	}
	if err := m.waitForState(rollbackCtx, "active"); err != nil {
		return errors.New("new configuration failed; previous files were restored but previous service state could not be confirmed")
	}
	return errors.New("new configuration failed to start; previous configuration was restored and restarted")
}
func (m *Controller) configurationChanges(cfg adminapi.TunnelConfiguration) (map[string]string, error) {
	changes := make(map[string]string)
	if m.role == RoleGateway {
		if err := validateListenList(cfg.ListenAddress); err != nil {
			return nil, fmt.Errorf("listen address: %w", err)
		}
		if cfg.MaxClients != 1 {
			return nil, errors.New("server-to-server mode requires max clients to equal 1")
		}
		peer, err := parseCanonicalPrefixes(cfg.PeerPrefixes)
		if err != nil {
			return nil, fmt.Errorf("peer prefixes: %w", err)
		}
		local, err := parseCanonicalPrefixesWithDefault(cfg.LocalPrefixes, true)
		if err != nil {
			return nil, fmt.Errorf("local prefixes: %w", err)
		}
		for _, peerPrefix := range peer {
			for _, localPrefix := range local {
				if localPrefix.Bits() != 0 && peerPrefix.Overlaps(localPrefix) {
					return nil, errors.New("peer and local CIDR prefix sets must not overlap, except explicit local default routes")
				}
			}
		}
		if !validIdentity(cfg.PeerIdentity) {
			return nil, errors.New("peer identity must contain 1-128 letters, digits, dot, underscore or hyphen")
		}
		if err := validatePorts(cfg.AllowedDstPorts); err != nil {
			return nil, err
		}
		changes["PQTUNNEL_LISTEN"] = cfg.ListenAddress
		changes["PQTUNNEL_MAX_CLIENTS"] = "1"
		changes["PQTUNNEL_PEER_PREFIXES"] = cfg.PeerPrefixes
		changes["PQTUNNEL_LOCAL_PREFIXES"] = cfg.LocalPrefixes
		changes["PQTUNNEL_PEER_NAME"] = cfg.PeerIdentity
		changes["PQTUNNEL_ALLOWED_DST_PORTS"] = cfg.AllowedDstPorts
		return changes, nil
	}

	if err := validateEndpoint(cfg.ServerAddress); err != nil {
		return nil, fmt.Errorf("server endpoint: %w", err)
	}
	if !validServerName(cfg.ServerName) {
		return nil, errors.New("TLS server name must be a valid DNS name or IP address")
	}
	local, err := parseCanonicalPrefixes(cfg.LocalPrefixes)
	if err != nil {
		return nil, fmt.Errorf("local prefixes: %w", err)
	}
	remote, err := parseCanonicalPrefixesWithDefault(cfg.RemotePrefixes, true)
	if err != nil {
		return nil, fmt.Errorf("remote prefixes: %w", err)
	}
	for _, p := range local {
		for _, q := range remote {
			if q.Bits() == 0 {
				continue // default routes require a separate route/recovery review
			}
			if p.Overlaps(q) {
				return nil, errors.New("local and remote CIDR prefix sets must not overlap, except explicit remote default routes")
			}
		}
	}
	if err := validatePorts(cfg.AllowedDstPorts); err != nil {
		return nil, err
	}
	changes["PQTUNNEL_SERVER"] = cfg.ServerAddress
	changes["PQTUNNEL_SERVER_NAME"] = cfg.ServerName
	changes["PQTUNNEL_LOCAL_PREFIXES"] = cfg.LocalPrefixes
	changes["PQTUNNEL_REMOTE_PREFIXES"] = cfg.RemotePrefixes
	changes["PQTUNNEL_ALLOWED_DST_PORTS"] = cfg.AllowedDstPorts
	return changes, nil
}

func (m *Controller) readConfiguration() (adminapi.TunnelConfiguration, []byte, error) {
	data, _, err := readSecureConfig(m.configPath)
	if err != nil {
		return adminapi.TunnelConfiguration{}, nil, err
	}
	entries, err := parseEnvFile(data)
	if err != nil {
		return adminapi.TunnelConfiguration{}, nil, err
	}
	cfg := adminapi.TunnelConfiguration{}
	if m.role == RoleGateway {
		cfg.ListenAddress = entries["PQTUNNEL_LISTEN"]
		cfg.MaxClients, _ = strconv.Atoi(entries["PQTUNNEL_MAX_CLIENTS"])
		cfg.PeerPrefixes = entries["PQTUNNEL_PEER_PREFIXES"]
		cfg.LocalPrefixes = entries["PQTUNNEL_LOCAL_PREFIXES"]
		cfg.PeerIdentity = entries["PQTUNNEL_PEER_NAME"]
		cfg.AllowedDstPorts = entries["PQTUNNEL_ALLOWED_DST_PORTS"]
	} else {
		cfg.ServerAddress = entries["PQTUNNEL_SERVER"]
		cfg.ServerName = entries["PQTUNNEL_SERVER_NAME"]
		cfg.LocalPrefixes = entries["PQTUNNEL_LOCAL_PREFIXES"]
		cfg.RemotePrefixes = entries["PQTUNNEL_REMOTE_PREFIXES"]
		cfg.AllowedDstPorts = entries["PQTUNNEL_ALLOWED_DST_PORTS"]
	}
	return cfg, data, nil
}

func readSecureConfig(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("configuration path must be a regular file, not a symlink or special file")
	}
	if info.Mode().Perm()&0022 != 0 {
		return nil, nil, errors.New("configuration file must not be group/world-writable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if len(data) > 1<<20 {
		return nil, nil, errors.New("configuration file exceeds 1 MiB")
	}
	return data, info, nil
}

func parseEnvFile(data []byte) (map[string]string, error) {
	entries := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !envKeyPattern.MatchString(key) {
			return nil, errors.New("only plain PQTUNNEL_KEY=VALUE entries and comments are supported")
		}
		if _, exists := entries[key]; exists {
			return nil, fmt.Errorf("duplicate configuration key %s", key)
		}
		if !safeValuePattern.MatchString(value) {
			return nil, fmt.Errorf("unsupported characters in configuration value for %s", key)
		}
		entries[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func updateEnvFile(original []byte, entries, changes map[string]string) ([]byte, error) {
	var out strings.Builder
	seen := make(map[string]bool, len(changes))
	scanner := bufio.NewScanner(bytes.NewReader(original))
	scanner.Buffer(make([]byte, 1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		key := ""
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			key, _, _ = strings.Cut(trimmed, "=")
		}
		if value, ok := changes[key]; ok {
			if !safeValuePattern.MatchString(value) {
				return nil, fmt.Errorf("unsupported characters for %s", key)
			}
			if !seen[key] {
				out.WriteString(key)
				out.WriteByte('=')
				out.WriteString(value)
				seen[key] = true
			}
		} else {
			out.WriteString(line)
		}
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for key, value := range changes {
		if seen[key] {
			continue
		}
		if !envKeyPattern.MatchString(key) || !safeValuePattern.MatchString(value) {
			return nil, errors.New("invalid configuration update")
		}
		out.WriteString(key)
		out.WriteByte('=')
		out.WriteString(value)
		out.WriteByte('\n')
	}
	return []byte(out.String()), nil
}

func (m *Controller) writeBackup(data []byte) error {
	if err := os.MkdirAll(m.backupDir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(m.backupDir, 0700); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s.env", string(m.role), m.now().UTC().Format("20060102T150405.000000000Z"))
	path := filepath.Join(m.backupDir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".pqtunnel-manager-*")
	if err != nil {
		// The manager systemd sandbox can grant write access to the one
		// EnvironmentFile without making its parent directory writable. In
		// that case temp-file + rename is forbidden by the sandbox. Fall back
		// only for read-only/permission errors, preserving/restoring the prior
		// bytes on any in-place write failure.
		if errors.Is(err, syscall.EROFS) || errors.Is(err, os.ErrPermission) {
			return writeExistingFileWithRollback(path, data, mode)
		}
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode.Perm()); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// writeExistingFileWithRollback is used only when a sandbox permits writing
// the existing file but forbids creating a sibling temporary file. The original
// contents are kept in memory and restored if truncate/write/fsync fails. Apply
// Configuration writes a separate 0600 backup before reaching this function.
func writeExistingFileWithRollback(path string, data []byte, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("refusing in-place update of non-regular or group/world-writable config")
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	write := func(payload []byte) error {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, mode.Perm())
		if err != nil {
			return err
		}
		n, writeErr := f.Write(payload)
		if writeErr == nil && n != len(payload) {
			writeErr = io.ErrShortWrite
		}
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}
	if err := write(data); err != nil {
		if restoreErr := write(old); restoreErr != nil {
			return fmt.Errorf("in-place configuration write failed and in-memory rollback failed; protected backup retained: %w", err)
		}
		return fmt.Errorf("in-place configuration write failed; previous bytes restored from memory: %w", err)
	}
	return nil
}

func (m *Controller) readServiceState(ctx context.Context) (string, map[string]string, error) {
	out, err := m.runner.Run(ctx, "systemctl", "show", "--no-page", m.unit,
		"--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=MainPID")
	if err != nil {
		return "", nil, fmt.Errorf("systemctl status query failed")
	}
	props := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			props[key] = value
		}
	}
	if props["LoadState"] == "not-found" || props["LoadState"] == "" {
		return "", props, errors.New("configured tunnel service is not installed")
	}
	state := props["ActiveState"]
	if state == "" {
		return "", props, errors.New("systemd returned no ActiveState")
	}
	return state, props, nil
}

func (m *Controller) waitForState(ctx context.Context, want string) error {
	deadline := time.NewTimer(25 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	var last string
	for {
		state, _, err := m.readServiceState(ctx)
		if err == nil {
			last = state
			if want == "inactive" && (state == "inactive" || state == "failed") {
				return nil
			}
			if want == "active" && state == "active" {
				return nil
			}
			if want == "active" && state == "failed" {
				return errors.New("tunnel service entered failed state")
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for service state %s (last state %s)", want, last)
		case <-tick.C:
		}
	}
}

func (m *Controller) restartAndWait(ctx context.Context) error {
	if _, err := m.runner.Run(ctx, "systemctl", "restart", m.unit); err != nil {
		return errors.New("systemd restart failed")
	}
	return m.waitForState(ctx, "active")
}

func validateListenList(value string) error {
	if value == "" || len(value) > 512 {
		return errors.New("set one or more literal IP listen addresses with a port")
	}
	parts := strings.Split(value, ",")
	if len(parts) > 8 {
		return errors.New("at most 8 listen addresses are allowed")
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return errors.New("empty address in listen list")
		}
		host, portText, err := net.SplitHostPort(part)
		if err != nil {
			return errors.New("expected IP:port or [IPv6]:port")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return errors.New("port must be between 1 and 65535")
		}
		if host != "" {
			if _, err := netip.ParseAddr(host); err != nil {
				return errors.New("listen host must be a literal IP address or empty wildcard")
			}
		}
	}
	return nil
}

func validateEndpoint(value string) error {
	if value == "" || len(value) > 512 {
		return errors.New("set a DNS/IPv4/[IPv6] endpoint and port")
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return errors.New("expected hostname:port, IPv4:port or [IPv6]:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if strings.ContainsAny(host, " /\\\t\r\n") {
		return errors.New("endpoint host contains invalid characters")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("endpoint IP cannot be unspecified or multicast")
		}
		return nil
	}
	if !validDNSName(host) {
		return errors.New("endpoint host must be a DNS name or literal IP address")
	}
	return nil
}

func validServerName(value string) bool {
	if ip, err := netip.ParseAddr(value); err == nil {
		return !ip.IsUnspecified() && !ip.IsMulticast()
	}
	return validDNSName(value)
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func parseCanonicalPrefixes(value string) ([]netip.Prefix, error) {
	return parseCanonicalPrefixesWithDefault(value, false)
}

func parseCanonicalPrefixesWithDefault(value string, allowDefault bool) ([]netip.Prefix, error) {
	if value == "" || len(value) > 2048 {
		return nil, errors.New("at least one CIDR prefix is required")
	}
	parts := strings.Split(value, ",")
	if len(parts) > 128 {
		return nil, errors.New("at most 128 CIDR prefixes are allowed")
	}
	prefixes := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]bool, len(parts))
	for _, raw := range parts {
		raw = strings.TrimSpace(raw)
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR prefix %q: %w", raw, err)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("prefix %q must be a canonical network CIDR", raw)
		}
		if p.Bits() == 0 && !allowDefault {
			return nil, errors.New("default routes are not accepted in this prefix field")
		}
		if seen[p] {
			return nil, fmt.Errorf("duplicate CIDR prefix %q", p)
		}
		seen[p] = true
		prefixes = append(prefixes, p)
	}
	for i := range prefixes {
		for j := i + 1; j < len(prefixes); j++ {
			if prefixes[i].Overlaps(prefixes[j]) {
				return nil, errors.New("CIDR prefixes within one list must not overlap")
			}
		}
	}
	return prefixes, nil
}

func validatePorts(value string) error {
	if value == "" || len(value) > 1024 {
		return errors.New("destination port allowlist must be configured")
	}
	if _, err := portpolicy.ParseCSV(value); err != nil {
		return fmt.Errorf("destination port allowlist: %w", err)
	}
	return nil
}

func validIdentity(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// ConfigPathForRole returns only the fixed app environment path used by this role.
// It never accepts a path from the HTTP request.
func ConfigPathForRole(role Role) string {
	if role == RoleGateway {
		return "/etc/default/pqtunneld"
	}
	if role == RoleDialer {
		return "/etc/default/pqtunnel-client"
	}
	return ""
}
