package manager

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
	"github.com/hatinati2/PQTunnel/internal/adminipc"
	"github.com/hatinati2/PQTunnel/internal/portpolicy"
	"github.com/hatinati2/PQTunnel/internal/prefixset"
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
	Runner     Runner
}

type Controller struct {
	role       Role
	unit       string
	configPath string
	backupDir  string
	ipcSocket  string
	runner     Runner
	mu         sync.Mutex
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
		ipcSocket: opts.IPCSocket, runner: opts.Runner, now: time.Now,
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
		view.ConfigReady = true
	}
	if m.role == RoleGateway && view.Config.ListenAddress == "" {
		view.ConfigReady = false
	}
	if m.role == RoleDialer && view.Config.ServerAddress == "" {
		view.ConfigReady = false
	}
	if m.role == RoleGateway {
		view.SpeedTestPeer = "" // populated by the optional speed-test feature when configured
	}
	if m.role == RoleDialer {
		view.SpeedTestPeer = ""
	}
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
		MaxClients: view.Config.MaxClients,
		SiteToSite: true,
		PeerIdentity: view.Config.PeerIdentity,
	}
	if m.role == RoleGateway {
		snapshot.ListenAddress = view.Config.ListenAddress
	} else {
		snapshot.ListenAddress = view.Config.ServerAddress
		if snapshot.MaxClients <= 0 {
			snapshot.MaxClients = 1
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := adminipc.Call(ctx, m.ipcSocket, "snapshot", "")
	if err == nil && response.Snapshot != nil {
		snapshot.Uptime = response.Snapshot.Uptime
		snapshot.Peers = response.Snapshot.Peers
	}
	return snapshot
}

func (m *Controller) DisconnectPeer(identity string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := adminipc.Call(ctx, m.ipcSocket, "disconnect", identity)
	return err == nil
}

func (m *Controller) ServiceAction(ctx context.Context, action string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch action {
	case "start", "stop", "restart":
	default:
		return errors.New("unsupported service action")
	}
	if _, err := m.runner.Run(ctx, "systemctl", action, m.unit); err != nil {
		return fmt.Errorf("systemd %s failed for %s", action, m.unit)
	}
	want := "active"
	if action == "stop" {
		want = "inactive"
	}
	return m.waitForState(ctx, want)
}

func (m *Controller) ApplyConfiguration(ctx context.Context, config adminapi.TunnelConfiguration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	changes, err := m.configurationChanges(config)
	if err != nil {
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
	if bytes.Equal(original, updated) {
		return nil
	}
	state, _, err := m.readServiceState(ctx)
	if err != nil {
		return fmt.Errorf("cannot verify service state; configuration was not changed: %w", err)
	}
	if err := m.writeBackup(original); err != nil {
		return fmt.Errorf("cannot create protected backup; configuration was not changed: %w", err)
	}
	if err := atomicWrite(m.configPath, updated, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write validated configuration: %w", err)
	}
	if state != "active" {
		return nil
	}
	restartErr := m.restartAndWait(ctx)
	if restartErr == nil {
		return nil
	}
	rollbackErr := atomicWrite(m.configPath, original, info.Mode().Perm())
	if rollbackErr != nil {
		return fmt.Errorf("new configuration failed to start and automatic rollback failed; manual recovery required")
	}
	if _, err := m.runner.Run(ctx, "systemctl", "restart", m.unit); err != nil {
		return fmt.Errorf("new configuration failed; previous file was restored but service rollback restart failed")
	}
	if err := m.waitForState(ctx, "active"); err != nil {
		return fmt.Errorf("new configuration failed; previous file was restored but previous service state could not be confirmed")
	}
	return fmt.Errorf("new configuration failed to start; previous configuration was restored and restarted")
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
		local, err := parseCanonicalPrefixes(cfg.LocalPrefixes)
		if err != nil {
			return nil, fmt.Errorf("local prefixes: %w", err)
		}
		if prefixset.Overlap(peer, local) {
			return nil, errors.New("peer and local CIDR prefix sets must not overlap")
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
	remote, err := parseCanonicalPrefixes(cfg.RemotePrefixes)
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
	if value == "" || len(value) > 2048 {
		return nil, errors.New("at least one CIDR prefix is required")
	}
	prefixes, err := prefixset.ParseCSV(value)
	if err != nil {
		return nil, err
	}
	if len(prefixes) > 128 {
		return nil, errors.New("at most 128 CIDR prefixes are allowed")
	}
	for _, p := range prefixes {
		if !p.IsValid() || p != p.Masked() {
			return nil, fmt.Errorf("prefix %q must be a canonical network CIDR", p)
		}
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
