package manager

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
		"regexp"
	"strconv"
	"strings"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

const (
	setupUnit = "pqtunnel-setup.service"
	setupDir = "/var/lib/pqtunnel-manager"
	setupEnvPath = setupDir + "/setup.env"
	setupStatePath = setupDir + "/setup-state"
	setupLogPath = setupDir + "/setup.log"
	setupRawLogPath = setupDir + "/setup-raw.log"
	setupTokensPath = setupDir + "/setup-tokens"
	setupApprovalPath = setupDir + "/setup-approval"
	setupWorkerPath = "/usr/local/lib/pqtunnel/pqtunnel-setup-worker.sh"
	setupScriptPath = "/usr/local/lib/pqtunnel/pqtunnel-site-to-site-setup.sh"
	setupServicePath = "/etc/systemd/system/pqtunnel-setup.service"
)

var (
	setupPortListPattern = regexp.MustCompile(`^[0-9]+(,[0-9]+)*$`)
	setupInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	setupTokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidateSiteToSiteSetupRequest validates all operator-provided values before
// they reach the fixed worker. No input is ever interpreted as a shell command.
func ValidateSiteToSiteSetupRequest(req adminapi.SiteToSiteSetupRequest) error {
	if req.Confirm != "CHECK" {
		return errors.New("setup request must be explicitly started from the authenticated wizard")
	}
	if !strings.HasPrefix(req.GatewaySSHTarget, "root@") || strings.Count(req.GatewaySSHTarget, "@") != 1 {
		return errors.New("Gateway SSH target must use root@IPv4-or-DNS")
	}
	if !validSetupHost(strings.TrimPrefix(req.GatewaySSHTarget, "root@")) {
		return errors.New("Gateway SSH target contains an invalid IPv4 address or DNS name")
	}
	if req.SSHPort < 1 || req.SSHPort > 65535 {
		return errors.New("SSH port must be between 1 and 65535")
	}
	if !validSetupHost(req.GatewayName) {
		return errors.New("Gateway TLS name must be a valid IPv4 address or DNS name")
	}
	if req.TLSPort < 1 || req.TLSPort > 65535 {
		return errors.New("Tunnel listener port must be between 1 and 65535")
	}
	tcp, err := validateSetupPorts(req.TCPPorts, false)
	if err != nil || tcp == "" {
		return errors.New("TCP destination ports must be a comma-separated list such as 443 or 80,443")
	}
	if _, err := validateSetupPorts(req.UDPPorts, true); err != nil {
		return errors.New("UDP destination ports must be a comma-separated list such as 53,123 or none")
	}
	if req.DialerWAN != "" && !setupInterfacePattern.MatchString(req.DialerWAN) {
		return errors.New("Iran WAN interface name is invalid")
	}
	if req.GatewayWAN != "" && !setupInterfacePattern.MatchString(req.GatewayWAN) {
		return errors.New("Germany WAN interface name is invalid")
	}
	return nil
}

func validSetupHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\\x00 \t\r\n'\";$&|<>") {
		return false
	}
	if ip := netParseIPv4(host); ip {
		return true
	}
	if strings.Count(host, ".") == 3 && strings.Trim(host, "0123456789.") == "" {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func netParseIPv4(value string) bool {
	// The setup helper supports IPv4 or DNS (not bracketed IPv6) for this flow.
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 || (len(part) > 1 && part[0] == '0') {
			return false
		}
	}
	return true
}

func validateSetupPorts(value string, allowNone bool) (string, error) {
	value = strings.TrimSpace(value)
	if allowNone && (value == "" || strings.EqualFold(value, "none") || value == "-") {
		return "", nil
	}
	if value == "" || !setupPortListPattern.MatchString(value) {
		return "", errors.New("invalid port list")
	}
	seen := make(map[int]bool)
	parts := strings.Split(value, ",")
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 || seen[n] {
			return "", errors.New("invalid or repeated port")
		}
		seen[n] = true
	}
	return value, nil
}

// StartSiteToSiteSetup starts only the fixed systemd worker after validating all
// values. The browser cannot supply a command, script path, unit name or key.
func (m *Controller) StartSiteToSiteSetup(ctx context.Context, req adminapi.SiteToSiteSetupRequest) error {
	if m.role != RoleDialer {
		return errors.New("the two-server setup wizard must be run from the Iran/Dialer panel")
	}
	if err := ValidateSiteToSiteSetupRequest(req); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.speedRunMu.TryLock() {
		return errors.New("another management operation is in progress")
	}
	defer m.speedRunMu.Unlock()

	for _, path := range []string{setupWorkerPath, setupScriptPath, setupServicePath} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("the graphical setup worker is not installed; upgrade PQTunnel manager from a release containing the setup wizard")
		}
	}
	active, err := m.runner.Run(ctx, "systemctl", "show", "--property=ActiveState", "--value", setupUnit)
	if err != nil {
		return errors.New("could not inspect setup worker state")
	}
	if strings.TrimSpace(active) == "active" || strings.TrimSpace(active) == "activating" {
		return errors.New("a site-to-site setup is already running")
	}

	inputs := []string{
		req.GatewaySSHTarget,
		strconv.Itoa(req.SSHPort),
		req.GatewayName,
		strconv.Itoa(req.TLSPort),
		req.TCPPorts,
		req.UDPPorts,
		req.DialerWAN,
		req.GatewayWAN,
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(inputs, "\n") + "\n"))
	env := []byte("PQTUNNEL_SETUP_INPUT_B64=" + encoded + "\n")
	if err := atomicWrite(setupEnvPath, env, 0600); err != nil {
		return errors.New("could not securely stage the setup request")
	}
	for _, path := range []string{setupLogPath, setupRawLogPath, setupTokensPath, setupApprovalPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(setupEnvPath)
			return errors.New("could not clear protected state from the previous setup")
		}
	}
	if err := atomicWrite(setupStatePath, []byte("queued\n"), 0600); err != nil {
		_ = os.Remove(setupEnvPath)
		return errors.New("could not record setup state")
	}
	_, _ = m.runner.Run(ctx, "systemctl", "reset-failed", setupUnit)
	if _, err := m.runner.Run(ctx, "systemctl", "start", "--no-block", setupUnit); err != nil {
		_ = atomicWrite(setupStatePath, []byte("failed\n"), 0600)
		return errors.New("systemd could not start the graphical setup worker")
	}
	return nil
}

// SiteToSiteSetupStatus exposes only bounded, redacted setup output.
func (m *Controller) SiteToSiteSetupStatus(ctx context.Context) (adminapi.SiteToSiteSetupStatus, error) {
	out := adminapi.SiteToSiteSetupStatus{State: "idle"}
	if m.role != RoleDialer {
		return out, nil
	}
	for _, path := range []string{setupWorkerPath, setupScriptPath, setupServicePath} {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			return out, nil
		}
	}
	out.Available = true
	active, err := m.runner.Run(ctx, "systemctl", "show", "--property=ActiveState", "--value", setupUnit)
	if err == nil {
		stateText := strings.TrimSpace(active)
		if stateText == "active" || stateText == "activating" {
			out.Running = true
		}
	}
	if data, readErr := os.ReadFile(setupStatePath); readErr == nil {
		switch strings.TrimSpace(string(data)) {
		case "queued":
			out.State = "queued"
		case "running":
			out.State = "running"
		case "awaiting-confirmation":
			out.State = "awaiting-confirmation"
		case "succeeded":
			out.State, out.Success = "succeeded", true
		case "failed":
			out.State = "failed"
		}
	}
	if out.Running && (out.State == "idle" || out.State == "queued") {
		out.State = "running"
	}
	tokenInfo, tokenErr := os.Lstat(setupTokensPath)
	out.TokensAvailable = tokenErr == nil && tokenInfo.Mode().IsRegular() && tokenInfo.Mode().Perm() == 0600
	logPath := setupLogPath
	if out.Running {
		if _, statErr := os.Stat(setupRawLogPath); statErr == nil {
			logPath = setupRawLogPath
		}
	}
	if data, readErr := os.ReadFile(logPath); readErr == nil {
		if len(data) > 24000 {
			data = data[len(data)-24000:]
		}
		out.Output = redactSetupOutput(string(data))
	}
	return out, nil
}

var setupSecretLine = regexp.MustCompile(`(?im)^(Iran/Dialer manager token|Germany/Gateway manager token|Shared speed-test token|PQTUNNEL_MANAGER_TOKEN)=?[^\r\n]*`)
var setupTokenValue = regexp.MustCompile(`(?i)(token:\s*|PQTUNNEL_MANAGER_TOKEN=)[0-9a-f]{32,}`)

func redactSetupOutput(value string) string {
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		if strings.Contains(strings.ToUpper(line), "PRIVATE KEY") || strings.Contains(line, "-----BEGIN") ||
			setupSecretLine.MatchString(line) {
			lines[i] = "[redacted sensitive setup output]"
			continue
		}
		line = setupTokenValue.ReplaceAllString(line, "$1[REDACTED]")
		if len(line) > 1000 {
			line = line[:1000] + " … [truncated]"
		}
		lines[i] = line
	}
	result := strings.Join(lines, "\n")
	if len(result) > 18000 {
		result = result[len(result)-18000:]
	}
	return result
}

// ConsumeSiteToSiteSetupTokens atomically removes the one-time token handoff
// file before returning its strictly validated contents to the authenticated UI.
func (m *Controller) ConsumeSiteToSiteSetupTokens(ctx context.Context) (adminapi.SiteToSiteSetupTokens, error) {
	_ = ctx
	if m.role != RoleDialer {
		return adminapi.SiteToSiteSetupTokens{}, errors.New("tokens are available only from the Iran/Dialer panel")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	info, err := os.Lstat(setupTokensPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return adminapi.SiteToSiteSetupTokens{}, errors.New("no one-time setup tokens are available")
	}
	raw, err := os.ReadFile(setupTokensPath)
	if err != nil || len(raw) > 2048 {
		return adminapi.SiteToSiteSetupTokens{}, errors.New("could not read the protected token handoff")
	}
	// Remove first so a second request cannot read the same one-time secrets.
	if err := os.Remove(setupTokensPath); err != nil {
		return adminapi.SiteToSiteSetupTokens{}, errors.New("could not consume one-time setup tokens")
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	tokens := adminapi.SiteToSiteSetupTokens{
		Dialer: values["DIALER_TOKEN"],
		Gateway: values["GATEWAY_TOKEN"],
		SpeedTest: values["SPEEDTEST_TOKEN"],
	}
	if tokens.Dialer != "" && !setupTokenPattern.MatchString(tokens.Dialer) ||
		tokens.Gateway != "" && !setupTokenPattern.MatchString(tokens.Gateway) ||
		tokens.SpeedTest != "" && !setupTokenPattern.MatchString(tokens.SpeedTest) {
		return adminapi.SiteToSiteSetupTokens{}, fmt.Errorf("setup token handoff was invalid and has been consumed")
	}
	if tokens.Dialer == "" && tokens.Gateway == "" && tokens.SpeedTest == "" {
		return adminapi.SiteToSiteSetupTokens{}, errors.New("setup worker did not produce any new tokens")
	}
	return tokens, nil
}


// ApproveSiteToSiteSetup authorizes only the running, preflight-complete setup
// worker. Approval is a separate authenticated and CSRF-protected web action.
func (m *Controller) ApproveSiteToSiteSetup(ctx context.Context) error {
	if m.role != RoleDialer {
		return errors.New("setup approval is available only from the Dialer manager")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.speedRunMu.TryLock() {
		return errors.New("another management operation is in progress")
	}
	defer m.speedRunMu.Unlock()
	stateData, err := os.ReadFile(setupStatePath)
	if err != nil || strings.TrimSpace(string(stateData)) != "awaiting-confirmation" {
		return errors.New("setup has not completed its preflight review; approval is unavailable")
	}
	active, err := m.runner.Run(ctx, "systemctl", "show", "--property=ActiveState", "--value", setupUnit)
	if err != nil || strings.TrimSpace(active) != "active" {
		return errors.New("setup worker is not waiting for approval")
	}
	return atomicWrite(setupApprovalPath, []byte("INSTALL\n"), 0600)
}

var _ adminapi.SetupWizardController = (*Controller)(nil)
