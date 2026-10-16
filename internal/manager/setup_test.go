package manager

import (
	"strings"
	"testing"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

func validSiteToSiteSetupRequest() adminapi.SiteToSiteSetupRequest {
	return adminapi.SiteToSiteSetupRequest{
		GatewaySSHTarget: "root@203.0.113.10",
		SSHPort: 22,
		GatewayName: "vpn.example.test",
		TLSPort: 8443,
		TCPPorts: "80,443",
		UDPPorts: "53,123",
		DialerWAN: "ens3",
		GatewayWAN: "eth0",
		Confirm: "CHECK",
	}
}

func TestValidateSiteToSiteSetupRequestAcceptsValidInputs(t *testing.T) {
	req := validSiteToSiteSetupRequest()
	if err := ValidateSiteToSiteSetupRequest(req); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	req.GatewayName = "203.0.113.10"
	req.UDPPorts = "none"
	if err := ValidateSiteToSiteSetupRequest(req); err != nil {
		t.Fatalf("valid IPv4 with no UDP ports rejected: %v", err)
	}
	req.TCPPorts = "none"
	req.UDPPorts = "53"
	if err := ValidateSiteToSiteSetupRequest(req); err != nil {
		t.Fatalf("valid UDP-only profile rejected: %v", err)
	}
}

func TestValidateSiteToSiteSetupRequestRejectsUnsafeValues(t *testing.T) {
	tests := []struct {
		name string
		edit func(*adminapi.SiteToSiteSetupRequest)
	}{
		{"missing explicit preflight submit", func(r *adminapi.SiteToSiteSetupRequest) { r.Confirm = "" }},
		{"install confirmation cannot skip preflight", func(r *adminapi.SiteToSiteSetupRequest) { r.Confirm = "INSTALL" }},
		{"ssh target command injection", func(r *adminapi.SiteToSiteSetupRequest) { r.GatewaySSHTarget = "root@host;id" }},
		{"ssh user must be root", func(r *adminapi.SiteToSiteSetupRequest) { r.GatewaySSHTarget = "admin@203.0.113.10" }},
		{"invalid SSH port", func(r *adminapi.SiteToSiteSetupRequest) { r.SSHPort = 65536 }},
		{"URI is not a TLS host", func(r *adminapi.SiteToSiteSetupRequest) { r.GatewayName = "https://vpn.example.test" }},
		{"invalid TLS host", func(r *adminapi.SiteToSiteSetupRequest) { r.GatewayName = "bad name.example.test" }},
		{"invalid listener port", func(r *adminapi.SiteToSiteSetupRequest) { r.TLSPort = 0 }},
		{"both port lists empty", func(r *adminapi.SiteToSiteSetupRequest) { r.TCPPorts = ""; r.UDPPorts = "none" }},
		{"port out of range", func(r *adminapi.SiteToSiteSetupRequest) { r.TCPPorts = "443,65536" }},
		{"duplicate TCP port", func(r *adminapi.SiteToSiteSetupRequest) { r.TCPPorts = "443,443" }},
		{"command in port list", func(r *adminapi.SiteToSiteSetupRequest) { r.TCPPorts = "443;id" }},
		{"bad UDP list", func(r *adminapi.SiteToSiteSetupRequest) { r.UDPPorts = "53,none" }},
		{"bad interface name", func(r *adminapi.SiteToSiteSetupRequest) { r.DialerWAN = "eth0;reboot" }},
		{"bad remote interface name", func(r *adminapi.SiteToSiteSetupRequest) { r.GatewayWAN = "eth0/../x" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validSiteToSiteSetupRequest()
			tt.edit(&req)
			if err := ValidateSiteToSiteSetupRequest(req); err == nil {
				t.Fatal("unsafe request unexpectedly passed validation")
			}
		})
	}
}

func TestValidSetupHostRejectsMalformedNumericIPv4(t *testing.T) {
	for _, host := range []string{"999.999.999.999", "256.1.1.1", "01.2.3.4"} {
		if validSetupHost(host) {
			t.Errorf("invalid IPv4 address accepted as a DNS name: %q", host)
		}
	}
}

func TestRedactSetupOutputMasksAllManagerTokens(t *testing.T) {
	input := strings.Join([]string{
		"plan complete",
		"Iran/Dialer manager token: " + strings.Repeat("a", 64),
		"Germany/Gateway manager token: " + strings.Repeat("b", 64),
		"Shared speed-test token: " + strings.Repeat("c", 64),
		"PQTUNNEL_MANAGER_TOKEN=" + strings.Repeat("d", 64),
		"-----BEGIN PRIVATE KEY-----",
	}, "\n")
	out := redactSetupOutput(input)
	for _, secret := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), "PRIVATE KEY"} {
		if strings.Contains(out, secret) {
			t.Errorf("redacted setup output contains %q: %s", secret, out)
		}
	}
}
