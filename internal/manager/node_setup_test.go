package manager

import (
	"testing"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

func TestValidateNodeSetupRequest(t *testing.T) {
	valid := adminapi.NodeSetupRequest{
		Operation: "gateway-init",
		PublicName: "gateway.example.com",
		ListenPort: 8443,
		TCPPorts: "443,80",
		UDPPorts: "53,123",
	}
	if err := ValidateNodeSetupRequest("gateway", valid); err != nil {
		t.Fatalf("valid Gateway setup rejected: %v", err)
	}
	if err := ValidateNodeSetupRequest("dialer", valid); err == nil {
		t.Fatal("Dialer role must not generate a Gateway profile")
	}

	badPort := valid
	badPort.ListenPort = 65536
	if err := ValidateNodeSetupRequest("gateway", badPort); err == nil {
		t.Fatal("out-of-range listener port accepted")
	}

	badHost := valid
	badHost.PublicName = "example.com;systemctl stop pqtunnel"
	if err := ValidateNodeSetupRequest("gateway", badHost); err == nil {
		t.Fatal("unsafe public name accepted")
	}

	badTCP := valid
	badTCP.TCPPorts = "443,,80"
	if err := ValidateNodeSetupRequest("gateway", badTCP); err == nil {
		t.Fatal("malformed TCP allowlist accepted")
	}

	noPorts := valid
	noPorts.TCPPorts = "none"
	noPorts.UDPPorts = "none"
	if err := ValidateNodeSetupRequest("gateway", noPorts); err == nil {
		t.Fatal("empty port allowlist accepted")
	}

	if err := ValidateNodeSetupRequest("dialer", adminapi.NodeSetupRequest{Operation: "dialer-import-gateway"}); err != nil {
		t.Fatalf("valid Dialer profile import rejected: %v", err)
	}
	if err := ValidateNodeSetupRequest("gateway", adminapi.NodeSetupRequest{Operation: "gateway-import-dialer"}); err != nil {
		t.Fatalf("valid Gateway profile import rejected: %v", err)
	}
	if err := ValidateNodeSetupRequest("gateway", adminapi.NodeSetupRequest{Operation: "dialer-import-gateway"}); err == nil {
		t.Fatal("Gateway role must not import a Gateway profile as a Dialer")
	}
	if err := ValidateNodeSetupRequest("dialer", adminapi.NodeSetupRequest{Operation: "gateway-import-dialer"}); err == nil {
		t.Fatal("Dialer role must not import a Dialer profile as a Gateway")
	}
}

func TestManagerSelectsTransportUnitOnlyWithExplicitMode(t *testing.T) {
	t.Setenv("PQTUNNEL_MANAGER_ENDPOINT_MODE", "")
	gateway, err := New(Options{Role: RoleGateway})
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := New(Options{Role: RoleDialer})
	if err != nil {
		t.Fatal(err)
	}
	if gateway.unit != "pqtunneld.service" || dialer.unit != "pqtunnel-client.service" {
		t.Fatalf("legacy units unexpectedly changed: gateway=%q dialer=%q", gateway.unit, dialer.unit)
	}

	t.Setenv("PQTUNNEL_MANAGER_ENDPOINT_MODE", "transport")
	gateway, err = New(Options{Role: RoleGateway})
	if err != nil {
		t.Fatal(err)
	}
	dialer, err = New(Options{Role: RoleDialer})
	if err != nil {
		t.Fatal(err)
	}
	if gateway.unit != "pqtunneld-transport.service" || dialer.unit != "pqtunnel-client-transport.service" {
		t.Fatalf("transport units not selected: gateway=%q dialer=%q", gateway.unit, dialer.unit)
	}
}
