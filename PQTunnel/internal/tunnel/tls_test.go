package tunnel

import (
	"crypto/tls"
	"testing"
)

func TestTLSConfigRequiresHybridGroupOnly(t *testing.T) {
	cfg := StrictTLS13Config()
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatal("TLS 1.3 must be the only enabled version")
	}
	if len(cfg.CurvePreferences) != 1 || cfg.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("unexpected curve policy: %#v", cfg.CurvePreferences)
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("session tickets should be disabled for this prototype")
	}
}
