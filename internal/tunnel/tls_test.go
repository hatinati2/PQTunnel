package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

 
func TestVerifyPeerCommonName(t *testing.T) {
	tests := []struct {
		name     string
		state    tls.ConnectionState
		expected string
		wantErr  bool
	}{
		{
			name: "exact match",
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: "dialer.test"}},
			}},
			expected: "dialer.test",
		},
		{
			name: "mismatch",
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{
				{Subject: pkix.Name{CommonName: "other.test"}},
			}},
			expected: "dialer.test",
			wantErr:  true,
		},
		{name: "missing expected identity", state: tls.ConnectionState{}, wantErr: true},
		{name: "missing peer certificate", state: tls.ConnectionState{}, expected: "dialer.test", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPeerCommonName(tt.state, tt.expected)
			if (err != nil) != tt.wantErr {
				t.Fatalf("VerifyPeerCommonName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
