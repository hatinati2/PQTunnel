package tunnel

import (
	"crypto/tls"
	"errors"
)

var ErrHybridPQUnavailable = errors.New("strict X25519MLKEM768 key exchange unavailable; use Go 1.24+ and do not enable classical fallback")

// StrictTLS13Config enables only the standardized X25519 + ML-KEM-768 hybrid
// key-exchange group. It intentionally fails closed if the peer cannot negotiate it.
func StrictTLS13Config() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519MLKEM768},
		SessionTicketsDisabled: true,
	}
}

 
// VerifyPeerCommonName enforces an exact application identity after the TLS
// stack has validated the peer certificate chain and its usage.
func VerifyPeerCommonName(state tls.ConnectionState, expected string) error {
	if expected == "" {
		return errors.New("expected peer common name is required")
	}
	if len(state.PeerCertificates) == 0 {
		return errors.New("peer certificate is required")
	}
	if state.PeerCertificates[0].Subject.CommonName != expected {
		return errors.New("peer certificate common name mismatch")
	}
	return nil
}
