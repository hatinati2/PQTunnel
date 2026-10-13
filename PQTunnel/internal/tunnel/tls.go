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
