package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSafeIdentity(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"iran", true},
		{"germany-1", true},
		{"peer.example", true},
		{"", false},
		{"../outside", false},
		{"has space", false},
		{"slash/name", false},
		{strings.Repeat("a", 65), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeIdentity(tt.name); got != tt.ok {
				t.Fatalf("safeIdentity(%q) = %v, want %v", tt.name, got, tt.ok)
			}
		})
	}
}

func TestIssueServerCreatesVerifiableCertificateAndPrivateKey(t *testing.T) {
	for _, host := range []string{"vpn.example.test", "192.0.2.10", "2001:db8::10"} {
		t.Run(host, func(t *testing.T) {
			out := t.TempDir()
			caCert, caKey := testCA(t)
			issueServer(out, host, caCert, caKey)

			certPEM, err := os.ReadFile(filepath.Join(out, "server.crt"))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(certPEM)
			if block == nil {
				t.Fatal("server.crt is not PEM")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(caCert)
			opts := x509.VerifyOptions{Roots: roots, CurrentTime: time.Now()}
			if ip, err := netip.ParseAddr(host); err == nil {
				opts.DNSName = ip.String()
			} else {
				opts.DNSName = host
			}
			if _, err := leaf.Verify(opts); err != nil {
				t.Fatalf("issued server certificate does not verify for %q: %v", host, err)
			}
			if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
				t.Fatalf("unexpected extended key usages: %v", leaf.ExtKeyUsage)
			}

			info, err := os.Stat(filepath.Join(out, "server.key"))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("server private key mode = %04o, want 0600", info.Mode().Perm())
			}
		})
	}
}

func testCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(time.Hour),
		IsCA: true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

func TestValidateCAKeyRejectsMismatchedKey(t *testing.T) {
	caCert, _ := testCA(t)
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCAKey(caCert, otherKey); err == nil {
		t.Fatal("expected mismatched CA key to be rejected")
	}
}

func TestValidateCAKeyRejectsNonCA(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: "not a CA"},
		NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCAKey(cert, key); err == nil {
		t.Fatal("expected non-CA certificate to be rejected")
	}
}
