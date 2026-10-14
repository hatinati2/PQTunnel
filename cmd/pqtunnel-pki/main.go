package main

import (
	"crypto/ed25519"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "init":
		initCA(os.Args[2:])
	case "issue-client":
		issueClient(os.Args[2:])
	case "issue-server":
		issueAdditionalServer(os.Args[2:])
	case "issue-peer":
		issuePeer(os.Args[2:])
	default:
		usage()
	}
}

func initCA(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	out := fs.String("out", "./pki", "output directory; keep this directory private")
	host := fs.String("server-name", "", "public DNS name or IP used for the server certificate SAN")
	_ = fs.Parse(args)
	if *host == "" {
		die("--server-name is required")
	}
	if err := os.MkdirAll(*out, 0700); err != nil {
		die(err.Error())
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die(err.Error())
	}
	now := time.Now()
	caTpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "PQTunnel local CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, pub, priv)
	if err != nil {
		die(err.Error())
	}
	if err := writePEM(filepath.Join(*out, "ca.crt"), "CERTIFICATE", caDER, 0644); err != nil {
		die(err.Error())
	}
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		die(err.Error())
	}
	if err := writePEM(filepath.Join(*out, "ca.key"), "PRIVATE KEY", caKeyDER, 0600); err != nil {
		die(err.Error())
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		die(err.Error())
	}
	issueServer(*out, *host, caCert, priv)
	fmt.Printf("Created CA and server certificate in %s. Keep ca.key offline; never copy it to the server or clients.\n", *out)
}

func issueServer(out, host string, ca *x509.Certificate, caKey ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die(err.Error())
	}
	tpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: host}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			tpl.IPAddresses = []net.IP{ip.AsSlice()}
		} else {
			tpl.IPAddresses = []net.IP{ip.AsSlice()}
		}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, pub, caKey)
	if err != nil {
		die(err.Error())
	}
	if err := writePEM(filepath.Join(out, "server.crt"), "CERTIFICATE", der, 0644); err != nil {
		die(err.Error())
	}
	writePrivateKey(filepath.Join(out, "server.key"), priv)
}

func loadCA(out string) (*x509.Certificate, ed25519.PrivateKey) {
	caPEM, err := os.ReadFile(filepath.Join(out, "ca.crt"))
	if err != nil {
		die(err.Error())
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		die("invalid ca.crt")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		die(err.Error())
	}
	keyPEM, err := os.ReadFile(filepath.Join(out, "ca.key"))
	if err != nil {
		die(err.Error())
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		die("invalid ca.key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		die(err.Error())
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		die("ca.key is not an Ed25519 key")
	}
	if err := validateCAKey(ca, key); err != nil {
		die(err.Error())
	}
	return ca, key
}

func validateCAKey(ca *x509.Certificate, key ed25519.PrivateKey) error {
	if ca == nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("ca.crt is not a valid certificate-signing CA")
	}
	now := time.Now()
	if now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return fmt.Errorf("ca.crt is not currently valid")
	}
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("ca.key has an invalid Ed25519 private-key length")
	}
	pub, ok := ca.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, key.Public().(ed25519.PublicKey)) {
		return fmt.Errorf("ca.key does not match ca.crt")
	}
	return nil
}

func issueAdditionalServer(args []string) {
	fs := flag.NewFlagSet("issue-server", flag.ExitOnError)
	out := fs.String("out", "./pki", "existing CA directory (contains ca.crt and private ca.key)")
	host := fs.String("server-name", "", "DNS name or IP SAN for this server certificate")
	prefix := fs.String("prefix", "peer", "safe filename prefix, e.g. iran or abroad")
	_ = fs.Parse(args)
	if *host == "" {
		die("--server-name is required")
	}
	if !safeIdentity(*prefix) {
		die("--prefix must contain 1-64 letters, digits, dot, underscore or hyphen")
	}
	ca, caKey := loadCA(*out)
	issueServerNamed(*out, *host, *prefix+"-server", ca, caKey)
	fmt.Printf("Issued server certificate for %s as %s-server.crt/.key. Keep CA key offline.\n", *host, *prefix)
}

func issuePeer(args []string) {
	fs := flag.NewFlagSet("issue-peer", flag.ExitOnError)
	out := fs.String("out", "./pki", "existing CA directory (contains ca.crt and private ca.key)")
	name := fs.String("name", "", "peer identity; letters, digits, dot, underscore or hyphen")
	_ = fs.Parse(args)
	if !safeIdentity(*name) {
		die("--name is required and must contain 1-64 letters, digits, dot, underscore or hyphen")
	}
	ca, caKey := loadCA(*out)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die(err.Error())
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: *name, OrganizationalUnit: []string{"PQTunnel peer"}},
		NotBefore:    time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, pub, caKey)
	if err != nil {
		die(err.Error())
	}
	stem := filepath.Join(*out, "peer-"+*name)
	if err := writePEM(stem+".crt", "CERTIFICATE", der, 0644); err != nil {
		die(err.Error())
	}
	writePrivateKey(stem+".key", priv)
	fmt.Printf("Issued peer identity %s. Install only %s.crt, %s.key and ca.crt on the peer; keep ca.key offline.\n", *name, stem, stem)
}

func issueServerNamed(out, host, stem string, ca *x509.Certificate, caKey ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die(err.Error())
	}
	tpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: host}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip, err := netip.ParseAddr(host); err == nil {
		tpl.IPAddresses = []net.IP{ip.AsSlice()}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, pub, caKey)
	if err != nil {
		die(err.Error())
	}
	if err := writePEM(filepath.Join(out, stem+".crt"), "CERTIFICATE", der, 0644); err != nil {
		die(err.Error())
	}
	writePrivateKey(filepath.Join(out, stem+".key"), priv)
}

func safeIdentity(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func issueClient(args []string) {
	fs := flag.NewFlagSet("issue-client", flag.ExitOnError)
	out := fs.String("out", "./pki", "existing PKI directory")
	ipText := fs.String("ip", "", "unique client IPv4 address, also used as certificate CN")
	_ = fs.Parse(args)
	ip, err := netip.ParseAddr(*ipText)
	if err != nil || !ip.Is4() {
		die("--ip must be a valid IPv4 address")
	}
	ca, caKey := loadCA(*out)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		die(err.Error())
	}
	tpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: ip.String(), OrganizationalUnit: []string{"PQTunnel client"}}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, pub, caKey)
	if err != nil {
		die(err.Error())
	}
	stem := "client-" + strings.ReplaceAll(ip.String(), ".", "_")
	if err := writePEM(filepath.Join(*out, stem+".crt"), "CERTIFICATE", der, 0644); err != nil {
		die(err.Error())
	}
	writePrivateKey(filepath.Join(*out, stem+".key"), priv)
	fmt.Printf("Issued client %s. Install only %s.crt, %s.key and ca.crt on that device.\n", ip, stem, stem)
}

func writePrivateKey(path string, key ed25519.PrivateKey) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		die(err.Error())
	}
	if err := writePEM(path, "PRIVATE KEY", der, 0600); err != nil {
		die(err.Error())
	}
}
func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		die(err.Error())
	}
	return n
}
func die(s string) { fmt.Fprintln(os.Stderr, "pqtunnel-pki:", s); os.Exit(1) }
func usage() {
	die("usage: pqtunnel-pki init --server-name vpn.example.com --out ./pki | issue-server --server-name peer.example.com --prefix peer --out ./pki | issue-peer --name iran --out ./pki | issue-client --ip 10.66.0.2 --out ./pki")
}
