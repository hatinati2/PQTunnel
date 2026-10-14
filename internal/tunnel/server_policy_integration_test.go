package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/hatinati2/PQTunnel/internal/prefixset"
	"github.com/hatinati2/PQTunnel/internal/protocol"
)

type serverPolicyTestDevice struct {
	writes chan []byte
	closed chan struct{}
	once sync.Once
}

func newServerPolicyTestDevice() *serverPolicyTestDevice {
	return &serverPolicyTestDevice{writes: make(chan []byte, 8), closed: make(chan struct{})}
}
func (d *serverPolicyTestDevice) Read([]byte) (int, error) {
	<-d.closed
	return 0, io.ErrClosedPipe
}
func (d *serverPolicyTestDevice) Write(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	d.writes <- append([]byte(nil), p...)
	return len(p), nil
}
func (d *serverPolicyTestDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func createPolicyTestCert(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, cn, dnsName string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
		DNSNames: nil,
	}
	if dnsName != "" { tmpl.DNSNames = []string{dnsName} }
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil { t.Fatal(err) }
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil { t.Fatal(err) }
	certPEM := pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY", Bytes:keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil { t.Fatal(err) }
	return cert
}

func createPolicyTestCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{CommonName:"PQTunnel policy test CA"},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(2*time.Hour),
		IsCA: true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil { t.Fatal(err) }
	ca, err := x509.ParseCertificate(der)
	if err != nil { t.Fatal(err) }
	pemBytes := pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:der})
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) { t.Fatal("could not append generated test CA") }
	return ca, key, pool
}

func policyTestIPv4Packet(src, dst string) []byte {
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	p := make([]byte, 20)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 1
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return p
}

func TestServerHandleAuthenticatesPeerAndEnforcesCIDRPolicy(t *testing.T) {
	ca, caKey, roots := createPolicyTestCA(t)
	serverCert := createPolicyTestCert(t, ca, caKey, "gateway", "gateway.example.test", x509.ExtKeyUsageServerAuth)
	peerCert := createPolicyTestCert(t, ca, caKey, "iran", "", x509.ExtKeyUsageClientAuth)
	peerPrefixes, err := prefixset.ParseCSV("192.0.2.0/24")
	if err != nil { t.Fatal(err) }
	localPrefixes, err := prefixset.ParseCSV("10.66.0.0/24")
	if err != nil { t.Fatal(err) }

	dev := newServerPolicyTestDevice()
	s := &Server{
		TLSConfig: ServerTLSConfig(serverCert, roots),
		Device: dev,
		MaxClients: 1,
		PeerPrefixes: peerPrefixes,
		LocalPrefixes: localPrefixes,
		PeerIdentity: "iran",
		clients: make(map[string]*peer),
	}

	clientRaw, serverRaw := net.Pipe()
	serverConn := tls.Server(serverRaw, s.TLSConfig.Clone())
	clientTLSConfig := StrictTLS13Config()
	clientTLSConfig.RootCAs = roots
	clientTLSConfig.ServerName = "gateway.example.test"
	clientTLSConfig.Certificates = []tls.Certificate{peerCert}
	clientConn := tls.Client(clientRaw, clientTLSConfig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.handle(ctx, serverConn)
		close(done)
	}()
	if err := clientConn.Handshake(); err != nil {
		t.Fatalf("mutual TLS handshake failed: %v", err)
	}

	disallowedDst := policyTestIPv4Packet("192.0.2.7", "198.51.100.9")
	allowed := policyTestIPv4Packet("192.0.2.8", "10.66.0.2")
	for _, p := range [][]byte{disallowedDst, allowed} {
		if err := protocol.WriteFrame(clientConn, p); err != nil {
			t.Fatalf("write test frame: %v", err)
		}
	}
	select {
	case got := <-dev.writes:
		if string(got) != string(allowed) {
			t.Fatalf("server forwarded unexpected packet: got %v, want %v", got, allowed)
		}
	case <-time.After(2*time.Second):
		t.Fatal("server did not forward the allowed packet")
	}
	select {
	case extra := <-dev.writes:
		t.Fatalf("server forwarded disallowed packet: %v", extra)
	case <-time.After(30*time.Millisecond):
	}

	// A source address outside the authenticated peer's CIDR must terminate the session.
	spoof := policyTestIPv4Packet("203.0.113.7", "10.66.0.2")
	_ = protocol.WriteFrame(clientConn, spoof)
	select {
	case <-done:
	case <-time.After(2*time.Second):
		t.Fatal("server did not terminate a peer session after source spoofing")
	}
	_ = clientConn.Close()
	_ = dev.Close()
}

func TestServerHandleRejectsWrongPeerIdentity(t *testing.T) {
	ca, caKey, roots := createPolicyTestCA(t)
	serverCert := createPolicyTestCert(t, ca, caKey, "gateway", "gateway.example.test", x509.ExtKeyUsageServerAuth)
	wrongPeerCert := createPolicyTestCert(t, ca, caKey, "not-iran", "", x509.ExtKeyUsageClientAuth)
	peerPrefixes, _ := prefixset.ParseCSV("192.0.2.0/24")
	localPrefixes, _ := prefixset.ParseCSV("10.66.0.0/24")
	dev := newServerPolicyTestDevice()
	s := &Server{
		TLSConfig: ServerTLSConfig(serverCert, roots),
		Device: dev,
		MaxClients: 1,
		PeerPrefixes: peerPrefixes,
		LocalPrefixes: localPrefixes,
		PeerIdentity: "iran",
		clients: make(map[string]*peer),
	}
	clientRaw, serverRaw := net.Pipe()
	serverConn := tls.Server(serverRaw, s.TLSConfig.Clone())
	clientCfg := StrictTLS13Config()
	clientCfg.RootCAs = roots
	clientCfg.ServerName = "gateway.example.test"
	clientCfg.Certificates = []tls.Certificate{wrongPeerCert}
	clientConn := tls.Client(clientRaw, clientCfg)
	done := make(chan struct{})
	go func() { s.handle(context.Background(), serverConn); close(done) }()
	if err := clientConn.Handshake(); err != nil {
		// An early handshake error is acceptable for rejected identity.
		_ = clientConn.Close()
	} else {
		_ = protocol.WriteFrame(clientConn, policyTestIPv4Packet("192.0.2.1", "10.66.0.2"))
		_ = clientConn.Close()
	}
	select {
	case <-done:
	case <-time.After(2*time.Second):
		t.Fatal("server did not close connection for mismatched peer identity")
	}
	select {
	case got := <-dev.writes:
		t.Fatalf("server accepted data from wrong peer identity: %v", got)
	default:
	}
	if err := clientConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		// Closing a TLS connection after rejection can return a transport error; not significant.
	}
	_ = dev.Close()
}
