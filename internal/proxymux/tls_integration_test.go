package proxymux

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hatinati2/PQTunnel/internal/tunnel"
)

type tlsMuxFixture struct {
	roots          *x509.CertPool
	serverCert     tls.Certificate
	clientCert     tls.Certificate
	wrongClientCert tls.Certificate
}

func newTLSMuxFixture(t *testing.T) *tlsMuxFixture {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PQTunnel test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	return &tlsMuxFixture{
		roots:           roots,
		serverCert:      newTLSMuxLeaf(t, caCert, caKey, now, 2, "gateway.test", "gateway.test", x509.ExtKeyUsageServerAuth),
		clientCert:      newTLSMuxLeaf(t, caCert, caKey, now, 3, "dialer.test", "", x509.ExtKeyUsageClientAuth),
		wrongClientCert: newTLSMuxLeaf(t, caCert, caKey, now, 4, "unexpected-client.test", "", x509.ExtKeyUsageClientAuth),
	}
}

func newTLSMuxLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time, serial int64, commonName, dnsName string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
	}
	if dnsName != "" {
		template.DNSNames = []string{dnsName}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func (f *tlsMuxFixture) clientConfig(clientCert tls.Certificate, serverName string) *tls.Config {
	cfg := tunnel.StrictTLS13Config()
	cfg.RootCAs = f.roots
	cfg.Certificates = []tls.Certificate{clientCert}
	cfg.ServerName = serverName
	return cfg
}

func (f *tlsMuxFixture) serverConfig() *tls.Config {
	return tunnel.ServerTLSConfig(f.serverCert, f.roots)
}

func TestTLS13MTLSTransportsConcurrentDirectAndReverseStreams(t *testing.T) {
	fixture := newTLSMuxFixture(t)
	dialerSession, gatewaySession, targets := startTLSMuxSessions(t, fixture)

	direct, err := dialerSession.Open(TypeOpenDirect, []byte("direct"))
	if err != nil {
		t.Fatalf("open Direct stream over TLS: %v", err)
	}
	defer direct.Close()

	reverse, err := gatewaySession.Open(TypeOpenReverse, []byte("reverse"))
	if err != nil {
		t.Fatalf("open Reverse stream over TLS: %v", err)
	}
	defer reverse.Close()

	directTarget := awaitTarget(t, targets, "direct")
	reverseTarget := awaitTarget(t, targets, "reverse")

	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		results <- exchangeTLSStream(direct, directTarget, "direct-request", "direct-response")
	}()
	go func() {
		defer wg.Done()
		results <- exchangeTLSStream(reverse, reverseTarget, "reverse-request", "reverse-response")
	}()
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Errorf("TLS stream exchange failed: %v", err)
		}
	}
}

func startTLSMuxSessions(t *testing.T, fixture *tlsMuxFixture) (*Session, *Session, <-chan acceptedTarget) {
	t.Helper()
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(rawListener, fixture.serverConfig())
	ctx, cancel := context.WithCancel(context.Background())
	targets := make(chan acceptedTarget, 8)
	var gatewaySession, dialerSession *Session
	t.Cleanup(func() {
		cancel()
		if dialerSession != nil {
			_ = dialerSession.Close()
		}
		if gatewaySession != nil {
			_ = gatewaySession.Close()
		}
		_ = listener.Close()
	})

	openHandler := func(_ context.Context, typ Type, payload []byte) (net.Conn, error) {
		if typ != TypeOpenDirect && typ != TypeOpenReverse {
			return nil, fmt.Errorf("unexpected open type %v", typ)
		}
		remote, testSide := net.Pipe()
		select {
		case targets <- acceptedTarget{name: string(payload), conn: testSide}:
			return remote, nil
		default:
			_ = remote.Close()
			_ = testSide.Close()
			return nil, fmt.Errorf("test target channel is full")
		}
	}

	type sessionResult struct {
		session *Session
		err     error
	}
	gatewayReady := make(chan sessionResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			gatewayReady <- sessionResult{err: err}
			return
		}
		tc, ok := conn.(*tls.Conn)
		if !ok {
			_ = conn.Close()
			gatewayReady <- sessionResult{err: fmt.Errorf("accepted connection is not TLS")}
			return
		}
		handshakeCtx, handshakeCancel := context.WithTimeout(ctx, 3*time.Second)
		err = tc.HandshakeContext(handshakeCtx)
		handshakeCancel()
		if err == nil {
			state := tc.ConnectionState()
			err = tunnel.VerifyPeerCommonName(state, "dialer.test")
			if err == nil && (state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768) {
				err = fmt.Errorf("unexpected TLS negotiation: version=%x group=%v", state.Version, state.CurveID)
			}
		}
		if err != nil {
			_ = tc.Close()
			gatewayReady <- sessionResult{err: err}
			return
		}
		session, err := NewSession(ctx, tc, SessionOptions{
			Initiator: false, MaxStreams: 8, KeepAliveInterval: time.Hour,
			OnOpen: openHandler,
		})
		if err != nil {
			_ = tc.Close()
			gatewayReady <- sessionResult{err: err}
			return
		}
		gatewayReady <- sessionResult{session: session}
		<-session.Done()
	}()

	rawClient, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := tls.Client(rawClient, fixture.clientConfig(fixture.clientCert, "gateway.test"))
	handshakeCtx, handshakeCancel := context.WithTimeout(ctx, 3*time.Second)
	err = clientTLS.HandshakeContext(handshakeCtx)
	handshakeCancel()
	if err != nil {
		_ = clientTLS.Close()
		t.Fatalf("TLS 1.3 hybrid mTLS handshake failed: %v", err)
	}
	state := clientTLS.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("unexpected TLS negotiation: version=%x group=%v", state.Version, state.CurveID)
	}
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != "gateway.test" {
		t.Fatal("client did not receive the expected Gateway certificate identity")
	}
	dialerSession, err = NewSession(ctx, clientTLS, SessionOptions{
		Initiator: true, MaxStreams: 8, KeepAliveInterval: time.Hour,
		OnOpen: openHandler,
	})
	if err != nil {
		_ = clientTLS.Close()
		t.Fatalf("create Dialer session over TLS: %v", err)
	}
	select {
	case result := <-gatewayReady:
		if result.err != nil {
			t.Fatalf("create Gateway session over TLS: %v", result.err)
		}
		gatewaySession = result.session
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Gateway TLS session")
	}
	return dialerSession, gatewaySession, targets
}

func exchangeTLSStream(stream *Stream, target net.Conn, request, response string) error {
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	_ = target.SetDeadline(time.Now().Add(3 * time.Second))

	writeDone := make(chan error, 1)
	go func() {
		_, err := stream.Write([]byte(request))
		writeDone <- err
	}()
	gotRequest := make([]byte, len(request))
	if _, err := io.ReadFull(target, gotRequest); err != nil {
		return fmt.Errorf("read request at target: %w", err)
	}
	if !bytes.Equal(gotRequest, []byte(request)) {
		return fmt.Errorf("target got %q, want %q", gotRequest, request)
	}
	if err := <-writeDone; err != nil {
		return fmt.Errorf("write request to stream: %w", err)
	}

	responseDone := make(chan error, 1)
	go func() {
		_, err := target.Write([]byte(response))
		responseDone <- err
	}()
	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(stream, gotResponse); err != nil {
		return fmt.Errorf("read response from stream: %w", err)
	}
	if !bytes.Equal(gotResponse, []byte(response)) {
		return fmt.Errorf("stream got %q, want %q", gotResponse, response)
	}
	if err := <-responseDone; err != nil {
		return fmt.Errorf("write response at target: %w", err)
	}
	return nil
}

func performTLSIdentityProbe(t *testing.T, fixture *tlsMuxFixture, clientCert tls.Certificate, serverName, expectedClientCN string) (clientErr, serverErr error) {
	t.Helper()
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(rawListener, fixture.serverConfig())
	t.Cleanup(func() { _ = listener.Close() })

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		tc := conn.(*tls.Conn)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err = tc.HandshakeContext(ctx)
		if err == nil {
			err = tunnel.VerifyPeerCommonName(tc.ConnectionState(), expectedClientCN)
		}
		_ = tc.Close()
		serverDone <- err
	}()

	rawClient, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(rawClient, fixture.clientConfig(clientCert, serverName))
	clientCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	clientErr = client.HandshakeContext(clientCtx)
	cancel()
	defer client.Close()

	select {
	case serverErr = <-serverDone:
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for TLS peer identity result")
	}
	return clientErr, serverErr
}

func TestTLS13MTLSRejectsWrongClientCommonName(t *testing.T) {
	fixture := newTLSMuxFixture(t)
	_, serverErr := performTLSIdentityProbe(t, fixture, fixture.wrongClientCert, "gateway.test", "dialer.test")
	if serverErr == nil {
		t.Fatal("Gateway accepted a client certificate with the wrong Common Name")
	}
}

func TestTLS13MTLSRejectsWrongServerSAN(t *testing.T) {
	fixture := newTLSMuxFixture(t)
	clientErr, _ := performTLSIdentityProbe(t, fixture, fixture.clientCert, "wrong-gateway.test", "dialer.test")
	if clientErr == nil {
		t.Fatal("Dialer accepted a Gateway certificate with the wrong DNS SAN")
	}
}
