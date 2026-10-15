package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestRunClientReconnectsAfterPeerDisconnect exercises the dialer's
// server-to-server transport lifecycle: after an authenticated listener
// closes a session, the dialer should establish a fresh TLS session.
func TestRunClientReconnectsAfterPeerDisconnect(t *testing.T) {
	ca, caKey, roots := createPolicyTestCA(t)
	serverCert := createPolicyTestCert(t, ca, caKey, "gateway", "gateway.example.test", x509.ExtKeyUsageServerAuth)
	clientCert := createPolicyTestCert(t, ca, caKey, "iran", "", x509.ExtKeyUsageClientAuth)

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(rawListener, ServerTLSConfig(serverCert, roots))
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan error, 2)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for i := 0; i < 2; i++ {
			conn, err := listener.Accept()
			if err != nil {
				accepted <- err
				return
			}
			tc, ok := conn.(*tls.Conn)
			if !ok {
				_ = conn.Close()
				accepted <- errors.New("listener returned a non-TLS connection")
				return
			}
			_ = tc.SetDeadline(time.Now().Add(4 * time.Second))
			if err := tc.Handshake(); err != nil {
				_ = tc.Close()
				accepted <- err
				return
			}
			accepted <- nil
			// Simulate the remote listener/admin disconnecting this session.
			_ = tc.Close()
		}
	}()

	clientTLS := StrictTLS13Config()
	clientTLS.RootCAs = roots
	clientTLS.ServerName = "gateway.example.test"
	clientTLS.Certificates = []tls.Certificate{clientCert}
	dev := newBlockingTestDevice()
	ctx, cancel := context.WithCancel(context.Background())
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- RunClient(ctx, dev, ClientConfig{
			ServerAddress: listener.Addr().String(),
			ServerName:    "gateway.example.test",
			LocalIP:       netip.MustParseAddr("10.0.0.2"),
			TLSConfig:     clientTLS,
		})
	}()

	timeout := time.NewTimer(8 * time.Second)
	defer timeout.Stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-accepted:
			if err != nil {
				cancel()
				t.Fatalf("TLS session %d failed: %v", i+1, err)
			}
		case err := <-clientDone:
			cancel()
			t.Fatalf("dialer exited before reconnecting (session %d): %v", i+1, err)
		case <-timeout.C:
			cancel()
			t.Fatalf("dialer established only %d of 2 expected TLS sessions after peer disconnect", i)
		}
	}

	cancel()
	select {
	case err := <-clientDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RunClient returned %v after cancellation, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunClient did not stop after cancellation")
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("test listener did not finish after handling two sessions")
	}
}
