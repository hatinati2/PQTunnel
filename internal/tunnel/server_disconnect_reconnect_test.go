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

	"github.com/hatinati2/PQTunnel/internal/prefixset"
)

// TestServerAdminDisconnectAllowsDialerReconnect verifies a complete loopback
// client/handler lifecycle: the listener drops a peer session, the handler
// releases its identity and route slot, and the dialer can reconnect with the
// same certificate identity. No TUN routes or host firewall state are changed.
func TestServerAdminDisconnectAllowsDialerReconnect(t *testing.T) {
	ca, caKey, roots := createPolicyTestCA(t)
	serverCert := createPolicyTestCert(t, ca, caKey, "gateway", "gateway.example.test", x509.ExtKeyUsageServerAuth)
	clientCert := createPolicyTestCert(t, ca, caKey, "iran", "", x509.ExtKeyUsageClientAuth)

	peerPrefixes, err := prefixset.ParseCSV("192.0.2.0/24,2001:db8:2::/64")
	if err != nil {
		t.Fatal(err)
	}
	localPrefixes, err := prefixset.ParseCSV("10.66.0.0/24,2001:db8:10::/64")
	if err != nil {
		t.Fatal(err)
	}

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(rawListener, ServerTLSConfig(serverCert, roots))

	serverDev := newBlockingTestDevice()
	serverCtx, cancelServer := context.WithCancel(context.Background())
	clientCtx, cancelClient := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancelClient()
		cancelServer()
		_ = listener.Close()
		_ = serverDev.Close()
	})

	s := &Server{
		ListenAddress: listener.Addr().String(),
		TLSConfig:     ServerTLSConfig(serverCert, roots),
		Device:        serverDev,
		MaxClients:    1,
		PeerPrefixes:  peerPrefixes,
		LocalPrefixes: localPrefixes,
		PeerIdentity:  "iran",
		clients:       make(map[string]*peer),
	}
	acceptDone := make(chan error, 1)
	go func() {
		acceptDone <- s.acceptLoop(serverCtx, listener, make(chan struct{}, 1))
	}()

	clientTLS := StrictTLS13Config()
	clientTLS.RootCAs = roots
	clientTLS.ServerName = "gateway.example.test"
	clientTLS.Certificates = []tls.Certificate{clientCert}
	clientDev := newBlockingTestDevice()
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- RunClient(clientCtx, clientDev, ClientConfig{
			ServerAddress:  listener.Addr().String(),
			ServerName:     "gateway.example.test",
			LocalPrefixes:  peerPrefixes,
			RemotePrefixes: localPrefixes,
			TLSConfig:      clientTLS,
		})
	}()

	waitForPeerPresence(t, s, "iran", true, 5*time.Second)
	if !s.DisconnectPeer("iran") {
		t.Fatal("DisconnectPeer did not find the active authenticated peer")
	}
	waitForPeerPresence(t, s, "iran", false, 3*time.Second)
	// The dialer should retry after the active session is closed and re-register
	// the same identity instead of being blocked by a stale peer-map entry.
	waitForPeerPresence(t, s, "iran", true, 6*time.Second)

	cancelClient()
	cancelServer()
	_ = listener.Close()
	_ = serverDev.Close()

	select {
	case err := <-clientDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RunClient returned %v after cancellation, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dialer did not stop after cancellation")
	}
	select {
	case err := <-acceptDone:
		if err != nil {
			t.Fatalf("listener accept loop returned %v after cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener accept loop did not stop after cancellation")
	}
	waitForPeerPresence(t, s, "iran", false, 2*time.Second)
}

func waitForPeerPresence(t *testing.T, s *Server, identity string, wantPresent bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		found := false
		for _, peer := range s.AdminSnapshot().Peers {
			if peer.Identity == identity {
				found = true
				break
			}
		}
		if found == wantPresent {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer %q presence = %v, want %v within %s", identity, found, wantPresent, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
