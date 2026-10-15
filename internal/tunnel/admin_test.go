package tunnel

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAdminSnapshotRedactsPeerNetworksAndSortsIdentities(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	peerPrefix := netip.MustParsePrefix("192.0.2.0/24")
	localPrefix := netip.MustParsePrefix("198.51.100.0/24")
	s := &Server{
		ListenAddress: "127.0.0.1:8443",
		MaxClients:    8,
		PeerIdentity:  "site-peer",
		PeerPrefixes:  []netip.Prefix{peerPrefix},
		LocalPrefixes: []netip.Prefix{localPrefix},
		running:       true,
		startedAt:     time.Now().Add(-20 * time.Second),
		clients: map[string]*peer{
			"z-peer": {identity: "z-peer", prefixes: []netip.Prefix{peerPrefix}, conn: left, connectedAt: time.Now().Add(-9 * time.Second)},
			"a-peer": {identity: "a-peer", prefixes: []netip.Prefix{peerPrefix}, conn: left, connectedAt: time.Now().Add(-4 * time.Second)},
		},
	}

	got := s.AdminSnapshot()
	if !got.Running || got.Uptime == "" || got.MaxClients != 8 || !got.SiteToSite {
		t.Fatalf("unexpected server snapshot: %#v", got)
	}
	if got.PeerPrefixCount != 1 || got.LocalPrefixCount != 1 || len(got.Peers) != 2 {
		t.Fatalf("unexpected counts: %#v", got)
	}
	if got.Peers[0].Identity != "a-peer" || got.Peers[1].Identity != "z-peer" {
		t.Fatalf("peer list is not sorted: %#v", got.Peers)
	}
	if got.Peers[0].ConnectedFor == "" || got.Peers[1].ConnectedFor == "" {
		t.Fatalf("connected duration missing: %#v", got.Peers)
	}
	rendered := fmt.Sprintf("%+v", got)
	for _, secretValue := range []string{"192.0.2.0/24", "198.51.100.0/24"} {
		if strings.Contains(rendered, secretValue) {
			t.Fatalf("snapshot exposed a configured network prefix: %s", secretValue)
		}
	}
}

func TestDisconnectPeerClosesOnlyRequestedConnection(t *testing.T) {
	target, targetRemote := net.Pipe()
	other, otherRemote := net.Pipe()
	defer targetRemote.Close()
	defer other.Close()
	defer otherRemote.Close()

	s := &Server{clients: map[string]*peer{
		"target": {identity: "target", conn: target},
		"other":  {identity: "other", conn: other},
	}}
	if !s.DisconnectPeer("target") {
		t.Fatal("expected the target peer to be found")
	}
	if s.DisconnectPeer("missing") {
		t.Fatal("unknown peer must not be reported as disconnected")
	}
	_ = targetRemote.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := targetRemote.Read(make([]byte, 1)); err == nil {
		t.Fatal("target connection remained open")
	}
	_ = otherRemote.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := otherRemote.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("unselected peer connection was unexpectedly closed or errored: %v", err)
	}
}
