package main

import (
	"net"
	"net/netip"
	"testing"

	"github.com/hatinati2/PQTunnel/internal/prefixset"
)

func TestClientAdminControllerReportsAndDisconnectsCurrentTransport(t *testing.T) {
	local, err := prefixset.ParseCSV("10.66.0.2/32,192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	remote, err := prefixset.ParseCSV("10.66.0.1/32,198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	controller := newClientAdminController("gateway.example.test:8443", "gateway.example.test", local, remote)

	before := controller.AdminSnapshot()
	if before.TransportConnected || len(before.Peers) != 0 {
		t.Fatalf("new dialer should not claim a live peer: %#v", before)
	}

	tunnelConn, peerConn := net.Pipe()
	defer peerConn.Close()
	controller.OnConnected(tunnelConn)

	connected := controller.AdminSnapshot()
	if !connected.TransportConnected {
		t.Fatal("controller did not report active transport")
	}
	if len(connected.Peers) != 1 || connected.Peers[0].Identity != "gateway.example.test" {
		t.Fatalf("unexpected peer snapshot: %#v", connected.Peers)
	}
	if connected.LocalPrefixCount != 2 || connected.PeerPrefixCount != 2 {
		t.Fatalf("unexpected prefix counts: local=%d remote=%d", connected.LocalPrefixCount, connected.PeerPrefixCount)
	}

	if !controller.DisconnectPeer("gateway.example.test") {
		t.Fatal("disconnect of current peer should succeed")
	}
	buf := make([]byte, 1)
	if _, err := peerConn.Read(buf); err == nil {
		t.Fatal("peer transport did not close after disconnect")
	}
	controller.OnDisconnected(tunnelConn)
	after := controller.AdminSnapshot()
	if after.TransportConnected || len(after.Peers) != 0 {
		t.Fatalf("controller retained closed transport: %#v", after)
	}
	if controller.DisconnectPeer("gateway.example.test") {
		t.Fatal("disconnect should fail when no peer is connected")
	}
}

func TestClientAdminControllerDoesNotClearANewerTransport(t *testing.T) {
	controller := newClientAdminController("gateway.example.test:8443", "gateway.example.test", []netip.Prefix{
		netip.MustParsePrefix("10.66.0.2/32"),
	}, []netip.Prefix{
		netip.MustParsePrefix("10.66.0.1/32"),
	})
	oldConn, oldPeer := net.Pipe()
	defer oldPeer.Close()
	newConn, newPeer := net.Pipe()
	defer newPeer.Close()
	controller.OnConnected(oldConn)
	controller.OnConnected(newConn)
	controller.OnDisconnected(oldConn)
	if !controller.AdminSnapshot().TransportConnected {
		t.Fatal("late disconnect callback cleared the newer transport")
	}
	controller.OnDisconnected(newConn)
	_ = oldConn.Close()
	_ = newConn.Close()
}
