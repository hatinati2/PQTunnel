package tunnel

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/hatinati2/PQTunnel/internal/prefixset"
	"github.com/hatinati2/PQTunnel/internal/protocol"
)

type queuedRouteTestDevice struct {
	packets chan []byte
	closed  chan struct{}
	once    sync.Once
}

func (d *queuedRouteTestDevice) Read(buf []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	case p := <-d.packets:
		if len(p) > len(buf) {
			return 0, io.ErrShortBuffer
		}
		return copy(buf, p), nil
	}
}

func (d *queuedRouteTestDevice) Write(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(p), nil
	}
}

func (d *queuedRouteTestDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func routePolicyIPv6Packet(src, dst string) []byte {
	srcBytes := netip.MustParseAddr(src).As16()
	dstBytes := netip.MustParseAddr(dst).As16()
	p := make([]byte, 40)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], 0) // no payload
	p[6] = 59                               // no next header
	p[7] = 64
	copy(p[8:24], srcBytes[:])
	copy(p[24:40], dstBytes[:])
	return p
}

func TestRoutePacketsDropsSourcesOutsideConfiguredLocalPrefixes(t *testing.T) {
	localPrefixes, err := prefixset.ParseCSV("198.51.100.0/24,2001:db8:1::/64")
	if err != nil {
		t.Fatal(err)
	}
	peerPrefixes, err := prefixset.ParseCSV("192.0.2.0/24,2001:db8:2::/64")
	if err != nil {
		t.Fatal(err)
	}

	spoofedIPv4 := policyTestIPv4Packet("203.0.113.7", "192.0.2.8")
	allowedIPv4 := policyTestIPv4Packet("198.51.100.7", "192.0.2.8")
	spoofedIPv6 := routePolicyIPv6Packet("2001:db8:99::7", "2001:db8:2::8")
	allowedIPv6 := routePolicyIPv6Packet("2001:db8:1::7", "2001:db8:2::8")

	dev := &queuedRouteTestDevice{
		packets: make(chan []byte, 4),
		closed:  make(chan struct{}),
	}
	for _, p := range [][]byte{spoofedIPv4, allowedIPv4, spoofedIPv6, allowedIPv6} {
		dev.packets <- p
	}

	tunnelConn, peerConn := net.Pipe()
	t.Cleanup(func() {
		_ = dev.Close()
		_ = tunnelConn.Close()
		_ = peerConn.Close()
	})
	s := &Server{
		Device:        dev,
		LocalPrefixes: localPrefixes,
		clients: map[string]*peer{
			"iran": {
				identity: "iran",
				prefixes: peerPrefixes,
				conn:     tunnelConn,
			},
		},
	}

	done := make(chan error, 1)
	go func() { done <- s.routePackets(context.Background()) }()
	if err := peerConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}

	for i, want := range [][]byte{allowedIPv4, allowedIPv6} {
		got, err := protocol.ReadFrame(peerConn)
		if err != nil {
			t.Fatalf("read forwarded frame %d: %v", i+1, err)
		}
		if string(got) != string(want) {
			t.Fatalf("forwarded frame %d came from an unauthorized source: got %v, want %v", i+1, got, want)
		}
	}

	_ = dev.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("routePackets returned nil after the test TUN device closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("routePackets did not stop after the test TUN device closed")
	}
}
