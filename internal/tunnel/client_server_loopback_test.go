package tunnel

import (
	"context"
	"encoding/binary"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/hatinati2/PQTunnel/internal/portpolicy"
	"github.com/hatinati2/PQTunnel/internal/prefixset"
	"github.com/hatinati2/PQTunnel/internal/protocol"
)

type loopbackTunnelDevice struct {
	reads chan []byte
	writes chan []byte
	closed chan struct{}
	once sync.Once
}

func newLoopbackTunnelDevice(packets ...[]byte) *loopbackTunnelDevice {
	d := &loopbackTunnelDevice{
		reads: make(chan []byte, len(packets)),
		writes: make(chan []byte, 8),
		closed: make(chan struct{}),
	}
	for _, p := range packets { d.reads <- append([]byte(nil), p...) }
	return d
}

func (d *loopbackTunnelDevice) Read(buf []byte) (int, error) {
	select {
	case p := <-d.reads:
		if len(p) > len(buf) { return 0, io.ErrShortBuffer }
		return copy(buf, p), nil
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}
func (d *loopbackTunnelDevice) Write(p []byte) (int, error) {
	select {
	case <-d.closed: return 0, io.ErrClosedPipe
	default:
	}
	select {
	case d.writes <- append([]byte(nil), p...):
		return len(p), nil
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}
func (d *loopbackTunnelDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func e2eTCPPacket(src, dst string, srcPort, dstPort uint16) []byte {
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	p := make([]byte, 40)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 6
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[20:22], srcPort)
	binary.BigEndian.PutUint16(p[22:24], dstPort)
	p[32] = 0x50
	return p
}

func e2eIPv6TCPPacket(src, dst string, srcPort, dstPort uint16) []byte {
	s := netip.MustParseAddr(src).As16()
	d := netip.MustParseAddr(dst).As16()
	p := make([]byte, 60)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], 20)
	p[6] = 6
	p[7] = 64
	copy(p[8:24], s[:])
	copy(p[24:40], d[:])
	binary.BigEndian.PutUint16(p[40:42], srcPort)
	binary.BigEndian.PutUint16(p[42:44], dstPort)
	p[52] = 0x50
	return p
}

type loopbackServerResult struct {
	packets [][]byte
	extra []byte
	err error
}

func TestRunClientLoopbackTLSFiltersOutboundAndInboundPackets(t *testing.T) {
	ca, caKey, roots := createPolicyTestCA(t)
	serverCert := createPolicyTestCert(t, ca, caKey, "gateway", "gateway.example.test", extKeyUsageServerAuth())
	clientCert := createPolicyTestCert(t, ca, caKey, "iran", "", extKeyUsageClientAuth())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer listener.Close()

	local, err := prefixset.ParseCSV("10.66.0.0/24,fd42:7061:7475::/64")
	if err != nil { t.Fatal(err) }
	remote, err := prefixset.ParseCSV("192.0.2.0/24,2001:db8:2::/64")
	if err != nil { t.Fatal(err) }
	ports, err := portpolicy.ParseCSV("tcp:443")
	if err != nil { t.Fatal(err) }

	inputs := [][]byte{
		e2eTCPPacket("203.0.113.7", "192.0.2.8", 50000, 443), // source outside local prefixes
		e2eTCPPacket("10.66.0.2", "198.51.100.8", 50001, 443), // destination outside remote prefixes
		e2eTCPPacket("10.66.0.2", "192.0.2.8", 50002, 22), // destination port denied
		e2eTCPPacket("10.66.0.2", "192.0.2.8", 50003, 443), // allowed IPv4
		e2eIPv6TCPPacket("2001:db8:99::7", "2001:db8:2::8", 50004, 443), // IPv6 source outside local prefixes
		e2eIPv6TCPPacket("fd42:7061:7475::2", "2001:db8:99::8", 50005, 443), // IPv6 destination outside remote prefixes
		e2eIPv6TCPPacket("fd42:7061:7475::2", "2001:db8:2::8", 50006, 22), // IPv6 destination port denied
		e2eIPv6TCPPacket("fd42:7061:7475::2", "2001:db8:2::8", 50007, 443), // allowed IPv6
	}
	dev := newLoopbackTunnelDevice(inputs...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientCfg := StrictTLS13Config()
	clientCfg.RootCAs = roots
	clientCfg.ServerName = "gateway.example.test"
	clientCfg.Certificates = []tls.Certificate{clientCert}
	cfg := ClientConfig{
		ServerAddress: listener.Addr().String(),
		ServerName: "gateway.example.test",
		LocalPrefixes: local,
		RemotePrefixes: remote,
		AllowedDstPorts: ports,
		TLSConfig: clientCfg,
	}
	clientDone := make(chan error, 1)
	go func() { clientDone <- RunClient(ctx, dev, cfg) }()

	serverResult := make(chan loopbackServerResult, 1)
	serverDone := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil { serverDone <- err; return }
		defer raw.Close()
		tlsConn := tls.Server(raw, ServerTLSConfig(serverCert, roots))
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil { serverDone <- err; return }
		got4, err := protocol.ReadFrame(tlsConn)
		if err != nil { serverDone <- err; return }
		got6, err := protocol.ReadFrame(tlsConn)
		if err != nil { serverDone <- err; return }
		_ = tlsConn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		extra, extraErr := protocol.ReadFrame(tlsConn)
		_ = tlsConn.SetReadDeadline(time.Time{})
		if extraErr != nil {
			if ne, ok := extraErr.(net.Error); !ok || !ne.Timeout() {
				serverResult <- loopbackServerResult{err: extraErr}
				serverDone <- extraErr
				return
			}
		}
		response4 := e2eTCPPacket("192.0.2.9", "10.66.0.2", 443, 50003)
		response6 := e2eIPv6TCPPacket("2001:db8:2::9", "fd42:7061:7475::2", 443, 50007)
		for _, response := range [][]byte{response4, response6} {
			if err := protocol.WriteFrame(tlsConn, response); err != nil {
				serverResult <- loopbackServerResult{err: err}
				serverDone <- err
				return
			}
		}
		if extraErr == nil {
			serverResult <- loopbackServerResult{packets: [][]byte{got4, got6}, extra: extra}
		} else {
			serverResult <- loopbackServerResult{packets: [][]byte{got4, got6}}
		}
		<-ctx.Done()
		serverDone <- nil
	}()

	select {
	case result := <-serverResult:
		if result.err != nil { t.Fatalf("loopback TLS server: %v", result.err) }
		if len(result.packets) != 2 {
			t.Fatalf("server received %d allowed packets, want one per IP family", len(result.packets))
		}
		if string(result.packets[0]) != string(inputs[3]) {
			t.Fatalf("outbound IPv4 packet = %v, want %v", result.packets[0], inputs[3])
		}
		if string(result.packets[1]) != string(inputs[7]) {
			t.Fatalf("outbound IPv6 packet = %v, want %v", result.packets[1], inputs[7])
		}
		if result.extra != nil {
			t.Fatalf("client sent an extra disallowed packet: %v", result.extra)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("client did not establish TLS and send the allowed packet")
	}

	select {
	for _, want := range [][]byte{
		e2eTCPPacket("192.0.2.9", "10.66.0.2", 443, 50003),
		e2eIPv6TCPPacket("2001:db8:2::9", "fd42:7061:7475::2", 443, 50007),
	} {
		select {
		case got := <-dev.writes:
			if string(got) != string(want) { t.Fatalf("inbound packet = %v, want %v", got, want) }
		case <-time.After(3 * time.Second):
			t.Fatal("client did not deliver an allowed inbound packet to the device")
		}
	}

	cancel()
	select {
	case err := <-clientDone:
		if !errors.Is(err, context.Canceled) { t.Fatalf("RunClient returned %v, want context.Canceled", err) }
	case <-time.After(3 * time.Second):
		t.Fatal("RunClient did not stop after cancellation")
	}
	select {
	case err := <-serverDone:
		if err != nil { t.Fatalf("loopback TLS server returned: %v", err) }
	case <-time.After(3 * time.Second):
		t.Fatal("test server did not shut down")
	}
}

func extKeyUsageServerAuth() x509.ExtKeyUsage { return x509.ExtKeyUsageServerAuth }
func extKeyUsageClientAuth() x509.ExtKeyUsage { return x509.ExtKeyUsageClientAuth }
