package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/hatinati2/PQTunnel/internal/prefixset"
	"github.com/hatinati2/PQTunnel/internal/protocol"
)

type policyCaptureWriter struct {
	mu sync.Mutex
	packets [][]byte
}

func (w *policyCaptureWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.packets = append(w.packets, append([]byte(nil), p...))
	return len(p), nil
}

func (w *policyCaptureWriter) snapshot() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([][]byte, len(w.packets))
	for i := range w.packets {
		out[i] = append([]byte(nil), w.packets[i]...)
	}
	return out
}

func policyIPv4Packet(src, dst string) []byte {
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

func TestReadPacketsEnforcesRemoteSourceAndLocalDestinationPrefixes(t *testing.T) {
	remote, err := prefixset.ParseCSV("192.0.2.0/24")
	if err != nil { t.Fatal(err) }
	local, err := prefixset.ParseCSV("10.66.0.0/24")
	if err != nil { t.Fatal(err) }

	clientConn, serverConn := net.Pipe()
	dev := &policyCaptureWriter{}
	done := make(chan error, 1)
	go func() { done <- readPackets(context.Background(), clientConn, dev, local, remote) }()

	inputs := [][]byte{
		policyIPv4Packet("203.0.113.7", "10.66.0.2"),
		policyIPv4Packet("192.0.2.7", "198.51.100.9"),
		policyIPv4Packet("192.0.2.8", "10.66.0.2"),
	}
	for _, p := range inputs {
		if err := protocol.WriteFrame(serverConn, p); err != nil {
			t.Fatalf("write test frame: %v", err)
		}
	}
	_ = serverConn.Close()
	defer clientConn.Close()

	err = <-done
	if !errors.Is(err, io.EOF) {
		t.Fatalf("readPackets error = %v, want EOF", err)
	}
	got := dev.snapshot()
	if len(got) != 1 {
		t.Fatalf("device received %d packets, want exactly 1", len(got))
	}
	if string(got[0]) != string(inputs[2]) {
		t.Fatalf("device received unexpected packet: got %v, want %v", got[0], inputs[2])
	}
}
