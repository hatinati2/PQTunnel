package packet

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestIPv4(t *testing.T) {
	p := make([]byte, 20)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], 20)
	copy(p[12:16], []byte{10, 66, 0, 2})
	copy(p[16:20], []byte{1, 1, 1, 1})
	s, d, got, err := IPv4(p)
	if err != nil {
		t.Fatal(err)
	}
	if s != netip.MustParseAddr("10.66.0.2") || d != netip.MustParseAddr("1.1.1.1") || len(got) != 20 {
		t.Fatalf("unexpected packet view: %v %v %d", s, d, len(got))
	}
}

func TestRejectIPv6(t *testing.T) {
	p := []byte{0x60, 0, 0, 0, 0, 0, 0, 64}
	if _, _, _, err := IPv4(p); err != ErrNotIPv4 {
		t.Fatalf("expected ErrNotIPv4, got %v", err)
	}
}

func TestRejectMalformed(t *testing.T) {
	p := make([]byte, 20)
	p[0] = 0x46 // header length 24, longer than packet
	binary.BigEndian.PutUint16(p[2:4], 20)
	if _, _, _, err := IPv4(p); err != ErrMalformed {
		t.Fatalf("expected ErrMalformed, got %v", err)
	}
}
