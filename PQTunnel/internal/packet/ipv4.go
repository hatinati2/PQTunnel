package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ErrNotIPv4 = errors.New("IPv4 packet required")
var ErrMalformed = errors.New("malformed IPv4 packet")

// IPv4 returns a view of a complete IPv4 packet. IPv6 is deliberately rejected
// in this MVP so it can be dropped instead of escaping outside the tunnel.
func IPv4(p []byte) (src, dst netip.Addr, packet []byte, err error) {
	if len(p) < 1 || p[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, nil, ErrNotIPv4
	}
	if len(p) < 20 {
		return netip.Addr{}, netip.Addr{}, nil, ErrMalformed
	}
	hlen := int(p[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if hlen < 20 || hlen > len(p) || total < hlen || total > len(p) {
		return netip.Addr{}, netip.Addr{}, nil, ErrMalformed
	}
	var s, d [4]byte
	copy(s[:], p[12:16])
	copy(d[:], p[16:20])
	return netip.AddrFrom4(s), netip.AddrFrom4(d), p[:total], nil
}
