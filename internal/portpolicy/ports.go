// Package portpolicy parses protocol/destination-port allowlists for PQTunnel.
// It intentionally fails closed for fragmented packets when a port policy is active,
// because later fragments do not contain transport ports and reassembly is not done here.
package portpolicy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/hatinati2/PQTunnel/internal/packet"
)

const (
	protoTCP = 6
	protoUDP = 17
)

var (
	ErrBadRule       = errors.New("invalid destination-port rule")
	ErrNoPortHeader  = errors.New("packet has no supported TCP/UDP destination port")
	ErrFragmented    = errors.New("fragmented packet cannot be checked by destination-port policy")
	ErrMalformedIPv6 = errors.New("malformed IPv6 extension header")
)

type portRange struct{ first, last uint16 }

// RuleSet is an allowlist. A zero-value or empty RuleSet means filtering is disabled
// for backwards compatibility. Once one rule is configured, only listed TCP/UDP
// destination ports pass.
type RuleSet struct{ ranges map[uint8][]portRange }

// ParseCSV accepts rules like "tcp:443,udp:53,tcp:10000-10100".
// Port zero, unknown protocols, empty items, and malformed ranges are rejected.
func ParseCSV(value string) (RuleSet, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return RuleSet{}, nil
	}
	out := RuleSet{ranges: make(map[uint8][]portRange)}
	for _, raw := range strings.Split(value, ",") {
		item := strings.TrimSpace(raw)
		parts := strings.Split(item, ":")
		if len(parts) != 2 {
			return RuleSet{}, fmt.Errorf("%w %q: expected proto:port or proto:first-last", ErrBadRule, item)
		}
		var proto uint8
		switch strings.ToLower(strings.TrimSpace(parts[0])) {
		case "tcp":
			proto = protoTCP
		case "udp":
			proto = protoUDP
		default:
			return RuleSet{}, fmt.Errorf("%w %q: protocol must be tcp or udp", ErrBadRule, item)
		}
		portSpec := strings.TrimSpace(parts[1])
		bounds := strings.Split(portSpec, "-")
		if len(bounds) > 2 {
			return RuleSet{}, fmt.Errorf("%w %q", ErrBadRule, item)
		}
		first, err := parsePort(bounds[0])
		if err != nil {
			return RuleSet{}, fmt.Errorf("%w %q: %v", ErrBadRule, item, err)
		}
		last := first
		if len(bounds) == 2 {
			last, err = parsePort(bounds[1])
			if err != nil {
				return RuleSet{}, fmt.Errorf("%w %q: %v", ErrBadRule, item, err)
			}
		}
		if first > last {
			return RuleSet{}, fmt.Errorf("%w %q: first port exceeds last port", ErrBadRule, item)
		}
		out.ranges[proto] = append(out.ranges[proto], portRange{first, last})
	}
	for proto, ranges := range out.ranges {
		out.ranges[proto] = coalesce(ranges)
	}
	return out, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port must be an integer from 1 to 65535")
	}
	return uint16(n), nil
}

func coalesce(in []portRange) []portRange {
	if len(in) < 2 {
		return in
	}
	// Port ranges are small; insertion sort avoids introducing another dependency.
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j].first < in[j-1].first; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
	out := make([]portRange, 0, len(in))
	for _, r := range in {
		if len(out) == 0 || uint32(r.first) > uint32(out[len(out)-1].last)+1 {
			out = append(out, r)
			continue
		}
		if r.last > out[len(out)-1].last {
			out[len(out)-1].last = r.last
		}
	}
	return out
}

func (r RuleSet) Empty() bool { return len(r.ranges) == 0 }

// AllowsPacket returns true when the packet's destination transport port matches
// this allowlist. Unsupported protocols and fragments are denied when filtering is active.
func (r RuleSet) AllowsPacket(p []byte) bool {
	if r.Empty() {
		return true
	}
	proto, port, err := DestinationPort(p)
	if err != nil {
		return false
	}
	for _, allowed := range r.ranges[proto] {
		if port >= allowed.first && port <= allowed.last {
			return true
		}
	}
	return false
}

// DestinationPort extracts the IP transport protocol and TCP/UDP destination port.
// IPv4 fragmentation and IPv6 fragment headers are rejected; IPv6 hop-by-hop,
// routing, destination-options and AH extension headers are walked with bounds checks.
func DestinationPort(p []byte) (protocol uint8, dstPort uint16, err error) {
	_, _, normalized, err := packet.IP(p)
	if err != nil {
		return 0, 0, err
	}
	p = normalized
	version := p[0] >> 4
	var offset int
	if version == 4 {
		headerLen := int(p[0]&0x0f) * 4
		frag := binary.BigEndian.Uint16(p[6:8])
		if frag&0x3fff != 0 {
			return 0, 0, ErrFragmented
		}
		protocol = p[9]
		offset = headerLen
	} else {
		next := p[6]
		offset = 40
		for count := 0; count < 12; count++ {
			switch next {
			case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
				if offset+2 > len(p) {
					return 0, 0, ErrMalformedIPv6
				}
				length := (int(p[offset+1]) + 1) * 8
				if length < 8 || offset+length > len(p) {
					return 0, 0, ErrMalformedIPv6
				}
				next = p[offset]
				offset += length
			case 51: // Authentication Header
				if offset+2 > len(p) {
					return 0, 0, ErrMalformedIPv6
				}
				length := (int(p[offset+1]) + 2) * 4
				if length < 8 || offset+length > len(p) {
					return 0, 0, ErrMalformedIPv6
				}
				next = p[offset]
				offset += length
			case 44: // Fragment header: fail closed without fragment reassembly.
				return 0, 0, ErrFragmented
			case 50, 59: // ESP is encrypted; No Next Header has no transport port.
				return 0, 0, ErrNoPortHeader
			default:
				protocol = next
				goto transport
			}
		}
		return 0, 0, ErrMalformedIPv6
	}

transport:
	if protocol != protoTCP && protocol != protoUDP {
		return protocol, 0, ErrNoPortHeader
	}
	if offset < 0 || offset+4 > len(p) {
		return protocol, 0, packet.ErrMalformed
	}
	return protocol, binary.BigEndian.Uint16(p[offset+2 : offset+4]), nil
}
