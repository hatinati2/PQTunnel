package portpolicy

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func ipv4Packet(proto byte, src, dst string, sport, dport uint16, frag uint16) []byte {
	p := make([]byte, 20+8)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[6:8], frag)
	p[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	return p
}

func ipv6Packet(proto byte, src, dst string, sport, dport uint16) []byte {
	p := make([]byte, 40+8)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
	p[6] = proto
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(p[8:24], s[:])
	copy(p[24:40], d[:])
	binary.BigEndian.PutUint16(p[40:42], sport)
	binary.BigEndian.PutUint16(p[42:44], dport)
	return p
}

func TestParseAndAllowPorts(t *testing.T) {
	rules, err := ParseCSV("tcp:443,udp:53,tcp:8000-8010,tcp:443")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"tcp 443", ipv4Packet(6, "192.0.2.1", "198.51.100.1", 12000, 443, 0), true},
		{"udp 53", ipv4Packet(17, "192.0.2.1", "198.51.100.1", 12000, 53, 0), true},
		{"tcp range", ipv4Packet(6, "192.0.2.1", "198.51.100.1", 12000, 8005, 0), true},
		{"tcp denied", ipv4Packet(6, "192.0.2.1", "198.51.100.1", 12000, 22, 0), false},
		{"udp denied tcp rule", ipv4Packet(17, "192.0.2.1", "198.51.100.1", 12000, 443, 0), false},
		{"tcp port not in tcp allowlist despite udp rule", ipv4Packet(6, "192.0.2.1", "198.51.100.1", 12000, 53, 0), false},
		{"tcp range lower boundary", ipv4Packet(6, "192.0.2.1", "198.51.100.1", 12000, 8000, 0), true},
		{"tcp range upper boundary", ipv4Packet(6, "192.0.2.1", "198.51.100.1", 12000, 8010, 0), true},
		{"tcp just below range", ipv4Packet(6, "192.0.2.1", "198.51.100.1", 12000, 7999, 0), false},
		{"tcp just above range", ipv4Packet(6, "192.0.2.1", "198.51.100.1", 12000, 8011, 0), false},
		{"icmp denied", ipv4Packet(1, "192.0.2.1", "198.51.100.1", 0, 0, 0), false},
		{"ipv6 tcp", ipv6Packet(6, "2001:db8::1", "2001:db8::2", 12000, 443), true},
		{"ipv6 udp denied", ipv6Packet(17, "2001:db8::1", "2001:db8::2", 12000, 443), false},
		{"ipv6 udp allowed", ipv6Packet(17, "2001:db8::1", "2001:db8::2", 12000, 53), true},
		{"ipv6 tcp uses tcp policy only", ipv6Packet(6, "2001:db8::1", "2001:db8::2", 12000, 53), false},
		{"ipv4 fragment denied", ipv4Packet(6, "192.0.2.1", "198.51.100.1", 12000, 443, 0x2000), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rules.AllowsPacket(tt.pkt); got != tt.want {
				t.Fatalf("AllowsPacket()=%v want %v", got, tt.want)
			}
		})
	}
}

func TestIPv6DestinationOptionsHeader(t *testing.T) {
	p := make([]byte, 40+8+8)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], 16)
	p[6] = 60
	p[40] = 17
	p[41] = 0 // 8-byte destination options
	binary.BigEndian.PutUint16(p[48:50], 53000)
	binary.BigEndian.PutUint16(p[50:52], 53)
	rules, _ := ParseCSV("udp:53")
	if !rules.AllowsPacket(p) {
		t.Fatal("IPv6 destination-options packet should match UDP 53")
	}
}

func TestParseRejectsInvalidRules(t *testing.T) {
	for _, input := range []string{"tcp:0", "udp:65536", "sctp:443", "tcp:9-2", "tcp:", "tcp:80,,udp:53"} {
		if _, err := ParseCSV(input); err == nil {
			t.Errorf("ParseCSV(%q) expected error", input)
		}
	}
}

func TestEmptyPolicyAllowsLegacyTraffic(t *testing.T) {
	var rules RuleSet
	if !rules.AllowsPacket([]byte{1, 2, 3}) {
		t.Fatal("empty policy must preserve legacy behavior")
	}
}

func TestIPv6FragmentDeniedWithPortPolicy(t *testing.T) {
	p := make([]byte, 40+8+8)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], 16)
	p[6] = 44 // Fragment header
	s, d := netip.MustParseAddr("2001:db8::1").As16(), netip.MustParseAddr("2001:db8::2").As16()
	copy(p[8:24], s[:])
	copy(p[24:40], d[:])
	p[40] = 17 // UDP follows fragment header
	p[41] = 0  // reserved
	binary.BigEndian.PutUint16(p[48:50], 53000)
	binary.BigEndian.PutUint16(p[50:52], 53)
	rules, err := ParseCSV("udp:53")
	if err != nil {
		t.Fatal(err)
	}
	if rules.AllowsPacket(p) {
		t.Fatal("IPv6 fragmented packet must be denied when destination-port policy is enabled")
	}
}
