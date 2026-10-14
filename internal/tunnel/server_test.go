package tunnel

import (
	"net/netip"
	"testing"

	"github.com/hatinati2/PQTunnel/internal/prefixset"
)

func TestPeerForDestinationIPv4AndIPv6(t *testing.T) {
	v4, err := prefixset.ParseCSV("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	v6, err := prefixset.ParseCSV("2001:db8:1::/64")
	if err != nil {
		t.Fatal(err)
	}
	peers := map[string]*peer{
		"iran":   {identity: "iran", prefixes: v4},
		"abroad": {identity: "abroad", prefixes: v6},
	}
	if got := peerForDestination(peers, netip.MustParseAddr("192.0.2.44")); got == nil || got.identity != "iran" {
		t.Fatalf("IPv4 route selected wrong peer: %#v", got)
	}
	if got := peerForDestination(peers, netip.MustParseAddr("2001:db8:1::44")); got == nil || got.identity != "abroad" {
		t.Fatalf("IPv6 route selected wrong peer: %#v", got)
	}
	if got := peerForDestination(peers, netip.MustParseAddr("198.51.100.4")); got != nil {
		t.Fatalf("unmatched destination should be dropped: %#v", got)
	}
}

func TestPeerForDestinationDropsAmbiguousRoute(t *testing.T) {
	a, _ := prefixset.ParseCSV("10.0.0.0/8")
	b, _ := prefixset.ParseCSV("10.1.0.0/16")
	peers := map[string]*peer{
		"a": {identity: "a", prefixes: a},
		"b": {identity: "b", prefixes: b},
	}
	if got := peerForDestination(peers, netip.MustParseAddr("10.1.2.3")); got != nil {
		t.Fatalf("ambiguous route must be dropped, got %#v", got)
	}
}

func TestPeerPacketAllowedChecksBothSourceAndDestination(t *testing.T) {
	peerRanges, err := prefixset.ParseCSV("192.0.2.0/24,2001:db8:20::/64")
	if err != nil {
		t.Fatal(err)
	}
	localRanges, err := prefixset.ParseCSV("198.51.100.0/24,2001:db8:10::/64")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		src  string
		dst  string
		want bool
	}{
		{"v4 allowed", "192.0.2.10", "198.51.100.20", true},
		{"v6 allowed", "2001:db8:20::10", "2001:db8:10::20", true},
		{"spoofed v4 source", "203.0.113.4", "198.51.100.20", false},
		{"disallowed v4 destination", "192.0.2.10", "203.0.113.9", false},
		{"disallowed v6 destination", "2001:db8:20::10", "2001:db8:30::20", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerPacketAllowed(netip.MustParseAddr(tt.src), netip.MustParseAddr(tt.dst), peerRanges, localRanges); got != tt.want {
				t.Fatalf("peerPacketAllowed(%s, %s) = %v, want %v", tt.src, tt.dst, got, tt.want)
			}
		})
	}
}
