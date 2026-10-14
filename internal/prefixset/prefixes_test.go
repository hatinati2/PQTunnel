package prefixset

import (
	"net/netip"
	"testing"
)

func TestParseCSVAndContainsIPv4IPv6(t *testing.T) {
	got, err := ParseCSV("10.0.0.1/24, 2001:db8::1/64,10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want two deduplicated prefixes; got %d: %v", len(got), got)
	}
	if !Contains(got, netip.MustParseAddr("10.0.0.99")) {
		t.Fatal("IPv4 address should match prefix")
	}
	if !Contains(got, netip.MustParseAddr("2001:db8::5")) {
		t.Fatal("IPv6 address should match prefix")
	}
}

func TestRejectBadPrefix(t *testing.T) {
	if _, err := ParseCSV("10.1.2.3/33"); err == nil {
		t.Fatal("expected invalid prefix error")
	}
}

func TestOverlap(t *testing.T) {
	a, _ := ParseCSV("10.0.0.0/24")
	b, _ := ParseCSV("10.0.0.128/25")
	c, _ := ParseCSV("2001:db8::/64")
	if !Overlap(a, b) || Overlap(a, c) {
		t.Fatal("unexpected prefix overlap result")
	}
}
