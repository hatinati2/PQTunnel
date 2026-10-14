package tunnel

import (
	"net/netip"
	"testing"

	"github.com/hatinati2/PQTunnel/internal/prefixset"
)

func TestValidateDisjointPrefixes(t *testing.T) {
	tests := []struct {
		name string
		a string
		b string
		wantErr bool
	}{
		{name: "disjoint IPv4", a: "10.10.0.0/16", b: "10.20.0.0/16"},
		{name: "disjoint IPv6", a: "fd00:1::/64", b: "fd00:2::/64"},
		{name: "partial IPv4 overlap", a: "10.0.0.0/8", b: "10.1.0.0/16", wantErr: true},
		{name: "equal prefix", a: "192.0.2.0/24", b: "192.0.2.0/24", wantErr: true},
		{name: "cross-family", a: "10.0.0.0/8", b: "2001:db8::/32"},
		{name: "host prefix overlap", a: "192.0.2.7/32", b: "192.0.2.0/24", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := prefixset.ParseCSV(tt.a)
			if err != nil { t.Fatal(err) }
			b, err := prefixset.ParseCSV(tt.b)
			if err != nil { t.Fatal(err) }
			err = validateDisjointPrefixes(a, b)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateDisjointPrefixes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDisjointPrefixesRejectsNonCanonicalInput(t *testing.T) {
	_, err := validateDisjointPrefixes(
		[]netip.Prefix{netip.MustParsePrefix("10.1.2.3/24")},
		[]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	)
	if err == nil {
		t.Fatal("expected non-canonical prefix to be rejected")
	}
}
