package tunnel

import (
	"fmt"
	"net/netip"

	"github.com/hatinati2/PQTunnel/internal/prefixset"
)

// validateDisjointPrefixes rejects overlapping networks. When allowDefaultRoute is
// true, exact IPv4/IPv6 default routes may overlap local prefixes for full-tunnel mode.
func validateDisjointPrefixes(a, b []netip.Prefix, allowDefaultRoute bool) error {
	for _, left := range a {
		if !left.IsValid() || left != left.Masked() {
			return fmt.Errorf("invalid or non-canonical prefix %q", left)
		}
	}
	for _, right := range b {
		if !right.IsValid() || right != right.Masked() {
			return fmt.Errorf("invalid or non-canonical prefix %q", right)
		}
	}
	for _, left := range a {
		for _, right := range b {
			if allowDefaultRoute && isDefaultPrefix(right) {
				continue
			}
			if prefixset.Overlap([]netip.Prefix{left}, []netip.Prefix{right}) {
				return fmt.Errorf("prefix sets overlap")
			}
		}
	}
	return nil
}

func isDefaultPrefix(p netip.Prefix) bool { return p.IsValid() && p.Bits() == 0 }
