package tunnel

import (
	"fmt"
	"net/netip"

	"github.com/hatinati2/PQTunnel/internal/prefixset"
)

// validateDisjointPrefixes rejects any overlap between the two sets, including
// partial overlaps and equal prefixes. Site-to-site LANs must be distinct.
func validateDisjointPrefixes(a, b []netip.Prefix) error {
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
	if prefixset.Overlap(a, b) {
		return fmt.Errorf("prefix sets overlap")
	}
	return nil
}
