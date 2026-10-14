// Package prefixset parses and checks canonical IP prefix allowlists.
package prefixset

import (
	"fmt"
	"net/netip"
	"strings"
)

// ParseCSV parses comma-separated CIDR prefixes, canonicalizes them, removes
// duplicates, and rejects empty items.
func ParseCSV(value string) ([]netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty prefix in comma-separated list")
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q: %w", part, err)
		}
		p = p.Masked()
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out, nil
}

func Contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range prefixes {
		if p.IsValid() && p.Contains(addr) {
			return true
		}
	}
	return false
}

// Overlap reports whether any prefix in a overlaps any prefix in b.
func Overlap(a, b []netip.Prefix) bool {
	for _, x := range a {
		for _, y := range b {
			if !x.IsValid() || !y.IsValid() || x.Addr().Is4() != y.Addr().Is4() {
				continue
			}
			if x.Contains(y.Addr()) || y.Contains(x.Addr()) {
				return true
			}
		}
	}
	return false
}
