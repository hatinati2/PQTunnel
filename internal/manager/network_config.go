package manager

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type portInterval struct {
	first uint16
	last  uint16
}

func dialerNetworkEgressChanges(allowed string) (map[string]string, error) {
	if strings.TrimSpace(allowed) == "" || len(allowed) > 1024 {
		return nil, errors.New("destination port allowlist must be configured")
	}
	tcp := make([]portInterval, 0)
	udp := make([]portInterval, 0)
	for _, raw := range strings.Split(allowed, ",") {
		item := strings.TrimSpace(raw)
		parts := strings.Split(item, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid destination-port rule %q", item)
		}
		proto := strings.ToLower(strings.TrimSpace(parts[0]))
		bounds := strings.Split(strings.TrimSpace(parts[1]), "-")
		if (proto != "tcp" && proto != "udp") || len(bounds) < 1 || len(bounds) > 2 {
			return nil, fmt.Errorf("invalid destination-port rule %q", item)
		}
		first, err := parseNetworkPort(bounds[0])
		if err != nil {
			return nil, fmt.Errorf("invalid destination-port rule %q", item)
		}
		last := first
		if len(bounds) == 2 {
			last, err = parseNetworkPort(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid destination-port rule %q", item)
			}
		}
		if first > last {
			return nil, fmt.Errorf("invalid destination-port range %q", item)
		}
		interval := portInterval{first: first, last: last}
		if proto == "tcp" {
			tcp = append(tcp, interval)
		} else {
			udp = append(udp, interval)
		}
	}
	return map[string]string{
		"PQTUNNEL_TCP_EGRESS_PORTS": formatNetworkPortIntervals(tcp),
		"PQTUNNEL_UDP_EGRESS_PORTS": formatNetworkPortIntervals(udp),
	}, nil
}

func parseNetworkPort(value string) (uint16, error) {
	if value == "" {
		return 0, errors.New("empty port")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("port must be numeric")
		}
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	return uint16(n), nil
}

func formatNetworkPortIntervals(intervals []portInterval) string {
	if len(intervals) == 0 {
		return ""
	}
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].first == intervals[j].first {
			return intervals[i].last < intervals[j].last
		}
		return intervals[i].first < intervals[j].first
	})
	merged := make([]portInterval, 0, len(intervals))
	for _, current := range intervals {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		last := &merged[len(merged)-1]
		if uint32(current.first) > uint32(last.last)+1 {
			merged = append(merged, current)
			continue
		}
		if current.last > last.last {
			last.last = current.last
		}
	}
	parts := make([]string, 0, len(merged))
	for _, item := range merged {
		if item.first == item.last {
			parts = append(parts, strconv.Itoa(int(item.first)))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", item.first, item.last))
		}
	}
	return strings.Join(parts, ",")
}
