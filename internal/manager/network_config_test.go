package manager

import (
	"reflect"
	"testing"
)

func TestDialerNetworkEgressChanges(t *testing.T) {
	got, err := dialerNetworkEgressChanges("tcp:443,tcp:80-90,tcp:85-100,udp:53,udp:123")
	if err != nil {
		t.Fatalf("dialerNetworkEgressChanges returned error: %v", err)
	}
	want := map[string]string{
		"PQTUNNEL_TCP_EGRESS_PORTS": "80-100,443",
		"PQTUNNEL_UDP_EGRESS_PORTS": "53,123",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected egress mapping: got %#v, want %#v", got, want)
	}
}

func TestDialerNetworkEgressChangesRejectsInvalidRanges(t *testing.T) {
	for _, value := range []string{
		"tcp:0",
		"udp:65536",
		"tcp:90-80",
		"icmp:8",
		"tcp:443-",
		"tcp:1-2-3",
		"tcp:80,,udp:53",
	} {
		if _, err := dialerNetworkEgressChanges(value); err == nil {
			t.Errorf("expected invalid allowlist %q to be rejected", value)
		}
	}
}
