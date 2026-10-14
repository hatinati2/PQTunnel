package main

import (
	"net/netip"
	"testing"

	"github.com/hatinati2/PQTunnel/internal/prefixset"
)

func TestValidatePrefixMode(t *testing.T) {
	local, err := prefixset.ParseCSV("10.66.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	remote, err := prefixset.ParseCSV("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		local []netip.Prefix
		remote []netip.Prefix
		wantErr bool
	}{
		{name: "legacy mode", wantErr: false},
		{name: "site-to-site mode", local: local, remote: remote, wantErr: false},
		{name: "local only", local: local, wantErr: true},
		{name: "remote only", remote: remote, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePrefixMode(tt.local, tt.remote)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePrefixMode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
