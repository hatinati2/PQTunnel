#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_config="$(mktemp)"
trap 'rm -f "$tmp_config"' EXIT
chmod 600 "$tmp_config"

cat >"$tmp_config" <<'CONFIG'
PQTUNNEL_ROLE=dialer
PQTUNNEL_WAN_IF=eth0
PQTUNNEL_TUN=pqtun0
PQTUNNEL_TCP_EGRESS_PORTS=80-90,443
PQTUNNEL_UDP_EGRESS_PORTS=53-55
PQTUNNEL_TCP_FORWARD_RULES='8443=192.0.2.10:443,9443=[2001:db8::10]:443'
PQTUNNEL_UDP_FORWARD_RULES='5353=192.0.2.20:53,5354=[2001:db8::20]:53'
CONFIG

preview="$(PQTUNNEL_SITE_CONFIG="$tmp_config" bash "$ROOT/scripts/site-to-site-selective.sh" preview)"

assert_contains() {
  local expected="$1"
  if ! grep -Fq -- "$expected" <<<"$preview"; then
    printf 'FAIL: expected preview to contain: %s\n' "$expected" >&2
    printf '%s\n' "$preview" >&2
    exit 1
  fi
}

assert_contains 'dnat ip to 192.0.2.10:443'
assert_contains 'dnat ip6 to [2001:db8::10]:443'
assert_contains 'dnat ip to 192.0.2.20:53'
assert_contains 'dnat ip6 to [2001:db8::20]:53'
assert_contains 'tcp dport { 80-90 , 443 } meta mark set 20561'
assert_contains 'udp dport { 53-55 } meta mark set 20561'
assert_contains 'snat ip to 10.66.0.2'
assert_contains 'snat ip6 to fd42:7061:7475::2'

if grep -Eq 'dnat to |snat to ' <<<"$preview"; then
  echo 'FAIL: inet-family NAT statements must specify ip or ip6 explicitly' >&2
  exit 1
fi

# Run the real nftables parser in check-only mode. This does not apply rules.
if ! command -v nft >/dev/null 2>&1; then
  echo 'FAIL: nftables parser is required for this regression test' >&2
  exit 1
fi
rules_file="$(mktemp)"
trap 'rm -f "$tmp_config" "$rules_file"' EXIT
printf '%s\n' "$preview" >"$rules_file"
sudo nft -c -f "$rules_file"

echo 'PASS: preview has explicit IPv4/IPv6 NAT syntax and passes nft -c.'
