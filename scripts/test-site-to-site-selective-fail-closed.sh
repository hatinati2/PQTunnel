#!/usr/bin/env bash
# Exercise fail-closed validation and rollback only inside a disposable netns.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "$BASH_SOURCE")/.." && pwd)"
cd "$ROOT"
[[ $EUID -eq 0 ]] || { echo 'FAIL: run with sudo/root on an isolated Linux host' >&2; exit 2; }
for cmd in ip nft sysctl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "FAIL: required command missing: $cmd" >&2; exit 2; }
done
[[ -c /dev/net/tun ]] || { echo 'FAIL: /dev/net/tun is unavailable' >&2; exit 2; }

SUFFIX="$$"
NS="pqt-fail-$SUFFIX"
WAN_IF="pfw$SUFFIX"
if ip netns list | awk '{print $1}' | grep -Fxq "$NS"; then
  echo "FAIL: refusing to reuse existing namespace $NS" >&2
  exit 2
fi

LAB_DIR="$(mktemp -d -t pqtunnel-failclosed.XXXXXX)"
STATE_DIR="$LAB_DIR/state"
GOOD_CONFIG="$LAB_DIR/valid.env"
BAD_CONFIG="$LAB_DIR/invalid.env"
WRAPPER_DIR="$LAB_DIR/wrapper"
REAL_NFT="$(command -v nft)"
CREATED_NS=0

fail() { echo "FAIL: $*" >&2; exit 1; }
run_helper() {
  local config="$1" mode="$2"
  ip netns exec "$NS" env PQTUNNEL_SITE_CONFIG="$config" PQTUNNEL_STATE_DIR="$STATE_DIR" \
    bash "$ROOT/scripts/site-to-site-selective.sh" "$mode"
}
assert_no_tun() {
  if ip -n "$NS" link show dev pqtun0 >/dev/null 2>&1; then
    fail "unexpected pqtun0 interface after $1"
  fi
}
assert_no_saved_state() {
  if [[ -e "$STATE_DIR/site-selective-dialer.state" ]]; then
    fail "unexpected saved dialer state after $1"
  fi
}
assert_no_helper_policy() {
  if ip netns exec "$NS" nft list table inet pqtunnel_selective >/dev/null 2>&1; then
    fail "unexpected pqtunnel_selective nftables table after $1"
  fi
  if ip -n "$NS" -4 rule show | grep -Eq '^(10518|10519):'; then
    fail "unexpected helper IPv4 policy rule after $1"
  fi
  if ip -n "$NS" -6 rule show | grep -Eq '^(10518|10519):'; then
    fail "unexpected helper IPv6 policy rule after $1"
  fi
  if [[ -n "$(ip -n "$NS" -4 route show table 518 2>/dev/null || true)$(ip -n "$NS" -6 route show table 518 2>/dev/null || true)$(ip -n "$NS" -4 route show table 519 2>/dev/null || true)$(ip -n "$NS" -6 route show table 519 2>/dev/null || true)" ]]; then
    fail "unexpected helper policy route after $1"
  fi
}
assert_forwarding_zero() {
  local v4 v6
  v4="$(ip netns exec "$NS" cat /proc/sys/net/ipv4/ip_forward)"
  v6="$(ip netns exec "$NS" cat /proc/sys/net/ipv6/conf/all/forwarding)"
  [[ "$v4" == 0 && "$v6" == 0 ]] || fail "forwarding not restored after $1 (IPv4=$v4 IPv6=$v6)"
}
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  if (( rc != 0 )); then
    if (( CREATED_NS )) && ip netns list | awk '{print $1}' | grep -Fxq "$NS"; then
      echo '--- fail-closed test namespace diagnostics ---' >&2
      ip -n "$NS" -brief address show >&2
      ip -n "$NS" -4 rule show >&2
      ip -n "$NS" -6 rule show >&2
      ip netns exec "$NS" nft list ruleset >&2
      [[ -f "$LAB_DIR/rollback-apply.log" ]] && cat "$LAB_DIR/rollback-apply.log" >&2
    fi
  fi
  if (( CREATED_NS )) && ip netns list | awk '{print $1}' | grep -Fxq "$NS"; then
    if [[ -f "$STATE_DIR/site-selective-dialer.state" && -f "$GOOD_CONFIG" ]]; then
      run_helper "$GOOD_CONFIG" dialer-down >/dev/null 2>&1
    fi
    ip netns del "$NS" >/dev/null 2>&1
  fi
  rm -rf "$LAB_DIR"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 0700 "$STATE_DIR"
cat >"$GOOD_CONFIG" <<CONFIG
PQTUNNEL_ROLE=dialer
PQTUNNEL_WAN_IF=$WAN_IF
PQTUNNEL_TUN=pqtun0
PQTUNNEL_TCP_EGRESS_PORTS=443
PQTUNNEL_UDP_EGRESS_PORTS=
PQTUNNEL_TCP_FORWARD_RULES=
PQTUNNEL_UDP_FORWARD_RULES=
CONFIG
cat >"$BAD_CONFIG" <<CONFIG
PQTUNNEL_ROLE=dialer
PQTUNNEL_WAN_IF=$WAN_IF
PQTUNNEL_TUN=pqtun0
PQTUNNEL_TCP_EGRESS_PORTS=443,,8443
PQTUNNEL_UDP_EGRESS_PORTS=
PQTUNNEL_TCP_FORWARD_RULES=
PQTUNNEL_UDP_FORWARD_RULES=
CONFIG
chmod 0600 "$GOOD_CONFIG" "$BAD_CONFIG"

ip netns add "$NS"
CREATED_NS=1
ip netns exec "$NS" sysctl -w net.ipv4.ip_forward=0 >/dev/null
ip netns exec "$NS" sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null
ip -n "$NS" link set lo up
ip -n "$NS" link add "$WAN_IF" type dummy
ip -n "$NS" link set "$WAN_IF" up

# 1. Malformed port allowlists must fail validation without network changes.
if run_helper "$BAD_CONFIG" validate >"$LAB_DIR/invalid-config.log" 2>&1; then
  fail 'invalid port allowlist unexpectedly passed validation'
fi
assert_no_tun 'invalid configuration validation'
assert_no_saved_state 'invalid configuration validation'
assert_no_helper_policy 'invalid configuration validation'
assert_forwarding_zero 'invalid configuration validation'
echo 'PASS: invalid port list fails closed without applying network state.'

# 2. A conflicting policy-routing priority must be detected before apply.
ip -n "$NS" rule add priority 10518 fwmark 20561 table 518
if run_helper "$GOOD_CONFIG" dialer-up >"$LAB_DIR/route-conflict.log" 2>&1; then
  fail 'dialer-up unexpectedly accepted a pre-existing policy-rule priority'
fi
assert_no_tun 'policy rule conflict'
assert_no_saved_state 'policy rule conflict'
if ip netns exec "$NS" nft list table inet pqtunnel_selective >/dev/null 2>&1; then
  fail 'policy-rule conflict created a nftables table'
fi
if ip -n "$NS" -4 rule show | grep -Eq '^10519:' || ip -n "$NS" -6 rule show | grep -Eq '^10519:'; then
  fail 'policy-rule conflict added the other helper policy priority'
fi
if [[ -n "$(ip -n "$NS" -4 route show table 518 2>/dev/null || true)$(ip -n "$NS" -6 route show table 518 2>/dev/null || true)$(ip -n "$NS" -4 route show table 519 2>/dev/null || true)$(ip -n "$NS" -6 route show table 519 2>/dev/null || true)" ]]; then
  fail 'policy-rule conflict populated a helper route table'
fi
assert_forwarding_zero 'policy rule conflict'
echo 'PASS: existing policy-routing priority is rejected before apply.'
ip -n "$NS" rule del priority 10518 fwmark 20561 table 518

# 3. Inject an nftables apply failure after the helper has created TUN/routes/
# rules and enabled forwarding. Check-only validation still uses real nft.
mkdir -m 0700 "$WRAPPER_DIR"
cat >"$WRAPPER_DIR/nft" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
case "\${1:-}" in
  -c) exec "$PQTUNNEL_REAL_NFT" "$@" ;;
  -f) echo 'injected nftables apply failure for rollback test' >&2; exit 42 ;;
  *) exec "$PQTUNNEL_REAL_NFT" "$@" ;;
esac
WRAPPER
chmod 0700 "$WRAPPER_DIR/nft"

set +e
ip netns exec "$NS" env \
  PATH="$WRAPPER_DIR:$PATH" \
  PQTUNNEL_REAL_NFT="$REAL_NFT" \
  PQTUNNEL_SITE_CONFIG="$GOOD_CONFIG" \
  PQTUNNEL_STATE_DIR="$STATE_DIR" \
  bash "$ROOT/scripts/site-to-site-selective.sh" dialer-up >"$LAB_DIR/rollback-apply.log" 2>&1
apply_rc=$?
set -e
(( apply_rc != 0 )) || fail 'dialer-up unexpectedly succeeded with injected nftables apply failure'

assert_no_tun 'injected nftables apply failure rollback'
assert_no_saved_state 'injected nftables apply failure rollback'
assert_no_helper_policy 'injected nftables apply failure rollback'
assert_forwarding_zero 'injected nftables apply failure rollback'
if ! grep -q 'injected nftables apply failure' "$LAB_DIR/rollback-apply.log"; then
  fail 'rollback test did not reach the injected nftables apply failure'
fi
echo 'PASS: nftables apply failure rolls back TUN, routes, rules, state and forwarding.'
echo 'PASS: selective site-to-site helper fail-closed and rollback checks passed inside a disposable namespace.'
