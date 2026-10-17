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
GATEWAY_CONFIG="$LAB_DIR/gateway.env"
WRAPPER_DIR="$LAB_DIR/wrapper"
REAL_IP="$(command -v ip)"
REAL_NFT="$(command -v nft)"
REAL_SYSCTL="$(command -v sysctl)"
CREATED_NS=0

fail() { echo "FAIL: $*" >&2; exit 1; }
run_helper() {
  local config="$1" mode="$2"
  ip netns exec "$NS" env PQTUNNEL_SITE_CONFIG="$config" PQTUNNEL_STATE_DIR="$STATE_DIR" \
    bash "$ROOT/scripts/site-to-site-selective.sh" "$mode"
}
run_dialer_injected_failure() {
  local name="$1" ip_pattern="$2" sysctl_pattern="$3"
  local log="$LAB_DIR/rollback-$name.log" rc
  if ip netns exec "$NS" env \
    PATH="$WRAPPER_DIR:$PATH" \
    PQTUNNEL_REAL_IP="$REAL_IP" \
    PQTUNNEL_FAIL_IP_PATTERN="$ip_pattern" \
    PQTUNNEL_REAL_SYSCTL="$REAL_SYSCTL" \
    PQTUNNEL_FAIL_SYSCTL_PATTERN="$sysctl_pattern" \
    PQTUNNEL_SITE_CONFIG="$GOOD_CONFIG" \
    PQTUNNEL_STATE_DIR="$STATE_DIR" \
    bash "$ROOT/scripts/site-to-site-selective.sh" dialer-up >"$log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  (( rc != 0 )) || fail "dialer-up unexpectedly succeeded with injected failure at $name"
  assert_no_tun "injected $name failure rollback"
  assert_no_saved_state "injected $name failure rollback"
  assert_no_helper_policy "injected $name failure rollback"
  assert_forwarding_zero "injected $name failure rollback"
  if [[ -n "$ip_pattern" ]] && ! grep -Fq 'injected ip failure' "$log"; then
    fail "dialer $name test did not reach the injected ip failure"
  fi
  if [[ -n "$sysctl_pattern" ]] && ! grep -Fq 'injected sysctl failure' "$log"; then
    fail "dialer $name test did not reach the injected sysctl failure"
  fi
  echo "PASS: dialer rollback succeeds after injected $name failure."
}
assert_no_gateway_state() {
  if [[ -e "$STATE_DIR/site-selective-gateway.state" ]]; then
    fail "unexpected saved Gateway state after $1"
  fi
}
assert_gateway_base_preserved() {
  if ! ip -n "$NS" link show dev pqtun0 >/dev/null 2>&1; then
    fail "Gateway rollback removed the pre-existing pqtun0 interface after $1"
  fi
  if ! ip -n "$NS" -4 addr show dev pqtun0 | grep -qF '10.66.0.1/24'; then
    fail "Gateway rollback changed the pre-existing IPv4 address after $1"
  fi
  if ip -n "$NS" -6 addr show dev pqtun0 | grep -qF 'fd42:7061:7475::1/64'; then
    fail "Gateway rollback left its added IPv6 address after $1"
  fi
  if ip netns exec "$NS" nft list table inet pqtunnel_gateway >/dev/null 2>&1; then
    fail "unexpected pqtunnel_gateway nftables table after $1"
  fi
  assert_no_gateway_state "$1"
  assert_forwarding_zero "$1"
}
run_gateway_injected_failure() {
  local name="$1" ip_pattern="$2" sysctl_pattern="$3" nft_pattern="$4"
  local log="$LAB_DIR/rollback-gateway-$name.log" rc
  if ip netns exec "$NS" env \
    PATH="$WRAPPER_DIR:$PATH" \
    PQTUNNEL_REAL_IP="$REAL_IP" \
    PQTUNNEL_FAIL_IP_PATTERN="$ip_pattern" \
    PQTUNNEL_REAL_SYSCTL="$REAL_SYSCTL" \
    PQTUNNEL_FAIL_SYSCTL_PATTERN="$sysctl_pattern" \
    PQTUNNEL_REAL_NFT="$REAL_NFT" \
    PQTUNNEL_FAIL_NFT_PATTERN="$nft_pattern" \
    PQTUNNEL_SITE_CONFIG="$GATEWAY_CONFIG" \
    PQTUNNEL_STATE_DIR="$STATE_DIR" \
    bash "$ROOT/scripts/site-to-site-selective.sh" gateway-up >"$log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  (( rc != 0 )) || fail "gateway-up unexpectedly succeeded with injected failure at $name"
  assert_gateway_base_preserved "Gateway $name rollback"
  if [[ -n "$ip_pattern" ]] && ! grep -Fq 'injected ip failure' "$log"; then
    fail "Gateway $name test did not reach the injected ip failure"
  fi
  if [[ -n "$sysctl_pattern" ]] && ! grep -Fq 'injected sysctl failure' "$log"; then
    fail "Gateway $name test did not reach the injected sysctl failure"
  fi
  if [[ -n "$nft_pattern" ]] && ! grep -Fq 'injected nftables apply failure' "$log"; then
    fail "Gateway $name test did not reach the injected nftables apply failure"
  fi
  echo "PASS: Gateway rollback preserves the pre-existing TUN after injected $name failure."
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
      local diagnostic_log
      for diagnostic_log in "$LAB_DIR"/rollback-*.log; do
        [[ -f "$diagnostic_log" ]] || continue
        echo "--- $diagnostic_log ---" >&2
        cat "$diagnostic_log" >&2
      done
    fi
  fi
  if (( CREATED_NS )) && ip netns list | awk '{print $1}' | grep -Fxq "$NS"; then
    if [[ -f "$STATE_DIR/site-selective-gateway.state" && -f "$GATEWAY_CONFIG" ]]; then
      run_helper "$GATEWAY_CONFIG" gateway-down >/dev/null 2>&1
    fi
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
PQTUNNEL_TCP_FORWARD_RULES=8443=198.51.100.2:443
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
cat >"$GATEWAY_CONFIG" <<CONFIG
PQTUNNEL_ROLE=gateway
PQTUNNEL_WAN_IF=$WAN_IF
PQTUNNEL_TUN=pqtun0
CONFIG
chmod 0600 "$GOOD_CONFIG" "$BAD_CONFIG" "$GATEWAY_CONFIG"

mkdir -m 0700 "$WRAPPER_DIR"
cat >"$WRAPPER_DIR/ip" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ -n "${PQTUNNEL_FAIL_IP_PATTERN:-}" && "$*" == *"$PQTUNNEL_FAIL_IP_PATTERN"* ]]; then
  echo "injected ip failure for pattern: $PQTUNNEL_FAIL_IP_PATTERN" >&2
  exit 42
fi
exec "$PQTUNNEL_REAL_IP" "$@"
WRAPPER
cat >"$WRAPPER_DIR/sysctl" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ -n "${PQTUNNEL_FAIL_SYSCTL_PATTERN:-}" && "$*" == *"$PQTUNNEL_FAIL_SYSCTL_PATTERN"* ]]; then
  echo "injected sysctl failure for pattern: $PQTUNNEL_FAIL_SYSCTL_PATTERN" >&2
  exit 42
fi
exec "$PQTUNNEL_REAL_SYSCTL" "$@"
WRAPPER
chmod 0700 "$WRAPPER_DIR/ip" "$WRAPPER_DIR/sysctl"

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

# 3. A pre-existing nftables table must be rejected before any network changes.
ip netns exec "$NS" nft add table inet host_firewall
if run_helper "$GOOD_CONFIG" dialer-up >"$LAB_DIR/preexisting-firewall.log" 2>&1; then
  fail 'dialer-up unexpectedly accepted a pre-existing nftables table'
fi
assert_no_tun 'pre-existing firewall'
assert_no_saved_state 'pre-existing firewall'
assert_no_helper_policy 'pre-existing firewall'
assert_forwarding_zero 'pre-existing firewall'
if ! grep -q 'existing nftables table/ruleset was detected' "$LAB_DIR/preexisting-firewall.log"; then
  fail 'pre-existing firewall test did not reach the fail-closed firewall guard'
fi
ip netns exec "$NS" nft delete table inet host_firewall
echo 'PASS: pre-existing nftables state is rejected before applying network changes.'

# 4. Pre-enabled forwarding must be preserved and rejected before state is written.
ip netns exec "$NS" sysctl -w net.ipv4.ip_forward=1 >/dev/null
if run_helper "$GOOD_CONFIG" dialer-up >"$LAB_DIR/preenabled-forwarding.log" 2>&1; then
  fail 'dialer-up unexpectedly accepted pre-enabled IPv4 forwarding'
fi
assert_no_tun 'pre-enabled forwarding'
assert_no_saved_state 'pre-enabled forwarding'
assert_no_helper_policy 'pre-enabled forwarding'
forward4="$(ip netns exec "$NS" cat /proc/sys/net/ipv4/ip_forward)"
forward6="$(ip netns exec "$NS" cat /proc/sys/net/ipv6/conf/all/forwarding)"
[[ "$forward4" == 1 && "$forward6" == 0 ]] || fail "helper changed pre-enabled forwarding (IPv4=$forward4 IPv6=$forward6)"
if ! grep -q 'forwarding is already enabled' "$LAB_DIR/preenabled-forwarding.log"; then
  fail 'pre-enabled forwarding test did not reach the fail-closed forwarding guard'
fi
ip netns exec "$NS" sysctl -w net.ipv4.ip_forward=0 >/dev/null
assert_forwarding_zero 'pre-enabled forwarding test cleanup'
echo 'PASS: pre-enabled forwarding is rejected without changing its prior value.'

# 5. Inject representative failures after each major Dialer apply stage.
# The command wrappers delegate everything except one exact command fragment.
run_dialer_injected_failure "tuntap-create" "tuntap add dev pqtun0 mode tun" ""
run_dialer_injected_failure "ipv4-address" "addr add 10.66.0.2/24 dev pqtun0" ""
run_dialer_injected_failure "egress-route" "route add default dev pqtun0 table 518" ""
run_dialer_injected_failure "policy-rule" "rule add priority 10518" ""
run_dialer_injected_failure "ipv4-forwarding" "" "net.ipv4.ip_forward=1"

# The final-stage failure is applied after the Dialer has created TUN/routes/rules
# and enabled forwarding. Check-only validation still goes through real nft.
cat >"$WRAPPER_DIR/nft" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
case "$1" in
  -c) exec "$PQTUNNEL_REAL_NFT" "$@" ;;
  -f)
    if [[ -n "${PQTUNNEL_FAIL_NFT_PATTERN:-}" && "$*" == *"$PQTUNNEL_FAIL_NFT_PATTERN"* ]]; then
      echo 'injected nftables apply failure for rollback test' >&2
      exit 42
    fi
    exec "$PQTUNNEL_REAL_NFT" "$@"
    ;;
  *) exec "$PQTUNNEL_REAL_NFT" "$@" ;;
esac
WRAPPER
chmod 0700 "$WRAPPER_DIR/nft"

if ip netns exec "$NS" env \
  PATH="$WRAPPER_DIR:$PATH" \
  PQTUNNEL_REAL_IP="$REAL_IP" \
  PQTUNNEL_REAL_SYSCTL="$REAL_SYSCTL" \
  PQTUNNEL_REAL_NFT="$REAL_NFT" \
  PQTUNNEL_FAIL_NFT_PATTERN="-f" \
  PQTUNNEL_SITE_CONFIG="$GOOD_CONFIG" \
  PQTUNNEL_STATE_DIR="$STATE_DIR" \
  bash "$ROOT/scripts/site-to-site-selective.sh" dialer-up >"$LAB_DIR/rollback-dialer-nftables-apply.log" 2>&1; then
  fail 'dialer-up unexpectedly succeeded with injected nftables apply failure'
fi
assert_no_tun 'injected nftables apply failure rollback'
assert_no_saved_state 'injected nftables apply failure rollback'
assert_no_helper_policy 'injected nftables apply failure rollback'
assert_forwarding_zero 'injected nftables apply failure rollback'
if ! grep -Fq 'injected nftables apply failure' "$LAB_DIR/rollback-dialer-nftables-apply.log"; then
  fail 'Dialer rollback test did not reach the injected nftables apply failure'
fi
echo 'PASS: Dialer nftables-apply failure rolls back TUN, routes, rules, state and forwarding.'

# 6. Exercise Gateway failures without allowing rollback to remove its pre-existing TUN.
ip netns exec "$NS" ip tuntap add dev pqtun0 mode tun
ip netns exec "$NS" ip addr add 10.66.0.1/24 dev pqtun0
ip netns exec "$NS" ip link set dev pqtun0 up
run_gateway_injected_failure "ipv6-address" "addr add fd42:7061:7475::1/64 dev pqtun0" "" ""
run_gateway_injected_failure "ipv4-forwarding" "" "net.ipv4.ip_forward=1" ""
run_gateway_injected_failure "ipv6-forwarding" "" "net.ipv6.conf.all.forwarding=1" ""
run_gateway_injected_failure "nftables-apply" "" "" "-f"

echo 'PASS: selective site-to-site helper fail-closed and rollback checks passed inside a disposable namespace.'
