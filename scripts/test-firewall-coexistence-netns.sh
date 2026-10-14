#!/usr/bin/env bash
# Demonstrate nftables base-chain ordering only inside disposable network namespaces.
# A later standalone "accept" chain cannot override an earlier host-firewall drop.
set -Eeuo pipefail

for cmd in ip nft ss python3; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "FAIL: required command missing: $cmd" >&2; exit 2; }
done
[[ $EUID -eq 0 ]] || { echo 'FAIL: run with sudo/root on a disposable Linux host' >&2; exit 2; }

SUFFIX="$$"
SRC_NS="pqt-co-src-$SUFFIX"
RTR_NS="pqt-co-rtr-$SUFFIX"
DST_NS="pqt-co-dst-$SUFFIX"
SRC_HOST_IF="cosrc$SUFFIX"
SRC_ROUTER_IF="corsr$SUFFIX"
ROUTER_DST_IF="cords$SUFFIX"
DST_HOST_IF="codst$SUFFIX"
LAB_DIR="$(mktemp -d -t pqtunnel-coexist.XXXXXX)"
SERVER_PID=""
CREATED_NS=0

fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  if [[ -n "$SERVER_PID" ]]; then kill -TERM "$SERVER_PID" >/dev/null 2>&1; wait "$SERVER_PID" >/dev/null 2>&1; fi
  if (( rc != 0 )); then
    for ns in "$SRC_NS" "$RTR_NS" "$DST_NS"; do
      if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
        echo "--- namespace $ns ---" >&2
        ip -n "$ns" -brief address show >&2
        ip -n "$ns" route show table all >&2
        ip netns exec "$ns" nft list ruleset >&2 || true
      fi
    done
    [[ ! -f "$LAB_DIR/server.log" ]] || cat "$LAB_DIR/server.log" >&2
  fi
  for ns in "$SRC_NS" "$RTR_NS" "$DST_NS"; do ip netns del "$ns" >/dev/null 2>&1; done
  for iface in "$SRC_HOST_IF" "$SRC_ROUTER_IF" "$ROUTER_DST_IF" "$DST_HOST_IF"; do ip link del "$iface" >/dev/null 2>&1; done
  rm -rf "$LAB_DIR"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for ns in "$SRC_NS" "$RTR_NS" "$DST_NS"; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    fail "refusing to reuse existing network namespace $ns"
  fi
done
for iface in "$SRC_HOST_IF" "$SRC_ROUTER_IF" "$ROUTER_DST_IF" "$DST_HOST_IF"; do
  if ip link show dev "$iface" >/dev/null 2>&1; then
    fail "refusing to reuse existing host interface $iface"
  fi
done

ip netns add "$SRC_NS"
ip netns add "$RTR_NS"
ip netns add "$DST_NS"

ip link add "$SRC_HOST_IF" type veth peer name "$SRC_ROUTER_IF"
ip link set "$SRC_HOST_IF" netns "$SRC_NS"
ip link set "$SRC_ROUTER_IF" netns "$RTR_NS"
ip link add "$ROUTER_DST_IF" type veth peer name "$DST_HOST_IF"
ip link set "$ROUTER_DST_IF" netns "$RTR_NS"
ip link set "$DST_HOST_IF" netns "$DST_NS"

ip -n "$SRC_NS" link set "$SRC_HOST_IF" name eth0
ip -n "$RTR_NS" link set "$SRC_ROUTER_IF" name wan0
ip -n "$RTR_NS" link set "$ROUTER_DST_IF" name lan0
ip -n "$DST_NS" link set "$DST_HOST_IF" name eth0

for ns in "$SRC_NS" "$RTR_NS" "$DST_NS"; do ip -n "$ns" link set lo up; done
ip -n "$SRC_NS" addr add 192.0.2.2/24 dev eth0
ip -n "$RTR_NS" addr add 192.0.2.1/24 dev wan0
ip -n "$RTR_NS" addr add 198.51.100.1/24 dev lan0
ip -n "$DST_NS" addr add 198.51.100.2/24 dev eth0
ip -n "$SRC_NS" link set eth0 up
ip -n "$RTR_NS" link set wan0 up
ip -n "$RTR_NS" link set lan0 up
ip -n "$DST_NS" link set eth0 up
ip -n "$SRC_NS" route add 198.51.100.0/24 via 192.0.2.1
ip -n "$DST_NS" route add 192.0.2.0/24 via 198.51.100.1
ip netns exec "$RTR_NS" sysctl -w net.ipv4.ip_forward=1 >/dev/null

# This is the simulated destination service. Only the disposable destination
# namespace listens; no host port is opened.
ip netns exec "$DST_NS" python3 -u -c '
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.51.100.2", 8080))
s.listen(4)
while True:
    c, _ = s.accept()
    with c:
        data = c.recv(1024)
        c.sendall(b"ok:" + data)
' >"$LAB_DIR/server.log" 2>&1 &
SERVER_PID=$!

ready=0
for _ in $(seq 1 50); do
  if ip netns exec "$DST_NS" ss -ltnH 2>/dev/null | grep -q '198.51.100.2:8080'; then ready=1; break; fi
  kill -0 "$SERVER_PID" >/dev/null 2>&1 || fail "destination test service exited"
  sleep 0.1
done
(( ready == 1 )) || fail "destination test service did not begin listening"

# The simulated pre-existing firewall drops all forwarded packets. A separate,
# later PQTunnel-like base chain contains exact allow rules, but cannot override
# the earlier base-chain drop verdict.
ip netns exec "$RTR_NS" nft -f - <<'NFT'
table inet host_firewall {
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
table inet pqtunnel_demo {
  chain forward {
    type filter hook forward priority 10; policy accept;
    iifname "wan0" oifname "lan0" ip saddr 192.0.2.2 ip daddr 198.51.100.2 tcp dport 8080 ct state new accept
    iifname "lan0" oifname "wan0" ip saddr 198.51.100.2 ip daddr 192.0.2.2 tcp sport 8080 ct state established accept
  }
}
NFT

if ip netns exec "$SRC_NS" python3 - <<'PY'
import socket
s = socket.socket()
s.settimeout(1.0)
try:
    s.connect(("198.51.100.2", 8080))
except OSError:
    print("PASS: earlier host-firewall drop is not overridden by a later independent accept chain")
else:
    raise SystemExit("FAIL: later independent accept unexpectedly bypassed the host-firewall drop")
finally:
    s.close()
PY
then
  :
else
  fail "could not demonstrate the expected independent-chain drop behavior"
fi

# A compatible integration must be made in the chain managed by the firewall
# owner (or its supported config), before that chain's final drop/policy.
ip netns exec "$RTR_NS" nft -f - <<'NFT'
add rule inet host_firewall forward iifname "wan0" oifname "lan0" ip saddr 192.0.2.2 ip daddr 198.51.100.2 tcp dport 8080 ct state { new, established } accept
add rule inet host_firewall forward iifname "lan0" oifname "wan0" ip saddr 198.51.100.2 ip daddr 192.0.2.2 tcp sport 8080 ct state { established, related } accept
NFT
ip netns exec "$RTR_NS" nft list chain inet host_firewall forward

ip netns exec "$SRC_NS" python3 - <<'PY'
import socket
s = socket.socket()
s.settimeout(3.0)
try:
    s.connect(("198.51.100.2", 8080))
    s.sendall(b"coexistence")
    got = s.recv(1024)
    if got != b"ok:coexistence":
        raise SystemExit(f"FAIL: unexpected response: {got!r}")
finally:
    s.close()
print("PASS: a narrowly scoped rule in the owning host-firewall chain allows the intended TCP flow")
PY

echo 'PASS: nftables coexistence semantics verified in disposable namespaces; no live firewall was touched.'
