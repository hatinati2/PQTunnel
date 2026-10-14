#!/usr/bin/env bash
# Verify selective outbound TCP/UDP egress using disposable network namespaces.
# Only ports configured in the dialer helper should be observed at the Germany
# gateway's egress address; other traffic should retain the Iran WAN source.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "$BASH_SOURCE")/.." && pwd)"
cd "$ROOT"
[[ $EUID -eq 0 ]] || { echo 'FAIL: run this test with sudo/root on an isolated Linux host' >&2; exit 2; }
for cmd in ip ss nft python3; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "FAIL: required command missing: $cmd" >&2; exit 2; }
done
[[ -c /dev/net/tun ]] || { echo 'FAIL: /dev/net/tun is unavailable' >&2; exit 2; }
[[ -n "${PQTUNNEL_BIN_DIR:-}" && -d "${PQTUNNEL_BIN_DIR:-}" ]] || { echo 'FAIL: set PQTUNNEL_BIN_DIR to the CI-built binaries directory' >&2; exit 2; }
for bin in pqtunneld pqtunnel-client pqtunnel-pki; do
  [[ -x "$PQTUNNEL_BIN_DIR/$bin" ]] || { echo "FAIL: missing executable $PQTUNNEL_BIN_DIR/$bin" >&2; exit 2; }
done

SUFFIX="$$"
IR_NS="pqt-eir-$SUFFIX"
DE_NS="pqt-ede-$SUFFIX"
NET_NS="pqt-enet-$SUFFIX"
SW_NS="pqt-esw-$SUFFIX"
IR_IF="pqe$SUFFIX"
DE_IF="pqd$SUFFIX"
NET_IF="pqn$SUFFIX"
SW_IR_IF="sei$SUFFIX"
SW_DE_IF="sed$SUFFIX"
SW_NET_IF="sen$SUFFIX"
for ns in "$IR_NS" "$DE_NS" "$NET_NS" "$SW_NS"; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    echo "FAIL: refusing to reuse existing network namespace $ns" >&2
    exit 2
  fi
done
for iface in "$IR_IF" "$DE_IF" "$NET_IF" "$SW_IR_IF" "$SW_DE_IF" "$SW_NET_IF"; do
  if ip link show dev "$iface" >/dev/null 2>&1; then
    echo "FAIL: refusing to reuse existing host interface $iface" >&2
    exit 2
  fi
done

LAB_DIR="$(mktemp -d -t pqtunnel-egress.XXXXXX)"
SERVER_PID=""
CLIENT_PID=""
PROBE_PID=""
DIALER_CONFIG="$LAB_DIR/dialer.env"
GATEWAY_CONFIG="$LAB_DIR/gateway.env"
DIALER_STATE="$LAB_DIR/dialer-state"
GATEWAY_STATE="$LAB_DIR/gateway-state"
SERVER_LOG="$LAB_DIR/server.log"
CLIENT_LOG="$LAB_DIR/client.log"
PROBE_LOG="$LAB_DIR/probe-server.log"
PEER_PREFIXES="10.66.0.2/32,fd42:7061:7475::2/128"
TARGET_PREFIXES="198.18.0.3/32,2001:db8:feed::3/128"

wait_for_ipv6_addr_ready() {
  local ns="$1" iface="$2" addr="$3" line i
  for i in $(seq 1 100); do
    line="$(ip -n "$ns" -6 addr show dev "$iface" 2>/dev/null | grep -F "$addr/" || true)"
    if [[ -n "$line" && "$line" != *tentative* && "$line" != *dadfailed* ]]; then return 0; fi
    sleep 0.1
  done
  echo "FAIL: IPv6 address $addr on $ns/$iface did not finish duplicate-address detection" >&2
  return 1
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  if (( rc != 0 )); then
    for ns in "$IR_NS" "$DE_NS" "$NET_NS" "$SW_NS"; do
      if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
        echo "--- namespace $ns interfaces and routes ---" >&2
        ip -n "$ns" -brief address show >&2
        ip -n "$ns" route show table all >&2
        ip -n "$ns" -6 route show table all >&2
      fi
    done
    if ip netns list | awk '{print $1}' | grep -Fxq "$IR_NS"; then
      echo '--- dialer nftables/rules ---' >&2
      ip netns exec "$IR_NS" nft list ruleset >&2
      ip netns exec "$IR_NS" ip -4 rule show >&2
      ip netns exec "$IR_NS" ip -6 rule show >&2
      ip netns exec "$IR_NS" ip -4 route show table 518 >&2
      ip netns exec "$IR_NS" ip -6 route show table 518 >&2
    fi
    if ip netns list | awk '{print $1}' | grep -Fxq "$DE_NS"; then
      echo '--- gateway nftables/rules ---' >&2
      ip netns exec "$DE_NS" nft list ruleset >&2
      ip netns exec "$DE_NS" ip -4 rule show >&2
      ip netns exec "$DE_NS" ip -6 rule show >&2
    fi
  fi
  for pid in "$CLIENT_PID" "$SERVER_PID" "$PROBE_PID"; do
    if [[ -n "$pid" ]]; then kill -TERM "$pid" >/dev/null 2>&1; wait "$pid" >/dev/null 2>&1; fi
  done
  if ip netns list | awk '{print $1}' | grep -Fxq "$IR_NS"; then
    if [[ -f "$DIALER_STATE/site-selective-dialer.state" && -f "$DIALER_CONFIG" ]]; then
      ip netns exec "$IR_NS" env PQTUNNEL_SITE_CONFIG="$DIALER_CONFIG" PQTUNNEL_STATE_DIR="$DIALER_STATE" \
        bash "$ROOT/scripts/site-to-site-selective.sh" dialer-down >/dev/null 2>&1
    fi
  fi
  if ip netns list | awk '{print $1}' | grep -Fxq "$DE_NS"; then
    if [[ -f "$GATEWAY_STATE/site-selective-gateway.state" && -f "$GATEWAY_CONFIG" ]]; then
      ip netns exec "$DE_NS" env PQTUNNEL_SITE_CONFIG="$GATEWAY_CONFIG" PQTUNNEL_STATE_DIR="$GATEWAY_STATE" \
        bash "$ROOT/scripts/site-to-site-selective.sh" gateway-down >/dev/null 2>&1
    fi
  fi
  ip netns del "$IR_NS" >/dev/null 2>&1
  ip netns del "$DE_NS" >/dev/null 2>&1
  ip netns del "$NET_NS" >/dev/null 2>&1
  ip netns del "$SW_NS" >/dev/null 2>&1
  for iface in "$IR_IF" "$DE_IF" "$NET_IF" "$SW_IR_IF" "$SW_DE_IF" "$SW_NET_IF"; do ip link del "$iface" >/dev/null 2>&1; done
  if (( rc != 0 )); then
    for log in "$SERVER_LOG" "$CLIENT_LOG" "$PROBE_LOG"; do
      if [[ -s "$log" ]]; then echo "--- $log ---" >&2; cat "$log" >&2; fi
    done
  fi
  rm -rf "$LAB_DIR"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 0700 "$LAB_DIR/authority" "$LAB_DIR/server-pki" "$LAB_DIR/client-pki" "$DIALER_STATE" "$GATEWAY_STATE"
"$PQTUNNEL_BIN_DIR/pqtunnel-pki" init --out "$LAB_DIR/authority" --server-name gateway.lab
"$PQTUNNEL_BIN_DIR/pqtunnel-pki" issue-peer --out "$LAB_DIR/authority" --name iran
cp "$LAB_DIR/authority/server.crt" "$LAB_DIR/server-pki/server.crt"
cp "$LAB_DIR/authority/server.key" "$LAB_DIR/server-pki/server.key"
cp "$LAB_DIR/authority/ca.crt" "$LAB_DIR/server-pki/ca.crt"
cp "$LAB_DIR/authority/ca.crt" "$LAB_DIR/client-pki/ca.crt"
cp "$LAB_DIR/authority/peer-iran.crt" "$LAB_DIR/client-pki/peer.crt"
cp "$LAB_DIR/authority/peer-iran.key" "$LAB_DIR/client-pki/peer.key"
chmod 0600 "$LAB_DIR/server-pki/server.key" "$LAB_DIR/client-pki/peer.key"

cat >"$DIALER_CONFIG" <<CONFIG
PQTUNNEL_ROLE=dialer
PQTUNNEL_WAN_IF=$IR_IF
PQTUNNEL_TUN=pqtun0
PQTUNNEL_TCP_EGRESS_PORTS=443
PQTUNNEL_UDP_EGRESS_PORTS=53
PQTUNNEL_TCP_FORWARD_RULES=
PQTUNNEL_UDP_FORWARD_RULES=
CONFIG
cat >"$GATEWAY_CONFIG" <<CONFIG
PQTUNNEL_ROLE=gateway
PQTUNNEL_WAN_IF=$DE_IF
PQTUNNEL_TUN=pqtun0
CONFIG
chmod 0600 "$DIALER_CONFIG" "$GATEWAY_CONFIG"

ip netns add "$IR_NS"
ip netns add "$DE_NS"
ip netns add "$NET_NS"
ip netns add "$SW_NS"
# A switch namespace keeps all WAN-side links isolated from the CI host.
ip link add "$IR_IF" type veth peer name "$SW_IR_IF"
ip link set "$IR_IF" netns "$IR_NS"
ip link set "$SW_IR_IF" netns "$SW_NS"
ip link add "$DE_IF" type veth peer name "$SW_DE_IF"
ip link set "$DE_IF" netns "$DE_NS"
ip link set "$SW_DE_IF" netns "$SW_NS"
ip link add "$NET_IF" type veth peer name "$SW_NET_IF"
ip link set "$NET_IF" netns "$NET_NS"
ip link set "$SW_NET_IF" netns "$SW_NS"

for ns in "$IR_NS" "$DE_NS" "$NET_NS" "$SW_NS"; do ip -n "$ns" link set lo up; done
ip -n "$SW_NS" link add brlab type bridge
ip -n "$SW_NS" link set brlab type bridge mcast_snooping 0
ip -n "$SW_NS" link set "$SW_IR_IF" master brlab
ip -n "$SW_NS" link set "$SW_DE_IF" master brlab
ip -n "$SW_NS" link set "$SW_NET_IF" master brlab
for iface in "$SW_IR_IF" "$SW_DE_IF" "$SW_NET_IF"; do ip -n "$SW_NS" link set "$iface" up; done
ip -n "$SW_NS" link set brlab up

ip -n "$IR_NS" addr add 198.18.0.2/24 dev "$IR_IF"
ip -n "$IR_NS" -6 addr add 2001:db8:feed::2/64 dev "$IR_IF"
ip -n "$IR_NS" link set "$IR_IF" up
ip -n "$DE_NS" addr add 198.18.0.1/24 dev "$DE_IF"
ip -n "$DE_NS" -6 addr add 2001:db8:feed::1/64 dev "$DE_IF"
ip -n "$DE_NS" link set "$DE_IF" up
ip -n "$NET_NS" addr add 198.18.0.3/24 dev "$NET_IF"
ip -n "$NET_NS" -6 addr add 2001:db8:feed::3/64 dev "$NET_IF"
ip -n "$NET_NS" link set "$NET_IF" up
wait_for_ipv6_addr_ready "$IR_NS" "$IR_IF" "2001:db8:feed::2"
wait_for_ipv6_addr_ready "$DE_NS" "$DE_IF" "2001:db8:feed::1"
wait_for_ipv6_addr_ready "$NET_NS" "$NET_IF" "2001:db8:feed::3"

cat >"$LAB_DIR/probe-server.py" <<'PY'
import select
import socket

sockets = []
for family, host in [
    (socket.AF_INET, "198.18.0.3"),
    (socket.AF_INET6, "2001:db8:feed::3"),
]:
    for kind, port in [
        (socket.SOCK_STREAM, 443),
        (socket.SOCK_STREAM, 8080),
        (socket.SOCK_DGRAM, 53),
        (socket.SOCK_DGRAM, 5353),
    ]:
        s = socket.socket(family, kind)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET:
            s.bind((host, port))
        else:
            s.bind((host, port, 0, 0))
        if kind == socket.SOCK_STREAM:
            s.listen(8)
        sockets.append(s)

while True:
    readable, _, _ = select.select(sockets, [], [], 1.0)
    for s in readable:
        if s.type == socket.SOCK_STREAM:
            conn, addr = s.accept()
            with conn:
                conn.settimeout(2)
                conn.recv(2048)
                conn.sendall(str(addr[0]).encode("ascii"))
        else:
            _, addr = s.recvfrom(2048)
            s.sendto(str(addr[0]).encode("ascii"), addr)
PY
ip netns exec "$NET_NS" python3 -u "$LAB_DIR/probe-server.py" >"$PROBE_LOG" 2>&1 &
PROBE_PID=$!

ip netns exec "$DE_NS" "$PQTUNNEL_BIN_DIR/pqtunneld" \
  --listen 198.18.0.1:443 \
  --tls-cert "$LAB_DIR/server-pki/server.crt" \
  --tls-key "$LAB_DIR/server-pki/server.key" \
  --client-ca "$LAB_DIR/server-pki/ca.crt" \
  --tun pqtun0 --max-clients 1 \
  --peer-prefixes "$PEER_PREFIXES" \
  --local-prefixes "$TARGET_PREFIXES" \
  --peer-name iran >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

wait_for_tun() {
  local ns="$1" pid="$2" i
  for i in $(seq 1 100); do
    kill -0 "$pid" >/dev/null 2>&1 || return 1
    ip -n "$ns" link show dev pqtun0 >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}
wait_for_listener() {
  local ns="$1" addr="$2" port="$3" pid="$4" i
  for i in $(seq 1 100); do
    kill -0 "$pid" >/dev/null 2>&1 || return 1
    ip netns exec "$ns" ss -ltnH 2>/dev/null | grep -Fq "$addr:$port" && return 0
    sleep 0.1
  done
  return 1
}
wait_for_tun "$DE_NS" "$SERVER_PID" || { echo 'FAIL: Germany gateway TUN did not appear' >&2; exit 1; }
ip -n "$DE_NS" addr add 10.66.0.1/24 dev pqtun0
ip -n "$DE_NS" link set pqtun0 up
ip netns exec "$DE_NS" env PQTUNNEL_SITE_CONFIG="$GATEWAY_CONFIG" PQTUNNEL_STATE_DIR="$GATEWAY_STATE" \
  bash "$ROOT/scripts/site-to-site-selective.sh" gateway-up
wait_for_listener "$DE_NS" "198.18.0.1" 443 "$SERVER_PID" || { echo 'FAIL: Germany TLS listener did not start' >&2; exit 1; }

# The dialer helper creates the TUN and installs only TCP/443 and UDP/53 egress
# marks. The TLS transport itself uses port 443, so SO_MARK is required to keep
# the tunnel's own socket on the underlay instead of routing it into its TUN.
ip netns exec "$IR_NS" env PQTUNNEL_SITE_CONFIG="$DIALER_CONFIG" PQTUNNEL_STATE_DIR="$DIALER_STATE" \
  bash "$ROOT/scripts/site-to-site-selective.sh" dialer-up
ip netns exec "$IR_NS" "$PQTUNNEL_BIN_DIR/pqtunnel-client" \
  --server 198.18.0.1:443 --server-name gateway.lab --network tcp4 \
  --ca "$LAB_DIR/client-pki/ca.crt" \
  --cert "$LAB_DIR/client-pki/peer.crt" \
  --key "$LAB_DIR/client-pki/peer.key" \
  --tun pqtun0 --local-prefixes "$PEER_PREFIXES" \
  --remote-prefixes "$TARGET_PREFIXES" --socket-mark 20560 >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!

for i in $(seq 1 120); do
  kill -0 "$CLIENT_PID" >/dev/null 2>&1 || { echo 'FAIL: Iran dialer exited before the tunnel came up' >&2; exit 1; }
  if ip netns exec "$DE_NS" ss -tnH state established 2>/dev/null | grep -Fq '198.18.0.2'; then break; fi
  (( i < 120 )) || { echo 'FAIL: Iran dialer did not establish the tunnel' >&2; exit 1; }
  sleep 0.1
done

# Selected ports must be observed from Germany's WAN address; non-selected
# ports must keep the Iran WAN source address. Exercise both address families
# and both transport protocols using real sockets.
ip netns exec "$IR_NS" python3 - <<'PY'
import socket

tests = [
    ("tcp4-selected", socket.AF_INET, socket.SOCK_STREAM, ("198.18.0.3", 443), "198.18.0.1"),
    ("udp4-selected", socket.AF_INET, socket.SOCK_DGRAM, ("198.18.0.3", 53), "198.18.0.1"),
    ("tcp4-direct", socket.AF_INET, socket.SOCK_STREAM, ("198.18.0.3", 8080), "198.18.0.2"),
    ("udp4-direct", socket.AF_INET, socket.SOCK_DGRAM, ("198.18.0.3", 5353), "198.18.0.2"),
    ("tcp6-selected", socket.AF_INET6, socket.SOCK_STREAM, ("2001:db8:feed::3", 443, 0, 0), "2001:db8:feed::1"),
    ("udp6-selected", socket.AF_INET6, socket.SOCK_DGRAM, ("2001:db8:feed::3", 53, 0, 0), "2001:db8:feed::1"),
    ("tcp6-direct", socket.AF_INET6, socket.SOCK_STREAM, ("2001:db8:feed::3", 8080, 0, 0), "2001:db8:feed::2"),
    ("udp6-direct", socket.AF_INET6, socket.SOCK_DGRAM, ("2001:db8:feed::3", 5353, 0, 0), "2001:db8:feed::2"),
]
for name, family, kind, endpoint, expected_source in tests:
    s = socket.socket(family, kind)
    s.settimeout(6)
    if kind == socket.SOCK_STREAM:
        s.connect(endpoint)
        s.sendall(b"egress-probe")
        received = s.recv(256).decode("ascii")
    else:
        s.sendto(b"egress-probe", endpoint)
        received, _ = s.recvfrom(256)
        received = received.decode("ascii")
    s.close()
    if received != expected_source:
        raise SystemExit(f"FAIL: {name} observed source {received!r}; expected {expected_source!r}")
    print(f"PASS: selective egress {name} observed {received}", flush=True)
PY

echo 'PASS: selective TCP/UDP egress is tunneled only for configured ports over IPv4 and IPv6.'
