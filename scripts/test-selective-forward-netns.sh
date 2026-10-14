#!/usr/bin/env bash
# Test the selective inbound TCP/UDP port-forward helper using only disposable
# network namespaces. No host routes, firewall rules, NAT, or sysctls are changed.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"
[[ $EUID -eq 0 ]] || { echo 'FAIL: run this test with sudo/root on an isolated Linux host' >&2; exit 2; }
for cmd in ip ss nft python3 go; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "FAIL: required command missing: $cmd" >&2; exit 2; }
done
[[ -c /dev/net/tun ]] || { echo 'FAIL: /dev/net/tun is unavailable' >&2; exit 2; }
[[ -n "${PQTUNNEL_BIN_DIR:-}" && -d "$PQTUNNEL_BIN_DIR" ]] || { echo 'FAIL: set PQTUNNEL_BIN_DIR to the CI-built binaries directory' >&2; exit 2; }
for bin in pqtunneld pqtunnel-client pqtunnel-pki; do
  [[ -x "$PQTUNNEL_BIN_DIR/$bin" ]] || { echo "FAIL: missing executable $PQTUNNEL_BIN_DIR/$bin" >&2; exit 2; }
done

SUFFIX="$$"
IR_NS="pqt-sir-$SUFFIX"
DE_NS="pqt-sde-$SUFFIX"
VIS_NS="pqt-svi-$SUFFIX"
IR_DE_IF="pqi$SUFFIX"
DE_IF="pqd$SUFFIX"
IR_VIS_IF="pvv$SUFFIX"
VIS_IF="pvi$SUFFIX"
for ns in "$IR_NS" "$DE_NS" "$VIS_NS"; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    echo "FAIL: refusing to reuse existing network namespace $ns" >&2
    exit 2
  fi
done
for iface in "$IR_DE_IF" "$DE_IF" "$IR_VIS_IF" "$VIS_IF"; do
  if ip link show dev "$iface" >/dev/null 2>&1; then
    echo "FAIL: refusing to reuse existing host interface $iface" >&2
    exit 2
  fi
done

LAB_DIR="$(mktemp -d -t pqtunnel-forward.XXXXXX)"
SERVER_PID=""
CLIENT_PID=""
TCP4_PID=""
UDP4_PID=""
TCP6_PID=""
UDP6_PID=""
SERVER_LOG="$LAB_DIR/server.log"
CLIENT_LOG="$LAB_DIR/client.log"
TCP4_LOG="$LAB_DIR/tcp4.log"
UDP4_LOG="$LAB_DIR/udp4.log"
TCP6_LOG="$LAB_DIR/tcp6.log"
UDP6_LOG="$LAB_DIR/udp6.log"
DIALER_CONFIG="$LAB_DIR/dialer.env"
STATE_DIR="$LAB_DIR/dialer-state"
STATE_FILE="$STATE_DIR/site-selective-dialer.state"
PEER_PREFIXES="10.66.0.2/32,fd42:7061:7475::2/128"
LOCAL_PREFIXES="10.10.0.1/32,fd10:10::1/128"

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  if [[ -n "$CLIENT_PID" ]]; then kill -TERM "$CLIENT_PID" >/dev/null 2>&1; wait "$CLIENT_PID" >/dev/null 2>&1; fi
  if [[ -n "$IR_NS" ]] && ip netns list | awk '{print $1}' | grep -Fxq "$IR_NS"; then
    if [[ -f "$STATE_FILE" && -f "$DIALER_CONFIG" ]]; then
      ip netns exec "$IR_NS" env PQTUNNEL_SITE_CONFIG="$DIALER_CONFIG" PQTUNNEL_STATE_DIR="$STATE_DIR" \
        bash "$ROOT/scripts/site-to-site-selective.sh" dialer-down >/dev/null 2>&1
    fi
  fi
  for pid in "$TCP4_PID" "$UDP4_PID" "$TCP6_PID" "$UDP6_PID" "$SERVER_PID"; do
    if [[ -n "$pid" ]]; then kill -TERM "$pid" >/dev/null 2>&1; wait "$pid" >/dev/null 2>&1; fi
  done
  ip netns del "$VIS_NS" >/dev/null 2>&1
  ip netns del "$IR_NS" >/dev/null 2>&1
  ip netns del "$DE_NS" >/dev/null 2>&1
  ip link del "$IR_DE_IF" >/dev/null 2>&1
  ip link del "$IR_VIS_IF" >/dev/null 2>&1
  if (( rc != 0 )); then
    for log in "$SERVER_LOG" "$CLIENT_LOG" "$TCP4_LOG" "$UDP4_LOG" "$TCP6_LOG" "$UDP6_LOG"; do
      if [[ -s "$log" ]]; then echo "--- $log ---" >&2; cat "$log" >&2; fi
    done
  fi
  rm -rf "$LAB_DIR"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 0700 "$LAB_DIR/authority" "$LAB_DIR/server-pki" "$LAB_DIR/client-pki" "$STATE_DIR"
"$PQTUNNEL_BIN_DIR/pqtunnel-pki" init --out "$LAB_DIR/authority" --server-name gateway.lab
"$PQTUNNEL_BIN_DIR/pqtunnel-pki" issue-peer --out "$LAB_DIR/authority" --name iran
cp "$LAB_DIR/authority/server.crt" "$LAB_DIR/server-pki/server.crt"
cp "$LAB_DIR/authority/server.key" "$LAB_DIR/server-pki/server.key"
cp "$LAB_DIR/authority/ca.crt" "$LAB_DIR/server-pki/ca.crt"
cp "$LAB_DIR/authority/ca.crt" "$LAB_DIR/client-pki/ca.crt"
cp "$LAB_DIR/authority/peer-iran.crt" "$LAB_DIR/client-pki/peer.crt"
cp "$LAB_DIR/authority/peer-iran.key" "$LAB_DIR/client-pki/peer.key"
chmod 0600 "$LAB_DIR/server-pki/server.key" "$LAB_DIR/client-pki/peer.key"

cat > "$DIALER_CONFIG" <<'CONFIG'
PQTUNNEL_ROLE=dialer
PQTUNNEL_WAN_IF=brwan
PQTUNNEL_TUN=pqtun0
PQTUNNEL_TCP_EGRESS_PORTS=
PQTUNNEL_UDP_EGRESS_PORTS=
PQTUNNEL_TCP_FORWARD_RULES='8443=10.10.0.1:8080,9443=[fd10:10::1]:8080'
PQTUNNEL_UDP_FORWARD_RULES='5354=10.10.0.1:5353,5355=[fd10:10::1]:5353'
CONFIG
chmod 0600 "$DIALER_CONFIG"

ip netns add "$IR_NS"
ip netns add "$DE_NS"
ip netns add "$VIS_NS"
# Some hosted kernels enable forwarding by default. Reset only the disposable
# Iran namespace so the helper can verify and record a known starting state.
ip netns exec "$IR_NS" sysctl -w net.ipv4.ip_forward=0 >/dev/null
ip netns exec "$IR_NS" sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null
ip link add "$IR_DE_IF" type veth peer name "$DE_IF"
ip link set "$IR_DE_IF" netns "$IR_NS"
ip link set "$DE_IF" netns "$DE_NS"
ip link add "$IR_VIS_IF" type veth peer name "$VIS_IF"
ip link set "$IR_VIS_IF" netns "$IR_NS"
ip link set "$VIS_IF" netns "$VIS_NS"

for ns in "$IR_NS" "$DE_NS" "$VIS_NS"; do ip -n "$ns" link set lo up; done
ip -n "$IR_NS" link add brwan type bridge
ip -n "$IR_NS" link set "$IR_DE_IF" master brwan
ip -n "$IR_NS" link set "$IR_VIS_IF" master brwan
ip -n "$IR_NS" addr add 198.18.0.2/24 dev brwan
ip -n "$IR_NS" -6 addr add 2001:db8:feed::2/64 dev brwan
ip -n "$IR_NS" link set "$IR_DE_IF" up
ip -n "$IR_NS" link set "$IR_VIS_IF" up
ip -n "$IR_NS" link set brwan up

ip -n "$DE_NS" addr add 198.18.0.1/24 dev "$DE_IF"
ip -n "$DE_NS" -6 addr add 2001:db8:feed::1/64 dev "$DE_IF"
ip -n "$DE_NS" link set "$DE_IF" up
ip -n "$VIS_NS" addr add 198.18.0.3/24 dev "$VIS_IF"
ip -n "$VIS_NS" -6 addr add 2001:db8:feed::3/64 dev "$VIS_IF"
ip -n "$VIS_NS" link set "$VIS_IF" up

ip -n "$DE_NS" link add lande type dummy
ip -n "$DE_NS" addr add 10.10.0.1/24 dev lande
ip -n "$DE_NS" -6 addr add fd10:10::1/64 dev lande
ip -n "$DE_NS" link set lande up

cat > "$LAB_DIR/tcp4.py" <<'PY'
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.10.0.1", 8080))
s.listen(1)
c, _ = s.accept()
with c:
    data = c.recv(4096)
    c.sendall(b"tcp4:" + data)
s.close()
PY
cat > "$LAB_DIR/udp4.py" <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.10.0.1", 5353))
data, addr = s.recvfrom(4096)
s.sendto(b"udp4:" + data, addr)
s.close()
PY
cat > "$LAB_DIR/tcp6.py" <<'PY'
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("fd10:10::1", 8080, 0, 0))
s.listen(1)
c, _ = s.accept()
with c:
    data = c.recv(4096)
    c.sendall(b"tcp6:" + data)
s.close()
PY
cat > "$LAB_DIR/udp6.py" <<'PY'
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("fd10:10::1", 5353, 0, 0))
data, addr = s.recvfrom(4096)
s.sendto(b"udp6:" + data, addr)
s.close()
PY
ip netns exec "$DE_NS" python3 -u "$LAB_DIR/tcp4.py" >"$TCP4_LOG" 2>&1 & TCP4_PID=$!
ip netns exec "$DE_NS" python3 -u "$LAB_DIR/udp4.py" >"$UDP4_LOG" 2>&1 & UDP4_PID=$!
ip netns exec "$DE_NS" python3 -u "$LAB_DIR/tcp6.py" >"$TCP6_LOG" 2>&1 & TCP6_PID=$!
ip netns exec "$DE_NS" python3 -u "$LAB_DIR/udp6.py" >"$UDP6_LOG" 2>&1 & UDP6_PID=$!

ip netns exec "$DE_NS" "$PQTUNNEL_BIN_DIR/pqtunneld" \
  --listen 198.18.0.1:8443 \
  --tls-cert "$LAB_DIR/server-pki/server.crt" \
  --tls-key "$LAB_DIR/server-pki/server.key" \
  --client-ca "$LAB_DIR/server-pki/ca.crt" \
  --tun pqtun0 --max-clients 1 \
  --peer-prefixes "$PEER_PREFIXES" \
  --local-prefixes "$LOCAL_PREFIXES" \
  --peer-name iran >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

wait_for_listener() {
  local i
  for i in $(seq 1 100); do
    kill -0 "$SERVER_PID" >/dev/null 2>&1 || return 1
    if ip netns exec "$DE_NS" ss -ltnH 2>/dev/null | grep -Eq '198\.18\.0\.1:8443([[:space:]]|$)'; then return 0; fi
    sleep 0.1
  done
  return 1
}
wait_for_service() {
  local proto="$1" port="$2" i
  for i in $(seq 1 100); do
    if [[ "$proto" == tcp ]]; then
      ip netns exec "$DE_NS" ss -ltnH 2>/dev/null | grep -Eq "[:.]$port([[:space:]]|$)" && return 0
    else
      ip netns exec "$DE_NS" ss -lunH 2>/dev/null | grep -Eq "[:.]$port([[:space:]]|$)" && return 0
    fi
    sleep 0.1
  done
  return 1
}
wait_for_listener || { echo 'FAIL: Germany gateway listener did not start' >&2; exit 1; }
for port in 8080; do wait_for_service tcp "$port" || { echo "FAIL: TCP test target $port did not start" >&2; exit 1; }; done
for port in 5353; do wait_for_service udp "$port" || { echo "FAIL: UDP test target $port did not start" >&2; exit 1; }; done

# This deliberately changes only the dialer namespace. All routes, nftables,
# forwarding sysctls and TUN changes are confined to the disposable Iran namespace.
ip netns exec "$IR_NS" env PQTUNNEL_SITE_CONFIG="$DIALER_CONFIG" PQTUNNEL_STATE_DIR="$STATE_DIR" \
  bash "$ROOT/scripts/site-to-site-selective.sh" dialer-up

ip netns exec "$IR_NS" "$PQTUNNEL_BIN_DIR/pqtunnel-client" \
  --server 198.18.0.1:8443 --server-name gateway.lab --network tcp4 \
  --ca "$LAB_DIR/client-pki/ca.crt" \
  --cert "$LAB_DIR/client-pki/peer.crt" \
  --key "$LAB_DIR/client-pki/peer.key" \
  --tun pqtun0 \
  --local-prefixes "$PEER_PREFIXES" \
  --remote-prefixes "$LOCAL_PREFIXES" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!

wait_for_client() {
  local i
  for i in $(seq 1 120); do
    kill -0 "$CLIENT_PID" >/dev/null 2>&1 || return 1
    if ip netns exec "$DE_NS" ss -tnH state established 2>/dev/null | grep -q '198\.18\.0\.2'; then return 0; fi
    sleep 0.1
  done
  return 1
}
wait_for_client || { echo 'FAIL: Iran dialer did not establish the tunnel to Germany' >&2; exit 1; }

ip netns exec "$VIS_NS" python3 - <<'PY'
import socket
tests = [
    ("tcp4", socket.AF_INET, socket.SOCK_STREAM, ("198.18.0.2", 8443), b"hello-v4", b"tcp4:hello-v4"),
    ("udp4", socket.AF_INET, socket.SOCK_DGRAM, ("198.18.0.2", 5354), b"hello-v4", b"udp4:hello-v4"),
    ("tcp6", socket.AF_INET6, socket.SOCK_STREAM, ("2001:db8:feed::2", 9443, 0, 0), b"hello-v6", b"tcp6:hello-v6"),
    ("udp6", socket.AF_INET6, socket.SOCK_DGRAM, ("2001:db8:feed::2", 5355, 0, 0), b"hello-v6", b"udp6:hello-v6"),
]
for name, family, kind, endpoint, payload, expected in tests:
    s = socket.socket(family, kind)
    s.settimeout(6)
    if kind == socket.SOCK_STREAM:
        s.connect(endpoint)
        s.sendall(payload)
        received = s.recv(4096)
    else:
        s.sendto(payload, endpoint)
        received, _ = s.recvfrom(4096)
    s.close()
    if received != expected:
        raise SystemExit(f"FAIL: {name} returned {received!r}; expected {expected!r}")
    print(f"PASS: selective {name} port-forward round-trip")
PY

echo 'PASS: selective TCP/UDP port forwarding across IPv4 and IPv6 passed inside disposable network namespaces.'
