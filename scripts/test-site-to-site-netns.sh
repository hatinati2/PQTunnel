#!/usr/bin/env bash
# Isolated kernel/TUN integration test. All interfaces and routes live inside
# disposable network namespaces; this script does not change the host routes,
# forwarding sysctls, NAT, firewall, or interfaces.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $EUID -eq 0 ]] || { echo 'FAIL: run with sudo/root on a disposable Linux host' >&2; exit 2; }
for cmd in ip ss ping go; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "FAIL: required command not found: $cmd" >&2; exit 2; }
done
[[ -c /dev/net/tun ]] || { echo 'FAIL: /dev/net/tun is unavailable on this runner' >&2; exit 2; }

SUFFIX="$$"
IR_NS="pqt-iran-${SUFFIX}"
DE_NS="pqt-de-${SUFFIX}"
IR_VETH="pqi${SUFFIX}"
DE_VETH="pqd${SUFFIX}"
for ns in "$IR_NS" "$DE_NS"; do
  if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    echo "FAIL: refusing to reuse existing network namespace $ns" >&2
    exit 2
  fi
done
for iface in "$IR_VETH" "$DE_VETH"; do
  if ip link show dev "$iface" >/dev/null 2>&1; then
    echo "FAIL: refusing to reuse existing host interface $iface" >&2
    exit 2
  fi
done

LAB_DIR="$(mktemp -d -t pqtunnel-netns.XXXXXX)"
SERVER_PID=""
CLIENT_PID=""
SERVER_LOG="$LAB_DIR/server.log"
CLIENT_LOG="$LAB_DIR/client.log"
IR_PREFIXES="10.20.0.0/24,10.66.0.2/32,fd20:20::/64,fd42:7061:7475::2/128"
DE_PREFIXES="10.10.0.0/24,10.66.0.1/32,fd10:10::/64,fd42:7061:7475::1/128"

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  if [[ -n "$CLIENT_PID" ]]; then kill -TERM "$CLIENT_PID" >/dev/null 2>&1; wait "$CLIENT_PID" >/dev/null 2>&1; fi
  if [[ -n "$SERVER_PID" ]]; then kill -TERM "$SERVER_PID" >/dev/null 2>&1; wait "$SERVER_PID" >/dev/null 2>&1; fi
  ip netns del "$IR_NS" >/dev/null 2>&1
  ip netns del "$DE_NS" >/dev/null 2>&1
  ip link del "$IR_VETH" >/dev/null 2>&1
  if (( rc != 0 )); then
    echo '--- pqtunneld log (isolated test) ---' >&2
    [[ -f "$SERVER_LOG" ]] && cat "$SERVER_LOG" >&2
    echo '--- pqtunnel-client log (isolated test) ---' >&2
    [[ -f "$CLIENT_LOG" ]] && cat "$CLIENT_LOG" >&2
  fi
  rm -rf "$LAB_DIR"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 0700 "$LAB_DIR/bin" "$LAB_DIR/authority" "$LAB_DIR/server-pki" "$LAB_DIR/client-pki"
go build -o "$LAB_DIR/bin/pqtunneld" "$ROOT/cmd/pqtunneld"
go build -o "$LAB_DIR/bin/pqtunnel-client" "$ROOT/cmd/pqtunnel-client"
go build -o "$LAB_DIR/bin/pqtunnel-pki" "$ROOT/cmd/pqtunnel-pki"
"$LAB_DIR/bin/pqtunnel-pki" init --out "$LAB_DIR/authority" --server-name gateway.lab
"$LAB_DIR/bin/pqtunnel-pki" issue-peer --out "$LAB_DIR/authority" --name iran

# Keep CA private material outside both endpoint PKI directories.
cp "$LAB_DIR/authority/server.crt" "$LAB_DIR/server-pki/server.crt"
cp "$LAB_DIR/authority/server.key" "$LAB_DIR/server-pki/server.key"
cp "$LAB_DIR/authority/ca.crt" "$LAB_DIR/server-pki/ca.crt"
cp "$LAB_DIR/authority/ca.crt" "$LAB_DIR/client-pki/ca.crt"
cp "$LAB_DIR/authority/peer-iran.crt" "$LAB_DIR/client-pki/peer.crt"
cp "$LAB_DIR/authority/peer-iran.key" "$LAB_DIR/client-pki/peer.key"
chmod 0600 "$LAB_DIR/server-pki/server.key" "$LAB_DIR/client-pki/peer.key"

ip netns add "$IR_NS"
ip netns add "$DE_NS"
ip link add "$IR_VETH" type veth peer name "$DE_VETH"
ip link set "$IR_VETH" netns "$IR_NS"
ip link set "$DE_VETH" netns "$DE_NS"

ip -n "$IR_NS" link set lo up
ip -n "$DE_NS" link set lo up
ip -n "$IR_NS" addr add 198.18.0.2/30 dev "$IR_VETH"
ip -n "$DE_NS" addr add 198.18.0.1/30 dev "$DE_VETH"
ip -n "$IR_NS" link set "$IR_VETH" up
ip -n "$DE_NS" link set "$DE_VETH" up

# Simulated site LANs: dummy interfaces and routes are only inside these namespaces.
ip -n "$IR_NS" link add lanir type dummy
ip -n "$IR_NS" addr add 10.20.0.1/24 dev lanir
ip -n "$IR_NS" -6 addr add fd20:20::1/64 dev lanir
ip -n "$IR_NS" link set lanir up
ip -n "$DE_NS" link add lande type dummy
ip -n "$DE_NS" addr add 10.10.0.1/24 dev lande
ip -n "$DE_NS" -6 addr add fd10:10::1/64 dev lande
ip -n "$DE_NS" link set lande up

ip netns exec "$DE_NS" "$LAB_DIR/bin/pqtunneld" \
  --listen 198.18.0.1:8443 \
  --tls-cert "$LAB_DIR/server-pki/server.crt" \
  --tls-key "$LAB_DIR/server-pki/server.key" \
  --client-ca "$LAB_DIR/server-pki/ca.crt" \
  --tun pqtun0 --max-clients 1 \
  --peer-prefixes "$IR_PREFIXES" \
  --local-prefixes "$DE_PREFIXES" \
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
  local i
  for i in $(seq 1 100); do
    kill -0 "$SERVER_PID" >/dev/null 2>&1 || return 1
    if ip netns exec "$DE_NS" ss -ltnH 2>/dev/null | grep -Eq '198\.18\.0\.1:8443([[:space:]]|$)'; then return 0; fi
    sleep 0.1
  done
  return 1
}

wait_for_tun "$DE_NS" "$SERVER_PID" || { echo 'FAIL: gateway TUN did not appear' >&2; exit 1; }
ip -n "$DE_NS" addr add 10.66.0.1/24 dev pqtun0
ip -n "$DE_NS" -6 addr add fd42:7061:7475::1/64 dev pqtun0
ip -n "$DE_NS" link set pqtun0 up
ip -n "$DE_NS" route add 10.20.0.0/24 dev pqtun0
ip -n "$DE_NS" -6 route add fd20:20::/64 dev pqtun0
wait_for_listener || { echo 'FAIL: gateway did not listen on 198.18.0.1:8443' >&2; exit 1; }

ip netns exec "$IR_NS" "$LAB_DIR/bin/pqtunnel-client" \
  --server 198.18.0.1:8443 --server-name gateway.lab --network tcp4 \
  --ca "$LAB_DIR/client-pki/ca.crt" \
  --cert "$LAB_DIR/client-pki/peer.crt" \
  --key "$LAB_DIR/client-pki/peer.key" \
  --tun pqtun0 --local-prefixes "$IR_PREFIXES" --remote-prefixes "$DE_PREFIXES" \
  >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!

wait_for_tun "$IR_NS" "$CLIENT_PID" || { echo 'FAIL: dialer TUN did not appear' >&2; exit 1; }
ip -n "$IR_NS" addr add 10.66.0.2/24 dev pqtun0
ip -n "$IR_NS" -6 addr add fd42:7061:7475::2/64 dev pqtun0
ip -n "$IR_NS" link set pqtun0 up
ip -n "$IR_NS" route add 10.10.0.0/24 dev pqtun0
ip -n "$IR_NS" -6 route add fd10:10::/64 dev pqtun0

ping_until_success() {
  local ns="$1" family="$2" source="$3" target="$4" i
  for i in $(seq 1 10); do
    if [[ "$family" == 4 ]]; then
      ip netns exec "$ns" ping -n -c 1 -W 1 -I "$source" "$target" >/dev/null 2>&1 && return 0
    else
      ip netns exec "$ns" ping -6 -n -c 1 -W 1 -I "$source" "$target" >/dev/null 2>&1 && return 0
    fi
    sleep 0.25
  done
  return 1
}

ping_until_success "$IR_NS" 4 10.20.0.1 10.10.0.1 || { echo 'FAIL: IPv4 site-to-site ping failed' >&2; exit 1; }
ping_until_success "$IR_NS" 6 fd20:20::1 fd10:10::1 || { echo 'FAIL: IPv6 site-to-site ping failed' >&2; exit 1; }

echo 'PASS: mTLS, Linux TUN, IPv4/IPv6 routes, and two-way site-to-site packets passed inside disposable network namespaces.'
