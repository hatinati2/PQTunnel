#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG="${PQTUNNEL_CLIENT_CONFIG:-/etc/pqtunnel/client.env}"
STATE="/run/pqtunnel-linux-client.state"
TUN_IF="pqtun0"
SERVER_IP=""
LOCAL_IP=""
DNS_IP="1.1.1.1"
IN_UP=0
CREATED_TUN=0
HOST_ROUTE=0
DEFAULT_ROUTE=0
V6_BLOCK=0
DNS_SET=0
WAN_IF=""
WAN_GW=""

usage() {
  cat <<'USAGE'
Configure a Linux client route to use PQTunnel. Run this on the CLIENT machine,
not the VPN server. The script does not launch pqtunnel-client itself.

1. Create /etc/pqtunnel/client.env from scripts/client.env.example.
2. sudo scripts/linux-client-network.sh up
3. Run pqtunnel-client with the matching server/local IP and certificates.
4. Stop pqtunnel-client, then deliberately restore the normal network with:
   sudo scripts/linux-client-network.sh down

The IPv4 default route stays pointed at TUN if the client process crashes, so
traffic is blackholed rather than falling back to the ordinary IPv4 route.
IPv6 default traffic is blackholed while up. This is not an audited firewall
kill-switch and it does not persist across reboot; do not claim zero-leak
protection on an unattended desktop until a persistent firewall policy is added.
USAGE
}
fail() { echo "linux-client-network: $*" >&2; exit 1; }
valid_ifname() { [[ "$1" =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]]; }
valid_ipv4() {
  local value="$1" a b c d octet
  [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r a b c d <<< "$value"
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}
cleanup_partial() {
  local rc=$?
  trap - ERR
  if (( IN_UP )); then
    (( DNS_SET )) && resolvectl revert "$TUN_IF" >/dev/null 2>&1 || true
    (( V6_BLOCK )) && ip -6 route del blackhole default metric 0 >/dev/null 2>&1 || true
    (( DEFAULT_ROUTE )) && ip -4 route del default dev "$TUN_IF" metric 5 >/dev/null 2>&1 || true
    if (( HOST_ROUTE )); then
      if [[ -n "$WAN_GW" ]]; then ip -4 route del "$SERVER_IP/32" via "$WAN_GW" dev "$WAN_IF" metric 50 >/dev/null 2>&1 || true
      else ip -4 route del "$SERVER_IP/32" dev "$WAN_IF" metric 50 >/dev/null 2>&1 || true; fi
    fi
    if [[ -n "$LOCAL_IP" ]]; then ip address del "$LOCAL_IP/32" dev "$TUN_IF" >/dev/null 2>&1 || true; fi
    ip link set dev "$TUN_IF" down >/dev/null 2>&1 || true
    if (( CREATED_TUN )); then ip tuntap del dev "$TUN_IF" mode tun >/dev/null 2>&1 || true; fi
  fi
  exit "$rc"
}

MODE="${1:-}"; shift || true
case "$MODE" in
  up|down|status) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
[[ $EUID -eq 0 ]] || fail 'run on the Linux client with sudo'
command -v ip >/dev/null || fail 'iproute2 is required'
command -v resolvectl >/dev/null || fail 'systemd-resolved/resolvectl is required for explicit tunnel DNS routing'

if [[ "$MODE" == status ]]; then
  ip -brief address show dev "$TUN_IF" 2>/dev/null || true
  ip -4 route show default
  ip -6 route show default
  resolvectl status "$TUN_IF" 2>/dev/null || true
  exit 0
fi

if [[ "$MODE" == up ]]; then
  [[ -r "$CONFIG" ]] || fail "configuration not found: $CONFIG (copy scripts/client.env.example first)"
  # This is a root-owned configuration file; it is intentionally treated as shell syntax.
  # shellcheck source=/dev/null
  source "$CONFIG"
  SERVER_IP="${PQTUNNEL_SERVER_IP:-}"
  LOCAL_IP="${PQTUNNEL_LOCAL_IP:-10.66.0.2}"
  TUN_IF="${PQTUNNEL_TUN:-pqtun0}"
  DNS_IP="${PQTUNNEL_DNS:-1.1.1.1}"
  valid_ipv4 "$SERVER_IP" || fail 'PQTUNNEL_SERVER_IP must be a valid literal IPv4 address (avoid bootstrap DNS leakage)'
  valid_ipv4 "$DNS_IP" || fail 'PQTUNNEL_DNS must be a valid literal IPv4 DNS server'
  valid_ipv4 "$LOCAL_IP" || fail 'PQTUNNEL_LOCAL_IP must be a valid IPv4 address'
  [[ "$LOCAL_IP" == 10.66.0.* ]] || fail 'PQTUNNEL_LOCAL_IP must currently be in 10.66.0.0/24'
  last_octet="${LOCAL_IP##*.}"
  (( 10#$last_octet >= 2 && 10#$last_octet <= 254 )) || fail 'PQTUNNEL_LOCAL_IP must be in 10.66.0.2..10.66.0.254'
  valid_ifname "$TUN_IF" || fail 'invalid TUN interface name'
  [[ ! -e "$STATE" ]] || fail "network setup already has state ($STATE); use status or down first"
  ip -4 route show exact "$SERVER_IP/32" | grep -q . && fail "a specific route to $SERVER_IP already exists; refusing to overwrite it"

  ROUTE="$(ip -4 route get "$SERVER_IP" 2>/dev/null | head -n1)"
  WAN_IF="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<< "$ROUTE")"
  WAN_GW="$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<< "$ROUTE")"
  [[ -n "$WAN_IF" && "$WAN_IF" != "$TUN_IF" ]] || fail "could not determine a physical route to $SERVER_IP"
  # The tunnel route uses metric 5. Refuse ambiguous/low-metric existing
  # defaults instead of accidentally leaving one physical route preferred.
  while IFS= read -r route; do
    [[ -n "$route" ]] || continue
    metric="$(awk '{for(i=1;i<=NF;i++) if($i=="metric"){print $(i+1); exit}}' <<< "$route")"
    [[ -n "$metric" ]] || fail "an IPv4 default route has no explicit metric ($route); set a deliberate metric before using full-tunnel mode"
    (( 10#$metric > 5 )) || fail "an IPv4 default route has metric <= 5 ($route); refusing a possible route leak"
  done <<< "$(ip -4 route show default)"
  while IFS= read -r route; do
    [[ -n "$route" ]] || continue
    metric="$(awk '{for(i=1;i<=NF;i++) if($i=="metric"){print $(i+1); exit}}' <<< "$route")"
    [[ -n "$metric" ]] || fail "an IPv6 default route has no explicit metric ($route); cannot verify that the blackhole wins"
    (( 10#$metric > 0 )) || fail "an IPv6 default route has metric 0 ($route); refusing a possible IPv6 leak"
  done <<< "$(ip -6 route show default)"

  IN_UP=1
  trap cleanup_partial ERR
  if ip link show dev "$TUN_IF" >/dev/null 2>&1; then
    fail "$TUN_IF already exists but no helper state is recorded; refusing to take over an existing interface. Inspect it before continuing."
  fi
  ip tuntap add dev "$TUN_IF" mode tun
  CREATED_TUN=1
  if [[ -n "$WAN_GW" ]]; then
    ip -4 route add "$SERVER_IP/32" via "$WAN_GW" dev "$WAN_IF" metric 50
  else
    ip -4 route add "$SERVER_IP/32" dev "$WAN_IF" metric 50
  fi
  HOST_ROUTE=1
  ip address replace "$LOCAL_IP/32" dev "$TUN_IF"
  ip link set dev "$TUN_IF" up
  ip -4 route add default dev "$TUN_IF" metric 5
  DEFAULT_ROUTE=1
  if ip -6 route show default | grep -q .; then
    ip -6 route add blackhole default metric 0
    V6_BLOCK=1
  fi
  resolvectl dns "$TUN_IF" "$DNS_IP"
  DNS_SET=1
  resolvectl domain "$TUN_IF" '~.'
  printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n' "$SERVER_IP" "$LOCAL_IP" "$TUN_IF" "$WAN_IF" "$WAN_GW" "$V6_BLOCK" "$CREATED_TUN" > "$STATE"
  chmod 0600 "$STATE"
  IN_UP=0
  trap - ERR
  echo "Routing prepared: IPv4 via $TUN_IF; DNS $DNS_IP routed through the tunnel; IPv6 default blocked when present."
  echo 'Now start pqtunnel-client separately. Keep this terminal/root access available.'
  echo 'This script did not change the server or install any software.'
  exit 0
fi

[[ -r "$STATE" ]] || fail "no network state found ($STATE); nothing to restore"
mapfile -t S < "$STATE"
[[ ${#S[@]} -ge 7 ]] || fail 'state file malformed; refusing cleanup'
SERVER_IP="${S[0]}"; LOCAL_IP="${S[1]}"; TUN_IF="${S[2]}"; WAN_IF="${S[3]}"; WAN_GW="${S[4]}"; V6_BLOCK="${S[5]}"; CREATED_TUN="${S[6]}"
if pgrep -x pqtunnel-client >/dev/null 2>&1; then fail 'stop pqtunnel-client first; then run down to deliberately restore ordinary networking'; fi
resolvectl revert "$TUN_IF" >/dev/null 2>&1 || true
ip -4 route del default dev "$TUN_IF" metric 5 >/dev/null 2>&1 || true
if [[ "$V6_BLOCK" == 1 ]]; then ip -6 route del blackhole default metric 0 >/dev/null 2>&1 || true; fi
if [[ -n "$WAN_GW" ]]; then ip -4 route del "$SERVER_IP/32" via "$WAN_GW" dev "$WAN_IF" metric 50 >/dev/null 2>&1 || true
else ip -4 route del "$SERVER_IP/32" dev "$WAN_IF" metric 50 >/dev/null 2>&1 || true; fi
ip address del "$LOCAL_IP/32" dev "$TUN_IF" >/dev/null 2>&1 || true
ip link set dev "$TUN_IF" down >/dev/null 2>&1 || true
if [[ "$CREATED_TUN" == 1 ]]; then ip tuntap del dev "$TUN_IF" mode tun >/dev/null 2>&1 || true; fi
rm -f "$STATE"
echo 'Network routes/DNS restored. Ordinary Internet routing is intentionally available again.'
