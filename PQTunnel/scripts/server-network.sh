#!/usr/bin/env bash
set -Eeuo pipefail

TUN_IF="pqtun0"
SUBNET="10.66.0.0/24"
SYSCTL_FILE="/etc/sysctl.d/99-pqtunnel.conf"
STATE_DIR="/var/lib/pqtunnel"
STATE_FILE="$STATE_DIR/server-network.state"
NFT_TABLE="pqtunnel"

usage() {
  cat <<'USAGE'
Explicitly enable/disable IPv4 forwarding and NAT for PQTunnel on Ubuntu.

Usage:
  sudo ./scripts/server-network.sh status
  sudo ./scripts/server-network.sh apply --wan-if eth0
  sudo ./scripts/server-network.sh rollback

apply requires pqtun0 to exist (start pqtunneld first). It creates only the
nftables table named 'ip pqtunnel' and /etc/sysctl.d/99-pqtunnel.conf; it refuses
to overwrite either if already present. It does NOT modify UFW or other firewall
rules. If UFW/another firewall blocks forwarding, configure that separately.
rollback removes only this script's table/file and restores the previous value
of net.ipv4.ip_forward if it is still set to 1.
USAGE
}
fail() { echo "server-network: $*" >&2; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || fail 'run with sudo on the Ubuntu server'; }

MODE="${1:-}"
if [[ "$MODE" == -h || "$MODE" == --help || -z "$MODE" ]]; then usage; exit 0; fi
shift || true
WAN_IF=""
while (($#)); do
  case "$1" in
    --wan-if) WAN_IF="${2:?missing interface}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

case "$MODE" in
  status)
    printf 'pqtun interface: '; ip -brief link show "$TUN_IF" 2>/dev/null || true
    printf 'IPv4 forwarding: '; cat /proc/sys/net/ipv4/ip_forward
    if nft list table ip "$NFT_TABLE" >/dev/null 2>&1; then echo 'nftables table ip pqtunnel: present'; else echo 'nftables table ip pqtunnel: absent'; fi
    [[ -f "$SYSCTL_FILE" ]] && echo "$SYSCTL_FILE: present" || echo "$SYSCTL_FILE: absent"
    exit 0 ;;
  apply) ;;
  rollback) ;;
  *) usage >&2; exit 2 ;;
esac
need_root
command -v ip >/dev/null || fail 'iproute2 is required'
command -v nft >/dev/null || fail 'nftables (nft) is required'
command -v sysctl >/dev/null || fail 'sysctl is required'

if [[ "$MODE" == apply ]]; then
  [[ "$WAN_IF" =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]] || fail 'supply a valid --wan-if interface name'
  ip link show dev "$WAN_IF" >/dev/null 2>&1 || fail "WAN interface '$WAN_IF' not found"
  ip link show dev "$TUN_IF" >/dev/null 2>&1 || fail "TUN interface '$TUN_IF' not found; start pqtunneld first"
  [[ ! -e "$STATE_FILE" ]] || fail "state file already exists ($STATE_FILE); inspect it or use rollback first"
  [[ ! -e "$SYSCTL_FILE" ]] || fail "$SYSCTL_FILE already exists; refusing to overwrite it"
  nft list table ip "$NFT_TABLE" >/dev/null 2>&1 && fail "nftables table ip $NFT_TABLE already exists; refusing to modify it"

  install -d -o root -g root -m 0700 "$STATE_DIR"
  old_forward="$(cat /proc/sys/net/ipv4/ip_forward)"
  printf '%s\n%s\n' "$WAN_IF" "$old_forward" > "$STATE_FILE"
  chmod 0600 "$STATE_FILE"
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  cat > "$tmp" <<NFT
 table ip pqtunnel {
   chain forward {
     type filter hook forward priority filter; policy accept;
     iifname "$TUN_IF" oifname "$WAN_IF" ip saddr $SUBNET counter accept
     iifname "$WAN_IF" oifname "$TUN_IF" ip daddr $SUBNET ct state established,related counter accept
   }
   chain postrouting {
     type nat hook postrouting priority srcnat; policy accept;
     ip saddr $SUBNET oifname "$WAN_IF" counter masquerade
   }
 }
NFT
  nft -c -f "$tmp" || { rm -f "$STATE_FILE"; fail 'nftables validation failed; no firewall rules were applied'; }
  if ! { printf '# Managed by PQTunnel scripts/server-network.sh\nnet.ipv4.ip_forward=1\n' > "$SYSCTL_FILE" && chmod 0644 "$SYSCTL_FILE" && sysctl -w net.ipv4.ip_forward=1 >/dev/null && nft -f "$tmp"; }; then
    rm -f "$SYSCTL_FILE"
    sysctl -w "net.ipv4.ip_forward=$old_forward" >/dev/null || true
    rm -f "$STATE_FILE"
    fail 'apply failed; attempted to restore the original forwarding value'
  fi
  echo 'PQTunnel IPv4 forwarding/NAT rules applied.'
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
    echo 'WARNING: UFW is active. It may still block forwarded traffic; this script did not modify UFW.' >&2
  fi
  echo 'Review `sudo nft list table ip pqtunnel` and test from one client before adding more devices.'
else
  [[ -f "$STATE_FILE" ]] || fail "state file $STATE_FILE not found; nothing to roll back"
  mapfile -t state < "$STATE_FILE"
  [[ ${#state[@]} -ge 2 ]] || fail 'state file malformed; refusing rollback'
  old_forward="${state[1]}"
  [[ "$old_forward" == 0 || "$old_forward" == 1 ]] || fail 'invalid saved ip_forward value'
  if nft list table ip "$NFT_TABLE" >/dev/null 2>&1; then nft delete table ip "$NFT_TABLE"; fi
  if [[ -f "$SYSCTL_FILE" ]] && cmp -s "$SYSCTL_FILE" <(printf '# Managed by PQTunnel scripts/server-network.sh\nnet.ipv4.ip_forward=1\n'); then
    rm -f "$SYSCTL_FILE"
  else
    echo "WARNING: $SYSCTL_FILE was edited; leaving it in place rather than deleting administrator changes." >&2
  fi
  current_forward="$(cat /proc/sys/net/ipv4/ip_forward)"
  if [[ "$current_forward" == 1 ]]; then sysctl -w "net.ipv4.ip_forward=$old_forward" >/dev/null; fi
  rm -f "$STATE_FILE"
  echo 'PQTunnel NAT table removed; prior IPv4 forwarding value restored where safe.'
fi
