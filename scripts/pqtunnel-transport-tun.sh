#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ $# -eq 2 ]] || { echo "Usage: pqtunnel-transport-tun.sh gateway|dialer up|down" >&2; exit 2; }
ROLE="$1"
ACTION="$2"
TUN=pqtun0
STATE=/var/lib/pqtunnel/pqtunnel-transport-owner

case "$ROLE:$ACTION" in
  gateway:up) V4=10.66.0.1/24; V6=fd42:7061:7475::1/64 ;;
  dialer:up) V4=10.66.0.2/24; V6=fd42:7061:7475::2/64 ;;
  gateway:down|dialer:down) ;;
  *) echo "Usage: pqtunnel-transport-tun.sh gateway|dialer up|down" >&2; exit 2 ;;
esac

[[ "$(id -u)" == 0 ]] || { echo "root privileges are required" >&2; exit 1; }
install -d -o root -g root -m 0750 /var/lib/pqtunnel

if [[ "$ACTION" == up ]]; then
  if ip link show dev "$TUN" >/dev/null 2>&1; then
    echo "pqtun0 already exists; refusing to take ownership of an unmanaged interface" >&2
    exit 1
  fi
  if [[ -n "$(ip -4 route show 10.66.0.0/24 2>/dev/null)" || -n "$(ip -6 route show fd42:7061:7475::/64 2>/dev/null)" ]]; then
    echo "the PQTunnel transport subnet already has a route; refusing to add a conflicting TUN" >&2
    exit 1
  fi
  created=0
  cleanup() {
    if (( created )); then
      ip link del dev "$TUN" >/dev/null 2>&1 || true
      rm -f "$STATE"
    fi
  }
  trap cleanup ERR
  ip tuntap add dev "$TUN" mode tun
  created=1
  printf '%s\n' "$ROLE" > "$STATE"
  chown root:root "$STATE"
  chmod 0600 "$STATE"
  ip address add "$V4" dev "$TUN"
  ip -6 address add "$V6" dev "$TUN" nodad
  ip link set dev "$TUN" up
  trap - ERR
  echo "PQTunnel transport interface configured. No firewall, forwarding, NAT, or policy-routing rules were changed."
  exit 0
fi

if [[ ! -e "$STATE" ]]; then
  exit 0
fi
[[ -f "$STATE" && ! -L "$STATE" ]] || { echo "transport ownership state is unsafe" >&2; exit 1; }
owner="$(cat "$STATE")"
[[ "$owner" == "$ROLE" ]] || { echo "transport interface is owned by a different PQTunnel role; refusing cleanup" >&2; exit 1; }
if ip link show dev "$TUN" >/dev/null 2>&1; then
  ip link del dev "$TUN"
fi
rm -f "$STATE"
echo "PQTunnel transport interface removed; no firewall or policy-routing rules were changed."
