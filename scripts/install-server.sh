#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Install PQTunnel server files on Ubuntu. This script does not alter UFW/firewall,
IP forwarding, NAT, or routes. Those are separate, explicit operations.

Usage:
  sudo ./scripts/install-server.sh --source /path/to/PQTunnel --pki /path/to/server-pki [--enable]

The PKI directory must contain server.crt, server.key and ca.crt.
Do NOT place ca.key on the server. --enable starts and enables the systemd unit;
without it, the unit is installed but left stopped/disabled.
USAGE
}

SOURCE=""
PKI=""
ENABLE=0
while (($#)); do
  case "$1" in
    --source) SOURCE="${2:?missing source path}"; shift 2 ;;
    --pki) PKI="${2:?missing PKI path}"; shift 2 ;;
    --enable) ENABLE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo 'Run this installer with sudo on the Ubuntu server.' >&2; exit 1; }
[[ -n "$SOURCE" && -d "$SOURCE" ]] || { echo '--source must point to an extracted project directory.' >&2; exit 2; }
[[ -n "$PKI" && -d "$PKI" ]] || { echo '--pki must point to a private directory with the server certificates.' >&2; exit 2; }
for f in server.crt server.key ca.crt; do
  [[ -s "$PKI/$f" ]] || { echo "Missing or empty PKI file: $PKI/$f" >&2; exit 1; }
done
command -v go >/dev/null || { echo 'Go 1.24+ is required. Build the binaries with Go 1.24+ first or install a supported Go toolchain.' >&2; exit 1; }
GV="$(go env GOVERSION | sed 's/^go//')"
if ! awk -v v="$GV" 'BEGIN { split(v,a,"."); exit !((a[1]+0)>1 || ((a[1]+0)==1 && (a[2]+0)>=24)) }'; then
  echo "Go 1.24+ is required; found $GV. No automatic toolchain installation is performed." >&2
  exit 1
fi
[[ -f "$SOURCE/go.mod" ]] || { echo 'go.mod not found under --source.' >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'systemd is required by this installer.' >&2; exit 1; }

TMPBIN="$(mktemp)"
trap 'rm -f "$TMPBIN"' EXIT
(
  cd "$SOURCE"
  GOTOOLCHAIN=local go build -trimpath -ldflags='-s -w' -o "$TMPBIN" ./cmd/pqtunneld
)

install -d -o root -g root -m 0750 /etc/pqtunnel /etc/pqtunnel/pki /var/lib/pqtunnel
install -o root -g root -m 0755 "$TMPBIN" /usr/local/sbin/pqtunneld
install -o root -g root -m 0644 "$PKI/server.crt" /etc/pqtunnel/pki/server.crt
install -o root -g root -m 0600 "$PKI/server.key" /etc/pqtunnel/pki/server.key
install -o root -g root -m 0644 "$PKI/ca.crt" /etc/pqtunnel/pki/ca.crt
install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunneld.service" /etc/systemd/system/pqtunneld.service

if [[ ! -e /etc/default/pqtunneld ]]; then
  cat > /etc/default/pqtunneld <<'ENV'
# PQTunnel server settings. Edit before enabling the service.
PQTUNNEL_LISTEN=0.0.0.0:8443
PQTUNNEL_MAX_CLIENTS=128
ENV
  chown root:root /etc/default/pqtunneld
  chmod 0640 /etc/default/pqtunneld
fi
systemctl daemon-reload

echo 'PQTunnel server binary, PKI files and systemd unit installed.'
echo 'No firewall, NAT, IP-forwarding, or route settings were changed.'
if (( ENABLE )); then
  systemctl enable --now pqtunneld
  echo 'pqtunneld is enabled and started. Apply the separate network script only after reviewing the firewall notes.'
else
  echo 'Service was NOT started. Review /etc/default/pqtunneld, then decide when to start it.'
  echo 'To enable/start later: systemctl enable --now pqtunneld'
fi
