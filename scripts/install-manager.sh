#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Install the optional standalone PQTunnel web manager. This installer does not
start the manager or change tunnel, route, firewall, NAT, or forwarding state.

Usage:
  sudo ./scripts/install-manager.sh --source /path/to/source-or-Linux-bundle --role gateway
  sudo ./scripts/install-manager.sh --source /path/to/source-or-Linux-bundle --role dialer

The role is fixed in /etc/default/pqtunnel-manager:
  gateway -> pqtunneld.service and /etc/default/pqtunneld
  dialer  -> pqtunnel-client.service and /etc/default/pqtunnel-client

Before starting the manager, set PQTUNNEL_MANAGER_TOKEN to a random secret of
at least 32 bytes, then review the role/config. The manager binds only to a
literal loopback address and must be accessed remotely through SSH forwarding.
USAGE
}
fail() { echo "pqtunnel manager installer: $*" >&2; exit 1; }

SOURCE=""
ROLE=""
while (($#)); do
  case "$1" in
    --source) SOURCE="${2:?missing source path}"; shift 2 ;;
    --role) ROLE="${2:?missing role}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || fail 'run with sudo on the destination Linux server.'
[[ -n "$SOURCE" && -d "$SOURCE" ]] || fail '--source must point to a source tree or extracted Linux release bundle.'
[[ "$ROLE" == gateway || "$ROLE" == dialer ]] || fail '--role must be gateway or dialer.'
[[ -f "$SOURCE/deploy/systemd/pqtunnel-manager.service" ]] || fail 'deploy/systemd/pqtunnel-manager.service is missing.'
for path in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service /etc/default/pqtunnel-manager; do
  [[ ! -e "$path" ]] || fail "existing artifact detected at $path; refusing to overwrite it."
done
command -v systemctl >/dev/null || fail 'systemd is required.'
command -v install >/dev/null || fail 'install utility is required.'

TMPBIN=""
cleanup() { [[ -z "$TMPBIN" ]] || rm -f "$TMPBIN"; }
trap cleanup EXIT
if [[ -f "$SOURCE/go.mod" ]]; then
  command -v go >/dev/null || fail 'Go 1.24+ is required to build from source; use the matching Linux release bundle otherwise.'
  GV="$(go env GOVERSION | sed 's/^go//')"
  if ! awk -v v="$GV" 'BEGIN { split(v,a,"."); exit !((a[1]+0)>1 || ((a[1]+0)==1 && (a[2]+0)>=24)) }'; then
    fail "Go 1.24+ is required; found $GV."
  fi
  TMPBIN="$(mktemp)"
  (cd "$SOURCE" && GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$TMPBIN" ./cmd/pqtunnel-manager)
  BIN_SOURCE="$TMPBIN"
elif [[ -f "$SOURCE/pqtunnel-manager" ]]; then
  [[ "$(uname -s)" == Linux ]] || fail 'pqtunnel-manager is Linux/systemd-only.'
  BIN_SOURCE="$SOURCE/pqtunnel-manager"
else
  fail 'source tree must contain go.mod or release bundle must contain pqtunnel-manager.'
fi

install -d -o root -g root -m 0750 /var/lib/pqtunnel-manager
install -o root -g root -m 0755 "$BIN_SOURCE" /usr/local/sbin/pqtunnel-manager
install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunnel-manager.service" /etc/systemd/system/pqtunnel-manager.service
cat > /etc/default/pqtunnel-manager <<ENV
# Optional management UI. It remains stopped until you review this file and start it.
PQTUNNEL_MANAGER_ROLE=$ROLE
PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091
# Set this to a random secret of at least 32 bytes; never commit or share it.
PQTUNNEL_MANAGER_TOKEN=
ENV
chown root:root /etc/default/pqtunnel-manager
chmod 0600 /etc/default/pqtunnel-manager
systemctl daemon-reload

echo 'PQTunnel manager installed, but not enabled or started.'
echo 'Review /etc/default/pqtunnel-manager and set a strong PQTUNNEL_MANAGER_TOKEN first.'
echo 'Then run: sudo systemctl enable --now pqtunnel-manager'
echo 'For remote browser access, use SSH local forwarding; do not expose port 9091 publicly.'
echo 'No tunnel service, route, firewall, NAT, or forwarding settings were changed.'
