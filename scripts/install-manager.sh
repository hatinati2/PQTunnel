#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Install the optional standalone PQTunnel web manager. This installer does not
start the manager or change tunnel, route, firewall, NAT, or forwarding state.

Usage:
  sudo bash ./scripts/install-manager.sh --source /path/to/source-or-Linux-bundle --role gateway
  sudo bash ./scripts/install-manager.sh --source /path/to/source-or-Linux-bundle --role dialer

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
UPGRADE=0
while (($#)); do
  case "$1" in
    --source) SOURCE="${2:?missing source path}"; shift 2 ;;
    --role) ROLE="${2:?missing role}"; shift 2 ;;
    --upgrade) UPGRADE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || fail 'run with sudo on the destination Linux server.'
[[ -n "$SOURCE" && -d "$SOURCE" ]] || fail '--source must point to a source tree or extracted Linux release bundle.'
[[ "$ROLE" == gateway || "$ROLE" == dialer ]] || fail '--role must be gateway or dialer.'
[[ -f "$SOURCE/deploy/systemd/pqtunnel-manager.service" ]] || fail 'deploy/systemd/pqtunnel-manager.service is missing.'
[[ -f "$SOURCE/deploy/systemd/pqtunnel-setup.service" ]] || fail 'deploy/systemd/pqtunnel-setup.service is missing.'
[[ -f "$SOURCE/scripts/pqtunnel-setup-worker.sh" && -f "$SOURCE/scripts/pqtunnel-site-to-site-setup.sh" ]] || fail 'graphical setup worker scripts are missing; use a release containing the setup wizard.'
SOURCE_VERSION="$(basename "$SOURCE" | sed -nE 's/^PQTunnel-(v[0-9A-Za-z._-]+)-linux-(amd64|arm64)$/\1/p')"
if [[ -z "$SOURCE_VERSION" && -f "$SOURCE/install.sh" ]]; then
  SOURCE_VERSION="$(sed -nE 's/^VERSION="(v[0-9A-Za-z._-]+)"$/\1/p' "$SOURCE/install.sh" | head -n1)"
fi
[[ "$SOURCE_VERSION" =~ ^v[0-9A-Za-z._-]+$ ]] || fail 'could not determine the installed setup helper release version.'
command -v systemctl >/dev/null || fail 'systemd is required.'
command -v systemd-analyze >/dev/null || fail 'systemd-analyze is required.'
command -v install >/dev/null || fail 'install utility is required.'

EXISTING_COUNT=0
for path in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service /etc/default/pqtunnel-manager; do
  [[ ! -e "$path" ]] || EXISTING_COUNT=$((EXISTING_COUNT + 1))
done
if (( UPGRADE )); then
  (( EXISTING_COUNT == 3 )) || fail '--upgrade requires a complete existing manager installation; inspect partial installs manually.'
  [[ -f /etc/default/pqtunnel-manager && ! -L /etc/default/pqtunnel-manager ]] || fail 'existing manager config is not a regular file.'
  EXISTING_ROLE="$(sed -n 's/^PQTUNNEL_MANAGER_ROLE=//p' /etc/default/pqtunnel-manager | head -n1)"
  [[ "$EXISTING_ROLE" == "$ROLE" ]] || fail "existing manager role is '$EXISTING_ROLE', not '$ROLE'; refusing role changes."
  [[ "$(stat -c '%a' /etc/default/pqtunnel-manager)" == 600 ]] || fail 'existing manager config must be mode 0600 before upgrade.'
else
  (( EXISTING_COUNT == 0 )) || fail 'existing manager artifacts detected; use --upgrade to back up and upgrade a complete installation.'
fi

TMPBIN=""
BACKUP_DIR=""
NEW_MANAGER_TOKEN=""
cleanup() { [[ -z "$TMPBIN" ]] || rm -f "$TMPBIN"; unset NEW_MANAGER_TOKEN; }
trap cleanup EXIT
if [[ -f "$SOURCE/go.mod" ]]; then
  command -v go >/dev/null || fail 'Go 1.26+ is required to build from source; use the matching Linux release bundle otherwise.'
  GV="$(go env GOVERSION | sed 's/^go//')"
  if ! awk -v v="$GV" 'BEGIN { split(v,a,"."); exit !((a[1]+0)>1 || ((a[1]+0)==1 && (a[2]+0)>=26)) }'; then
    fail "Go 1.26+ is required; found $GV."
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

install -d -o root -g root -m 0750 /var/lib/pqtunnel-manager/backups /usr/local/lib/pqtunnel
if (( UPGRADE )); then
  BACKUP_DIR="/var/lib/pqtunnel-manager/backups/manager-upgrade-$(date +%Y%m%d-%H%M%S)"
  install -d -o root -g root -m 0700 "$BACKUP_DIR"
  cp -a /usr/local/sbin/pqtunnel-manager "$BACKUP_DIR/pqtunnel-manager"
  cp -a /etc/systemd/system/pqtunnel-manager.service "$BACKUP_DIR/pqtunnel-manager.service"
  cp -a /etc/default/pqtunnel-manager "$BACKUP_DIR/pqtunnel-manager.env"
fi

install -o root -g root -m 0755 "$BIN_SOURCE" /usr/local/sbin/pqtunnel-manager
install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunnel-manager.service" /etc/systemd/system/pqtunnel-manager.service
install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunnel-setup.service" /etc/systemd/system/pqtunnel-setup.service
install -o root -g root -m 0750 "$SOURCE/scripts/pqtunnel-setup-worker.sh" /usr/local/lib/pqtunnel/pqtunnel-setup-worker.sh
install -o root -g root -m 0750 "$SOURCE/scripts/pqtunnel-site-to-site-setup.sh" /usr/local/lib/pqtunnel/pqtunnel-site-to-site-setup.sh

if (( UPGRADE )); then
  config_tmp="$(mktemp /etc/default/pqtunnel-manager.XXXXXX)"
  awk '!/^(PQTUNNEL_SETUP_VERSION|PQTUNNEL_MANAGER_LISTEN|PQTUNNEL_MANAGER_TOKEN|PQTUNNEL_MANAGER_PUBLIC_HOST|PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP|PQTUNNEL_MANAGER_TLS_CERT|PQTUNNEL_MANAGER_TLS_KEY)=/' /etc/default/pqtunnel-manager > "$config_tmp"
  old_listen="$(sed -n 's/^PQTUNNEL_MANAGER_LISTEN=//p' /etc/default/pqtunnel-manager | head -n1)"
  old_insecure="$(sed -n 's/^PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=//p' /etc/default/pqtunnel-manager | head -n1)"
  if [[ "$old_insecure" == true || ! "$old_listen" =~ ^(127\.0\.0\.1:[0-9]+|\[::1\]:[0-9]+)$ ]]; then
    NEW_MANAGER_TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
    [[ "$NEW_MANAGER_TOKEN" =~ ^[0-9a-f]{64}$ ]] || fail 'could not generate a replacement manager token; upgrade stopped.'
    printf 'PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091\nPQTUNNEL_MANAGER_TOKEN=%s\n' "$NEW_MANAGER_TOKEN" >> "$config_tmp"
  else
    printf 'PQTUNNEL_MANAGER_LISTEN=%s\n' "$old_listen" >> "$config_tmp"
    old_token="$(sed -n 's/^PQTUNNEL_MANAGER_TOKEN=//p' /etc/default/pqtunnel-manager | head -n1)"
    [[ "$old_token" =~ ^[A-Za-z0-9_.,:/=\-\[\]]{32,}$ ]] || fail 'existing manager token is missing or invalid; repair it locally before upgrading.'
    printf 'PQTUNNEL_MANAGER_TOKEN=%s\n' "$old_token" >> "$config_tmp"
  fi
  printf 'PQTUNNEL_SETUP_VERSION=%s\n' "$SOURCE_VERSION" >> "$config_tmp"
  chown root:root "$config_tmp"
  chmod 0600 "$config_tmp"
  mv -f "$config_tmp" /etc/default/pqtunnel-manager
else
  cat > /etc/default/pqtunnel-manager <<ENV
# Optional management UI. It remains stopped until you review this file and start it.
PQTUNNEL_MANAGER_ROLE=$ROLE
PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091
# Set this to a random secret of at least 32 bytes; never commit or share it.
PQTUNNEL_MANAGER_TOKEN=
PQTUNNEL_SETUP_VERSION=$SOURCE_VERSION
# Optional tunnel-only speed test. Set the actual private TUN addresses.
# Gateway example: listen=10.66.0.1:9109, peer=10.66.0.2:9109
# Dialer example:  listen=10.66.0.2:9109, peer=10.66.0.1:9109
# Configure matching local/peer prefixes and allow tcp:9109 on BOTH tunnel configs.
# Use the SAME separate random token on both servers; do not reuse the web token.
# PQTUNNEL_MANAGER_SPEEDTEST_LISTEN=
# PQTUNNEL_MANAGER_SPEEDTEST_PEER=
# PQTUNNEL_MANAGER_SPEEDTEST_TOKEN=
ENV
  chown root:root /etc/default/pqtunnel-manager
  chmod 0600 /etc/default/pqtunnel-manager
fi

systemctl daemon-reload
if ! systemd-analyze verify /etc/systemd/system/pqtunnel-manager.service /etc/systemd/system/pqtunnel-setup.service; then
  if (( UPGRADE )); then
    install -o root -g root -m 0755 "$BACKUP_DIR/pqtunnel-manager" /usr/local/sbin/pqtunnel-manager
    install -o root -g root -m 0644 "$BACKUP_DIR/pqtunnel-manager.service" /etc/systemd/system/pqtunnel-manager.service
    install -o root -g root -m 0600 "$BACKUP_DIR/pqtunnel-manager.env" /etc/default/pqtunnel-manager
    systemctl daemon-reload
  fi
  fail 'systemd unit validation failed; manager config/binary were restored when this was an upgrade.'
fi

if (( UPGRADE )); then
  if systemctl is-active --quiet pqtunnel-manager; then
    if ! systemctl restart pqtunnel-manager; then
      install -o root -g root -m 0755 "$BACKUP_DIR/pqtunnel-manager" /usr/local/sbin/pqtunnel-manager
      install -o root -g root -m 0644 "$BACKUP_DIR/pqtunnel-manager.service" /etc/systemd/system/pqtunnel-manager.service
      install -o root -g root -m 0600 "$BACKUP_DIR/pqtunnel-manager.env" /etc/default/pqtunnel-manager
      systemctl daemon-reload
      systemctl restart pqtunnel-manager || true
      fail "manager upgrade failed; previous manager binary, unit and config were restored. Backup: $BACKUP_DIR"
    fi
  fi
  echo "PQTunnel manager upgraded with graphical setup support."
  echo "Protected backup: $BACKUP_DIR"
  echo "Setup wizard worker is installed but not enabled as a daemon; it is invoked only for an authenticated setup request."
  if [[ -n "$NEW_MANAGER_TOKEN" ]]; then
    printf '\nThe previous manager listener was public or insecure. It is now loopback-only and its login token was rotated. Save this new token exactly once:\nPQTUNNEL_MANAGER_TOKEN=%s\n' "$NEW_MANAGER_TOKEN"
    unset NEW_MANAGER_TOKEN
  else
    echo "Existing loopback-only manager token and role were preserved."
  fi
else
  echo 'PQTunnel manager installed, but not enabled or started.'
  echo 'Review /etc/default/pqtunnel-manager and set a strong PQTUNNEL_MANAGER_TOKEN first.'
  echo 'Then run: sudo systemctl enable --now pqtunnel-manager'
fi
echo 'For remote browser access, use SSH local forwarding; do not expose port 9091 publicly.'
echo 'The graphical setup worker can change host packages and network state only after explicit web confirmation and existing-state guards.'
