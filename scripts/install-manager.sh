#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Install the PQTunnel web manager and optionally the stopped local endpoint.
--upgrade backs up and upgrades a complete existing manager.

Usage:
  sudo bash ./scripts/install-manager.sh --source /path/to/Linux-bundle --role gateway
  sudo bash ./scripts/install-manager.sh --source /path/to/Linux-bundle --role dialer
  sudo bash ./scripts/install-manager.sh --source /path/to/Linux-bundle --role dialer --upgrade
  sudo bash ./scripts/install-manager.sh --source /path/to/Linux-bundle --role dialer --with-node-endpoint --public-http --public-host 203.0.113.10 --upgrade

The default manager listener is loopback-only. Public plaintext HTTP requires
both --public-http and --public-host and is intended only for temporary testing.
With --with-node-endpoint, role-specific binaries and transport-only systemd units
are installed but not enabled or started. Existing tunnel configurations are
never overwritten by this installer.
USAGE
}
fail() { echo "pqtunnel manager installer: $*" >&2; exit 1; }

SOURCE=""
ROLE=""
UPGRADE=0
WITH_NODE_ENDPOINT=0
PUBLIC_HTTP=0
PUBLIC_HOST=""
while (($#)); do
  case "$1" in
    --source) SOURCE="${2:?missing source path}"; shift 2 ;;
    --role) ROLE="${2:?missing role}"; shift 2 ;;
    --upgrade) UPGRADE=1; shift ;;
    --with-node-endpoint) WITH_NODE_ENDPOINT=1; shift ;;
    --public-http) PUBLIC_HTTP=1; shift ;;
    --public-host) PUBLIC_HOST="${2:?missing public host IP}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || fail 'run with sudo on the destination Linux server.'
[[ -n "$SOURCE" && -d "$SOURCE" ]] || fail '--source must point to a source tree or extracted Linux release bundle.'
[[ "$ROLE" == gateway || "$ROLE" == dialer ]] || fail '--role must be gateway or dialer.'
if (( PUBLIC_HTTP )); then
  [[ -n "$PUBLIC_HOST" ]] || fail '--public-http requires --public-host with the server public IP.'
  command -v python3 >/dev/null || fail 'python3 is required to validate the public IP.'
  python3 - "$PUBLIC_HOST" <<'PY'
import ipaddress, sys
try:
    value = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("public host must be a literal public IP address")
if value.version != 4 or not value.is_global:
    raise SystemExit("public host must be a global IPv4 address")
PY
elif [[ -n "$PUBLIC_HOST" ]]; then
  fail '--public-host requires --public-http.'
fi
[[ -f "$SOURCE/deploy/systemd/pqtunnel-manager.service" ]] || fail 'deploy/systemd/pqtunnel-manager.service is missing.'
[[ -f "$SOURCE/deploy/systemd/pqtunnel-setup.service" ]] || fail 'deploy/systemd/pqtunnel-setup.service is missing.'
[[ -f "$SOURCE/scripts/pqtunnel-setup-worker.sh" && -f "$SOURCE/scripts/pqtunnel-site-to-site-setup.sh" ]] || fail 'graphical setup worker scripts are missing; use a release containing the setup wizard.'
[[ -f "$SOURCE/deploy/systemd/pqtunnel-node-setup.service" && -f "$SOURCE/scripts/pqtunnel-node-setup-worker.py" ]] || fail 'standalone node setup worker assets are missing.'
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

if (( WITH_NODE_ENDPOINT )); then
  [[ -x "$SOURCE/pqtunnel-pki" && -f "$SOURCE/scripts/pqtunnel-transport-tun.sh" ]] || fail 'release bundle lacks standalone endpoint support.'
  if [[ "$ROLE" == gateway ]]; then
    [[ -x "$SOURCE/pqtunneld" && -f "$SOURCE/deploy/systemd/pqtunneld-transport.service" ]] || fail 'release bundle lacks Gateway transport assets.'
  else
    [[ -x "$SOURCE/pqtunnel-client" && -f "$SOURCE/scripts/run-pqtunnel-client.sh" && -f "$SOURCE/deploy/systemd/pqtunnel-client-transport.service" ]] || fail 'release bundle lacks Dialer transport assets.'
  fi
  existing_mode=""
  if [[ -f /etc/default/pqtunnel-manager ]]; then
    existing_mode="$(sed -n 's/^PQTUNNEL_MANAGER_ENDPOINT_MODE=//p' /etc/default/pqtunnel-manager | head -n1)"
  fi
  if [[ "$existing_mode" != transport ]]; then
    if [[ "$ROLE" == gateway ]]; then
      for path in /usr/local/sbin/pqtunneld /etc/default/pqtunneld /etc/systemd/system/pqtunneld.service /etc/pqtunnel/pki/server.key /etc/pqtunnel/pki/server.crt; do
        [[ ! -e "$path" ]] || fail "existing Gateway endpoint artifact at $path; refusing to overwrite another installation."
      done
    else
      for path in /usr/local/bin/pqtunnel-client /etc/default/pqtunnel-client /etc/systemd/system/pqtunnel-client.service /etc/pqtunnel/pki/client.key /etc/pqtunnel/pki/client.crt; do
        [[ ! -e "$path" ]] || fail "existing Dialer endpoint artifact at $path; refusing to overwrite another installation."
      done
    fi
  fi
fi

TMPBIN=""
BACKUP_DIR=""
NEW_MANAGER_TOKEN=""
cleanup() { [[ -z "$TMPBIN" ]] || rm -f "$TMPBIN"; [[ -z "${config_tmp:-}" ]] || rm -f -- "$config_tmp"; unset NEW_MANAGER_TOKEN; }
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
install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunnel-node-setup.service" /etc/systemd/system/pqtunnel-node-setup.service
install -o root -g root -m 0750 "$SOURCE/scripts/pqtunnel-node-setup-worker.py" /usr/local/lib/pqtunnel/pqtunnel-node-setup-worker.py

if (( WITH_NODE_ENDPOINT )); then
  for path in /etc/pqtunnel /etc/pqtunnel/pki /var/lib/pqtunnel; do
    [[ ! -L "$path" ]] || fail "refusing symlinked endpoint directory: $path"
    if [[ ! -e "$path" ]]; then install -d -o root -g root -m 0750 "$path"; fi
    [[ -d "$path" ]] || fail "endpoint path is not a directory: $path"
  done
  install -o root -g root -m 0755 "$SOURCE/pqtunnel-pki" /usr/local/bin/pqtunnel-pki
  install -o root -g root -m 0750 "$SOURCE/scripts/pqtunnel-transport-tun.sh" /usr/local/lib/pqtunnel/pqtunnel-transport-tun.sh
  if [[ "$ROLE" == gateway ]]; then
    install -o root -g root -m 0755 "$SOURCE/pqtunneld" /usr/local/sbin/pqtunneld
    install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunneld-transport.service" /etc/systemd/system/pqtunneld-transport.service
  else
    install -o root -g root -m 0755 "$SOURCE/pqtunnel-client" /usr/local/bin/pqtunnel-client
    install -o root -g root -m 0755 "$SOURCE/scripts/run-pqtunnel-client.sh" /usr/local/lib/pqtunnel/run-client.sh
    install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunnel-client-transport.service" /etc/systemd/system/pqtunnel-client-transport.service
  fi
fi

if (( UPGRADE )); then
  config_tmp="$(mktemp /etc/default/pqtunnel-manager.XXXXXX)"
  old_endpoint_mode="$(sed -n 's/^PQTUNNEL_MANAGER_ENDPOINT_MODE=//p' /etc/default/pqtunnel-manager | head -n1)"
  awk '!/^(PQTUNNEL_SETUP_VERSION|PQTUNNEL_MANAGER_LISTEN|PQTUNNEL_MANAGER_TOKEN|PQTUNNEL_MANAGER_PUBLIC_HOST|PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP|PQTUNNEL_MANAGER_TLS_CERT|PQTUNNEL_MANAGER_TLS_KEY|PQTUNNEL_MANAGER_ENDPOINT_MODE)=/' /etc/default/pqtunnel-manager > "$config_tmp"
  old_listen="$(sed -n 's/^PQTUNNEL_MANAGER_LISTEN=//p' /etc/default/pqtunnel-manager | head -n1)"
  old_insecure="$(sed -n 's/^PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=//p' /etc/default/pqtunnel-manager | head -n1)"
  old_token="$(sed -n 's/^PQTUNNEL_MANAGER_TOKEN=//p' /etc/default/pqtunnel-manager | head -n1)"
  if (( PUBLIC_HTTP )); then
    if [[ ! "$old_token" =~ ^[A-Za-z0-9_.,:/=-]{32,}$ ]]; then
      NEW_MANAGER_TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
      [[ "$NEW_MANAGER_TOKEN" =~ ^[0-9a-f]{64}$ ]] || fail 'could not generate a replacement manager token; upgrade stopped.'
      old_token="$NEW_MANAGER_TOKEN"
    fi
    printf 'PQTUNNEL_MANAGER_LISTEN=0.0.0.0:9091\nPQTUNNEL_MANAGER_PUBLIC_HOST=%s\nPQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=true\nPQTUNNEL_MANAGER_TOKEN=%s\n' "$PUBLIC_HOST" "$old_token" >> "$config_tmp"
  elif [[ "$old_insecure" == true || ! "$old_listen" =~ ^(127\.0\.0\.1:[0-9]+|\[::1\]:[0-9]+)$ ]]; then
    NEW_MANAGER_TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
    [[ "$NEW_MANAGER_TOKEN" =~ ^[0-9a-f]{64}$ ]] || fail 'could not generate a replacement manager token; upgrade stopped.'
    printf 'PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091\nPQTUNNEL_MANAGER_TOKEN=%s\n' "$NEW_MANAGER_TOKEN" >> "$config_tmp"
  else
    printf 'PQTUNNEL_MANAGER_LISTEN=%s\nPQTUNNEL_MANAGER_TOKEN=%s\n' "$old_listen" "$old_token" >> "$config_tmp"
  fi
  if (( WITH_NODE_ENDPOINT )); then
    printf 'PQTUNNEL_MANAGER_ENDPOINT_MODE=transport\n' >> "$config_tmp"
  elif [[ -n "$old_endpoint_mode" ]]; then
    printf 'PQTUNNEL_MANAGER_ENDPOINT_MODE=%s\n' "$old_endpoint_mode" >> "$config_tmp"
  fi
  printf 'PQTUNNEL_SETUP_VERSION=%s\n' "$SOURCE_VERSION" >> "$config_tmp"
  chown root:root "$config_tmp"
  chmod 0600 "$config_tmp"
  mv -f "$config_tmp" /etc/default/pqtunnel-manager
else
  cat > /etc/default/pqtunnel-manager <<ENV
# Optional management UI; token is assigned by the top-level installer.
PQTUNNEL_MANAGER_ROLE=$ROLE
ENV
  if (( PUBLIC_HTTP )); then
    printf 'PQTUNNEL_MANAGER_LISTEN=0.0.0.0:9091\nPQTUNNEL_MANAGER_PUBLIC_HOST=%s\nPQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=true\n' "$PUBLIC_HOST" >> /etc/default/pqtunnel-manager
  else
    printf 'PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091\n' >> /etc/default/pqtunnel-manager
  fi
  if (( WITH_NODE_ENDPOINT )); then
    printf 'PQTUNNEL_MANAGER_ENDPOINT_MODE=transport\n' >> /etc/default/pqtunnel-manager
  fi
  cat >> /etc/default/pqtunnel-manager <<ENV
PQTUNNEL_MANAGER_TOKEN=
PQTUNNEL_SETUP_VERSION=$SOURCE_VERSION
ENV
  chown root:root /etc/default/pqtunnel-manager
  chmod 0600 /etc/default/pqtunnel-manager
fi

systemctl daemon-reload
VERIFY_UNITS=(/etc/systemd/system/pqtunnel-manager.service /etc/systemd/system/pqtunnel-setup.service /etc/systemd/system/pqtunnel-node-setup.service)
if (( WITH_NODE_ENDPOINT )); then
  if [[ "$ROLE" == gateway ]]; then VERIFY_UNITS+=(/etc/systemd/system/pqtunneld-transport.service); else VERIFY_UNITS+=(/etc/systemd/system/pqtunnel-client-transport.service); fi
fi
if ! systemd-analyze verify "${VERIFY_UNITS[@]}"; then
  if (( UPGRADE )); then
    install -o root -g root -m 0755 "$BACKUP_DIR/pqtunnel-manager" /usr/local/sbin/pqtunnel-manager
    install -o root -g root -m 0644 "$BACKUP_DIR/pqtunnel-manager.service" /etc/systemd/system/pqtunnel-manager.service
    if [[ -z "$NEW_MANAGER_TOKEN" ]]; then
      install -o root -g root -m 0600 "$BACKUP_DIR/pqtunnel-manager.env" /etc/default/pqtunnel-manager
    fi
    systemctl daemon-reload
    if [[ -n "$NEW_MANAGER_TOKEN" ]]; then
      systemctl stop pqtunnel-manager >/dev/null 2>&1 || true
      systemctl restart pqtunnel-manager || systemctl stop pqtunnel-manager >/dev/null 2>&1 || true
      printf '\nUpgrade validation failed; previous binary/unit restored. The old public listener has been kept private. Save the rotated token if needed:\\nPQTUNNEL_MANAGER_TOKEN=%s\\n' "$NEW_MANAGER_TOKEN" >&2
    fi
  fi
  fail 'systemd unit validation failed; previous manager binary/unit were restored when this was an upgrade.'
fi

if (( UPGRADE )); then
  if systemctl is-active --quiet pqtunnel-manager; then
    if ! systemctl restart pqtunnel-manager; then
      install -o root -g root -m 0755 "$BACKUP_DIR/pqtunnel-manager" /usr/local/sbin/pqtunnel-manager
      install -o root -g root -m 0644 "$BACKUP_DIR/pqtunnel-manager.service" /etc/systemd/system/pqtunnel-manager.service
      if [[ -z "$NEW_MANAGER_TOKEN" ]]; then
        install -o root -g root -m 0600 "$BACKUP_DIR/pqtunnel-manager.env" /etc/default/pqtunnel-manager
      fi
      systemctl daemon-reload
      if ! systemctl restart pqtunnel-manager; then
        systemctl stop pqtunnel-manager >/dev/null 2>&1 || true
      fi
      if [[ -n "$NEW_MANAGER_TOKEN" ]]; then
        printf '\nManager restart failed; previous binary/unit restored and insecure public binding was not restored. Save the new token for recovery:\\nPQTUNNEL_MANAGER_TOKEN=%s\\n' "$NEW_MANAGER_TOKEN" >&2
      fi
      fail "manager upgrade failed; previous binary/unit restored. Review service status and backup: $BACKUP_DIR"
    fi
  fi
  echo "PQTunnel manager upgraded."
  if (( WITH_NODE_ENDPOINT )); then echo "Standalone endpoint assets installed for role $ROLE; tunnel service remains stopped and disabled."; fi
  echo "Protected backup: $BACKUP_DIR"
  echo "Setup wizard worker is installed but not enabled as a daemon; it is invoked only for an authenticated setup request."
  if [[ -n "$NEW_MANAGER_TOKEN" ]]; then
    printf '\nThe previous manager listener was public or insecure. It is now loopback-only and its login token was rotated. Save this new token exactly once:\nPQTUNNEL_MANAGER_TOKEN=%s\n' "$NEW_MANAGER_TOKEN"
    unset NEW_MANAGER_TOKEN
  else
    echo "Existing manager token and role were preserved."
  fi
else
  echo 'PQTunnel manager installed; the top-level installer will assign the token and start the panel.'
  if (( WITH_NODE_ENDPOINT )); then echo "Standalone endpoint assets installed for role $ROLE; tunnel service remains stopped and disabled."; fi
fi
if (( PUBLIC_HTTP )); then
  echo 'WARNING: manager is exposed over plaintext HTTP. Use only for temporary testing and restrict TCP/9091 at the provider firewall.'
else
  echo 'For remote browser access, use SSH local forwarding; do not expose port 9091 publicly.'
fi
echo 'The standalone endpoint is not started during installation. Its transport unit does not apply host firewall, NAT, forwarding, or default-route changes.'
