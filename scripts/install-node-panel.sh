#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SOURCE=
ROLE=
PUBLIC_HTTP_HOST=
while (($#)); do
  case "$1" in
    --source) SOURCE="$2"; shift 2 ;;
    --role) ROLE="$2"; shift 2 ;;
    --public-http-host) PUBLIC_HTTP_HOST="$2"; shift 2 ;;
    -h|--help)
      cat <<'USAGE'
Install the PQTunnel panel and a dormant endpoint on one Linux server.
The endpoint is installed but not enabled or started. No routes, firewall rules,
forwarding, TUN interfaces, or tunnel services are activated.

Usage:
  sudo bash ./scripts/install-node-panel.sh --source /path/to/Linux-bundle --role gateway
  sudo bash ./scripts/install-node-panel.sh --source /path/to/Linux-bundle --role dialer --public-http-host 203.0.113.10
USAGE
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

fail() { printf 'PQTunnel node panel installer: %s\n' "$*" >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || fail 'run with root privileges.'
[[ -n "$SOURCE" && -d "$SOURCE" ]] || fail '--source must point to an extracted Linux release bundle.'
[[ "$ROLE" == gateway || "$ROLE" == dialer ]] || fail '--role must be gateway or dialer.'
for f in pqtunnel-manager pqtunnel-pki pqtunneld pqtunnel-client; do
  [[ -x "$SOURCE/$f" ]] || fail "release bundle is missing $f."
done
for f in deploy/systemd/pqtunnel-manager.service deploy/systemd/pqtunnel-setup.service deploy/systemd/pqtunneld.service deploy/systemd/pqtunnel-client.service scripts/pqtunnel-setup-worker.sh scripts/pqtunnel-site-to-site-setup.sh scripts/site-to-site-selective.sh scripts/run-pqtunnel-client.sh scripts/stop-pqtunnel-client-network.sh; do
  [[ -f "$SOURCE/$f" ]] || fail "release bundle is missing $f."
done
for cmd in systemctl systemd-analyze python3 ip od install sed grep; do
  command -v "$cmd" >/dev/null || fail "required command missing: $cmd"
done
BUNDLE_NAME="$(basename "$SOURCE")"
SOURCE_VERSION="$(printf '%s' "$BUNDLE_NAME" | sed -nE 's/^PQTunnel-(v[0-9A-Za-z._-]+)-linux-(amd64|arm64)$/\1/p')"
[[ "$SOURCE_VERSION" =~ ^v[0-9A-Za-z._-]+$ ]] || fail 'release bundle name must include version and architecture.'
case "$(uname -m)" in
  x86_64|amd64) HOST_ARCH=amd64 ;;
  aarch64|arm64) HOST_ARCH=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac
[[ "$BUNDLE_NAME" == *"-linux-$HOST_ARCH" ]] || fail "bundle architecture does not match this host ($HOST_ARCH)."

if [[ -n "$PUBLIC_HTTP_HOST" ]]; then
  python3 -c 'import ipaddress,sys; x=ipaddress.ip_address(sys.argv[1]); sys.exit(0 if x.is_global and not x.is_loopback and not x.is_private and not x.is_unspecified else 1)' "$PUBLIC_HTTP_HOST" || fail '--public-http-host must be a globally routable IP address.'
fi

CONFIG=/etc/default/pqtunnel-manager
MANAGER_COUNT=0
for path in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service "$CONFIG"; do
  [[ ! -e "$path" ]] || MANAGER_COUNT=$((MANAGER_COUNT + 1))
done
if (( MANAGER_COUNT != 0 && MANAGER_COUNT != 3 )); then fail 'partial manager installation detected; inspect manually.'; fi
if (( MANAGER_COUNT == 3 )); then
  EXISTING_ROLE="$(sed -n 's/^PQTUNNEL_MANAGER_ROLE=//p' "$CONFIG" | head -n1)"
  [[ "$EXISTING_ROLE" == "$ROLE" ]] || fail "existing manager role is '$EXISTING_ROLE', not '$ROLE'; refusing to change roles."
  BACKUP_DIR="/var/lib/pqtunnel-manager/backups/node-panel-$(date +%Y%m%d-%H%M%S)"
  install -d -o root -g root -m 0700 "$BACKUP_DIR"
  cp -a /usr/local/sbin/pqtunnel-manager "$BACKUP_DIR/pqtunnel-manager"
  cp -a /etc/systemd/system/pqtunnel-manager.service "$BACKUP_DIR/pqtunnel-manager.service"
  cp -a "$CONFIG" "$BACKUP_DIR/pqtunnel-manager.env"
else
  BACKUP_DIR=
fi

ENDPOINT_COUNT=0
if [[ "$ROLE" == gateway ]]; then
  for path in /usr/local/sbin/pqtunneld /etc/systemd/system/pqtunneld.service /etc/default/pqtunneld /etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh; do
    [[ ! -e "$path" ]] || ENDPOINT_COUNT=$((ENDPOINT_COUNT + 1))
  done
  EXPECTED_ENDPOINT_COUNT=5
  ENDPOINT_UNIT=pqtunneld.service
else
  for path in /usr/local/bin/pqtunnel-client /etc/systemd/system/pqtunnel-client.service /etc/default/pqtunnel-client /etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh /usr/local/lib/pqtunnel/run-client.sh /usr/local/lib/pqtunnel/stop-client-network.sh; do
    [[ ! -e "$path" ]] || ENDPOINT_COUNT=$((ENDPOINT_COUNT + 1))
  done
  EXPECTED_ENDPOINT_COUNT=7
  ENDPOINT_UNIT=pqtunnel-client.service
fi
if (( ENDPOINT_COUNT != 0 && ENDPOINT_COUNT != EXPECTED_ENDPOINT_COUNT )); then
  fail 'partial endpoint installation detected; refusing to overwrite it.'
fi
INSTALL_ENDPOINT=1
if (( ENDPOINT_COUNT == EXPECTED_ENDPOINT_COUNT )); then
  INSTALL_ENDPOINT=0
  printf 'Existing %s endpoint files detected; preserving them.\n' "$ROLE"
fi

WAN_IF="$(ip -o route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
[[ -n "$WAN_IF" && "$WAN_IF" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || fail 'could not detect the default-route interface.'

install -d -o root -g root -m 0750 /var/lib/pqtunnel-manager/backups /var/lib/pqtunnel /usr/local/lib/pqtunnel /etc/pqtunnel/pki
install -o root -g root -m 0755 "$SOURCE/pqtunnel-manager" /usr/local/sbin/pqtunnel-manager
install -o root -g root -m 0755 "$SOURCE/pqtunnel-pki" /usr/local/sbin/pqtunnel-pki
install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunnel-manager.service" /etc/systemd/system/pqtunnel-manager.service
install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunnel-setup.service" /etc/systemd/system/pqtunnel-setup.service
install -o root -g root -m 0750 "$SOURCE/scripts/pqtunnel-setup-worker.sh" /usr/local/lib/pqtunnel/pqtunnel-setup-worker.sh
install -o root -g root -m 0750 "$SOURCE/scripts/pqtunnel-site-to-site-setup.sh" /usr/local/lib/pqtunnel/pqtunnel-site-to-site-setup.sh
install -o root -g root -m 0755 "$SOURCE/scripts/site-to-site-selective.sh" /usr/local/lib/pqtunnel/site-to-site-selective.sh

if (( INSTALL_ENDPOINT )); then
  if [[ "$ROLE" == gateway ]]; then
    install -o root -g root -m 0755 "$SOURCE/pqtunneld" /usr/local/sbin/pqtunneld
    install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunneld.service" /etc/systemd/system/pqtunneld.service
    cat > /etc/default/pqtunneld <<'ENV'
# Draft endpoint configuration; review settings and install credentials before start.
PQTUNNEL_LISTEN=0.0.0.0:8443
PQTUNNEL_TLS_CERT=/etc/pqtunnel/pki/server.crt
PQTUNNEL_TLS_KEY=/etc/pqtunnel/pki/server.key
PQTUNNEL_CLIENT_CA=/etc/pqtunnel/pki/ca.crt
PQTUNNEL_MAX_CLIENTS=1
PQTUNNEL_PEER_PREFIXES=10.66.0.2/32,fd42:7061:7475::2/128
PQTUNNEL_LOCAL_PREFIXES=0.0.0.0/0,::/0
PQTUNNEL_PEER_NAME=pqtunnel-dialer
PQTUNNEL_ALLOWED_DST_PORTS=tcp:443,udp:53,udp:123
PQTUNNEL_MANAGER_NETWORK_HOOKS=1
ENV
    chown root:root /etc/default/pqtunneld
    chmod 0640 /etc/default/pqtunneld
    cat > /etc/pqtunnel/site-to-site.env <<ENV
PQTUNNEL_ROLE=gateway
PQTUNNEL_WAN_IF=$WAN_IF
PQTUNNEL_TUN=pqtun0
PQTUNNEL_TCP_EGRESS_PORTS=
PQTUNNEL_UDP_EGRESS_PORTS=
PQTUNNEL_TCP_FORWARD_RULES=
PQTUNNEL_UDP_FORWARD_RULES=
ENV
    chown root:root /etc/pqtunnel/site-to-site.env
    chmod 0600 /etc/pqtunnel/site-to-site.env
  else
    install -o root -g root -m 0755 "$SOURCE/pqtunnel-client" /usr/local/bin/pqtunnel-client
    install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunnel-client.service" /etc/systemd/system/pqtunnel-client.service
    install -o root -g root -m 0755 "$SOURCE/scripts/run-pqtunnel-client.sh" /usr/local/lib/pqtunnel/run-client.sh
    install -o root -g root -m 0755 "$SOURCE/scripts/stop-pqtunnel-client-network.sh" /usr/local/lib/pqtunnel/stop-client-network.sh
    cat > /etc/default/pqtunnel-client <<'ENV'
# Draft endpoint configuration; import a Gateway bundle before starting.
PQTUNNEL_SERVER=192.0.2.1:8443
PQTUNNEL_SERVER_NAME=192.0.2.1
PQTUNNEL_LOCAL_PREFIXES=10.66.0.2/32,fd42:7061:7475::2/128
PQTUNNEL_REMOTE_PREFIXES=0.0.0.0/0,::/0
PQTUNNEL_ALLOWED_DST_PORTS=tcp:443,udp:53,udp:123
ENV
    chown root:root /etc/default/pqtunnel-client
    chmod 0640 /etc/default/pqtunnel-client
    cat > /etc/pqtunnel/site-to-site.env <<ENV
PQTUNNEL_ROLE=dialer
PQTUNNEL_WAN_IF=$WAN_IF
PQTUNNEL_TUN=pqtun0
PQTUNNEL_TCP_EGRESS_PORTS=443
PQTUNNEL_UDP_EGRESS_PORTS=53,123
PQTUNNEL_TCP_FORWARD_RULES=
PQTUNNEL_UDP_FORWARD_RULES=
ENV
    chown root:root /etc/pqtunnel/site-to-site.env
    chmod 0600 /etc/pqtunnel/site-to-site.env
  fi
fi

OLD_TOKEN="$(sed -n 's/^PQTUNNEL_MANAGER_TOKEN=//p' "$CONFIG" 2>/dev/null | head -n1 || true)"
NEW_TOKEN=
if [[ -z "$OLD_TOKEN" ]]; then
  NEW_TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  [[ "$NEW_TOKEN" =~ ^[0-9a-f]{64}$ ]] || fail 'could not generate manager token.'
fi
OLD_LISTEN="$(sed -n 's/^PQTUNNEL_MANAGER_LISTEN=//p' "$CONFIG" 2>/dev/null | head -n1 || true)"
OLD_PUBLIC_HOST="$(sed -n 's/^PQTUNNEL_MANAGER_PUBLIC_HOST=//p' "$CONFIG" 2>/dev/null | head -n1 || true)"
OLD_INSECURE="$(sed -n 's/^PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=//p' "$CONFIG" 2>/dev/null | head -n1 || true)"
OLD_TLS_CERT="$(sed -n 's/^PQTUNNEL_MANAGER_TLS_CERT=//p' "$CONFIG" 2>/dev/null | head -n1 || true)"
OLD_TLS_KEY="$(sed -n 's/^PQTUNNEL_MANAGER_TLS_KEY=//p' "$CONFIG" 2>/dev/null | head -n1 || true)"
OLD_SPEED_LISTEN="$(sed -n 's/^PQTUNNEL_MANAGER_SPEEDTEST_LISTEN=//p' "$CONFIG" 2>/dev/null | head -n1 || true)"
OLD_SPEED_PEER="$(sed -n 's/^PQTUNNEL_MANAGER_SPEEDTEST_PEER=//p' "$CONFIG" 2>/dev/null | head -n1 || true)"
OLD_SPEED_TOKEN="$(sed -n 's/^PQTUNNEL_MANAGER_SPEEDTEST_TOKEN=//p' "$CONFIG" 2>/dev/null | head -n1 || true)"

if [[ -n "$PUBLIC_HTTP_HOST" ]]; then
  LISTEN_VALUE=0.0.0.0:9091
  PUBLIC_HOST_VALUE="$PUBLIC_HTTP_HOST"
  INSECURE_VALUE=true
  TLS_CERT_VALUE=
  TLS_KEY_VALUE=
else
  LISTEN_VALUE="$OLD_LISTEN"
  PUBLIC_HOST_VALUE="$OLD_PUBLIC_HOST"
  INSECURE_VALUE="$OLD_INSECURE"
  TLS_CERT_VALUE="$OLD_TLS_CERT"
  TLS_KEY_VALUE="$OLD_TLS_KEY"
  [[ -n "$LISTEN_VALUE" ]] || LISTEN_VALUE=127.0.0.1:9091
fi

TMP_CONFIG="$(mktemp /etc/default/pqtunnel-manager.XXXXXX)"
{
  printf 'PQTUNNEL_MANAGER_ROLE=%s\n' "$ROLE"
  printf 'PQTUNNEL_MANAGER_LISTEN=%s\n' "$LISTEN_VALUE"
  printf 'PQTUNNEL_MANAGER_TOKEN=%s\n' "${OLD_TOKEN:-$NEW_TOKEN}"
  printf 'PQTUNNEL_SETUP_VERSION=%s\n' "$SOURCE_VERSION"
  [[ -z "$PUBLIC_HOST_VALUE" ]] || printf 'PQTUNNEL_MANAGER_PUBLIC_HOST=%s\n' "$PUBLIC_HOST_VALUE"
  [[ -z "$INSECURE_VALUE" ]] || printf 'PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=%s\n' "$INSECURE_VALUE"
  [[ -z "$TLS_CERT_VALUE" ]] || printf 'PQTUNNEL_MANAGER_TLS_CERT=%s\n' "$TLS_CERT_VALUE"
  [[ -z "$TLS_KEY_VALUE" ]] || printf 'PQTUNNEL_MANAGER_TLS_KEY=%s\n' "$TLS_KEY_VALUE"
  [[ -z "$OLD_SPEED_LISTEN" ]] || printf 'PQTUNNEL_MANAGER_SPEEDTEST_LISTEN=%s\n' "$OLD_SPEED_LISTEN"
  [[ -z "$OLD_SPEED_PEER" ]] || printf 'PQTUNNEL_MANAGER_SPEEDTEST_PEER=%s\n' "$OLD_SPEED_PEER"
  [[ -z "$OLD_SPEED_TOKEN" ]] || printf 'PQTUNNEL_MANAGER_SPEEDTEST_TOKEN=%s\n' "$OLD_SPEED_TOKEN"
} > "$TMP_CONFIG"
chown root:root "$TMP_CONFIG"
chmod 0600 "$TMP_CONFIG"
mv -f "$TMP_CONFIG" "$CONFIG"

sed -i 's@^ReadWritePaths=.*@ReadWritePaths=-/etc/default/pqtunneld -/etc/default/pqtunnel-client /etc/pqtunnel/pki /var/lib/pqtunnel-manager@' /etc/systemd/system/pqtunnel-manager.service
chmod 0644 /etc/systemd/system/pqtunnel-manager.service

systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/pqtunnel-manager.service /etc/systemd/system/pqtunnel-setup.service
if (( INSTALL_ENDPOINT )); then
  if [[ "$ROLE" == gateway ]]; then
    systemd-analyze verify /etc/systemd/system/pqtunneld.service
  else
    systemd-analyze verify /etc/systemd/system/pqtunnel-client.service
  fi
fi
systemctl enable --now pqtunnel-manager

printf '\nPQTunnel %s panel installed and running (role=%s).\n' "$SOURCE_VERSION" "$ROLE"
if [[ -n "$PUBLIC_HTTP_HOST" ]]; then
  printf 'Panel URL: http://%s:9091\n' "$PUBLIC_HTTP_HOST"
  printf 'WARNING: public HTTP is unencrypted; restrict TCP/9091 at the provider firewall when possible.\n'
else
  printf 'Panel is loopback-only. Use SSH forwarding for remote browser access.\n'
fi
printf 'Endpoint binaries, service unit, configuration draft, and network helper are installed.\n'
printf 'Endpoint unit remains stopped and disabled. No routes, firewall rules, TUN interfaces, or forwarding settings were changed.\n'
if [[ "$ROLE" == gateway ]]; then
  printf 'Next: open /credentials on the Gateway panel, generate credentials, and download the Dialer bundle.\n'
else
  printf 'Next: upload the Gateway bundle at /credentials, then review the tunnel settings.\n'
fi
if [[ -n "$NEW_TOKEN" ]]; then
  printf '\nSave this new manager token now; it is shown only once:\nPQTUNNEL_MANAGER_TOKEN=%s\n' "$NEW_TOKEN"
fi
if [[ -n "$BACKUP_DIR" ]]; then printf 'Manager backup: %s\n' "$BACKUP_DIR"; fi
printf 'Endpoint unit: %s (not enabled or started)\n' "$ENDPOINT_UNIT"
