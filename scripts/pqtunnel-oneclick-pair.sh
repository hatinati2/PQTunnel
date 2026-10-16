#!/usr/bin/env bash
# Paired first-time installer: run as root on the Iran/Dialer host.
# Remote Gateway access must already be available through SSH key authentication.
set -Eeuo pipefail

SOURCE_DIR=
VERSION=
RELEASE_BASE=
while (($#)); do
  case "$1" in
    --source) [[ $# -ge 2 ]] || { echo 'missing --source' >&2; exit 2; }; SOURCE_DIR=$2; shift 2 ;;
    --version) [[ $# -ge 2 ]] || { echo 'missing --version' >&2; exit 2; }; VERSION=$2; shift 2 ;;
    --release-base) [[ $# -ge 2 ]] || { echo 'missing --release-base' >&2; exit 2; }; RELEASE_BASE=$2; shift 2 ;;
    -h|--help)
      cat <<'HELP'
PQTunnel first-time paired installer (experimental)

Run this on the Iran/Dialer VPS as root. It uses SSH key authentication to
install the Gateway on the overseas VPS. Existing endpoint installations are
never overwritten. It installs both loopback-only manager panels, builds a
mutual-TLS PKI bundle, configures selected-port egress, and prints each new
manager token once. Network activation requires typing APPLY-NETWORK.

This is not a full-tunnel/default-route VPN. By default, only TCP 80/443 and
UDP 53/123/443 from the Iran VPS are selected for egress through the Gateway.
The provider firewall is not modified; allow the chosen TCP listener port
there before activation. Do not activate on production hosts without a
separate console/recovery path and a reviewed firewall/routing state.
HELP
      exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

fail() { printf 'PQTunnel pair installer: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing required command '$1'; no packages or network state were changed."; }

[[ $EUID -eq 0 ]] || fail 'run with sudo/root on the Iran/Dialer VPS.'
[[ -d "$SOURCE_DIR" && -x "$SOURCE_DIR/pqtunneld" && -x "$SOURCE_DIR/pqtunnel-client" && -x "$SOURCE_DIR/pqtunnel-manager" && -x "$SOURCE_DIR/pqtunnel-pki" ]] || fail '--source must be a checksum-verified Linux release bundle.'
[[ -f "$SOURCE_DIR/scripts/install-server.sh" && -f "$SOURCE_DIR/scripts/install-manager.sh" && -f "$SOURCE_DIR/scripts/prepare-site-to-site-pki.sh" ]] || fail 'release bundle is missing installer scripts.'
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail 'invalid release version.'
[[ "$RELEASE_BASE" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/$VERSION$ ]] || fail 'release base URL does not match the pinned version.'

for cmd in curl tar sha256sum openssl ssh scp systemctl systemd-analyze ip ss awk grep sed install stat timeout; do need "$cmd"; done
[[ -d /run/systemd/system ]] || fail 'systemd is not running; no changes made.'

WORK_DIR="$(mktemp -d /root/pqtunnel-pair.XXXXXX)"
chmod 0700 "$WORK_DIR"
TOKEN_DIALER=
TOKEN_GATEWAY=
SPEEDTEST_TOKEN=
REMOTE_TARGET=
SSH_PORT=22
REMOTE_STAGE=
NETWORK_APPLY_ATTEMPTED=0

cleanup() {
  local rc=$?
  trap - EXIT
  if [[ -n "$TOKEN_DIALER" || -n "$TOKEN_GATEWAY" ]]; then
    printf '\n========== NEW PANEL TOKENS — SAVE SECURELY ==========\n'
    if [[ -n "$TOKEN_DIALER" ]]; then printf 'Iran/Dialer panel token: %s\n' "$TOKEN_DIALER"; fi
    if [[ -n "$TOKEN_GATEWAY" ]]; then printf 'Overseas/Gateway panel token: %s\n' "$TOKEN_GATEWAY"; fi
    printf 'These tokens are shown once by this installer. Do not paste them into chats or logs.\n'
  fi
  if [[ -n "$REMOTE_STAGE" && -n "$REMOTE_TARGET" ]]; then
    ssh -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 "$REMOTE_TARGET" \
      "case '$REMOTE_STAGE' in /tmp/pqtunnel-pair.*) rm -rf -- '$REMOTE_STAGE';; esac" >/dev/null 2>&1 || true
  fi
  [[ -z "$WORK_DIR" ]] || rm -rf -- "$WORK_DIR"
  exit "$rc"
}
trap cleanup EXIT

prompt() {
  [[ -r /dev/tty ]] || fail 'interactive setup needs a terminal; no changes made.'
  read -r -p "$1" "$2" </dev/tty
}
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
validate_port_list() {
  local label=$1 value=$2 p
  [[ -z "$value" ]] && return 0
  [[ "$value" != none ]] || return 0
  [[ "$value" =~ ^[0-9]+(,[0-9]+)*$ ]] || fail "$label must be a comma-separated list of numeric ports, or 'none'."
  local -A seen=()
  local IFS=,
  for p in $value; do
    valid_port "$p" || fail "$label contains an invalid port: $p"
    p=$((10#$p))
    [[ -z "${seen[$p]+x}" ]] || fail "$label contains duplicate port $p"
    seen[$p]=1
  done
}
normalize_port_list() {
  local value=$1 p result=
  [[ "$value" == none ]] && value=
  [[ -n "$value" ]] || { printf ''; return; }
  local IFS=,
  for p in $value; do
    p=$((10#$p))
    [[ -n "$result" ]] && result+=','
    result+="$p"
  done
  printf '%s' "$result"
}
make_allowed_ports() {
  local tcp=$1 udp=$2 p result=
  local IFS=,
  if [[ -n "$tcp" ]]; then
    for p in $tcp; do [[ -n "$result" ]] && result+=','; result+="tcp:$p"; done
  fi
  if [[ -n "$udp" ]]; then
    for p in $udp; do [[ -n "$result" ]] && result+=','; result+="udp:$p"; done
  fi
  printf '%s' "$result"
}
get_ifaces_from_routes() {
  awk '{for(i=1;i<=NF;i++) if($i=="dev" && i<NF) {print $(i+1); break}}' | sort -u
}
choose_iface() {
  local label=$1 output=$2 choice default count
  mapfile -t _ifaces < <(printf '%s\n' "$output" | get_ifaces_from_routes)
  count=${#_ifaces[@]}
  (( count > 0 )) || fail "no default-route interface was found on $label; no network changes were made."
  if (( count == 1 )); then default=${_ifaces[0]}; else default=; fi
  printf '\n%s default-route interface candidates: %s\n' "$label" "${_ifaces[*]}" >&2
  if [[ -n "$default" ]]; then
    prompt "$label WAN interface [${default}]: " choice
    choice=${choice:-$default}
  else
    prompt "$label WAN interface (choose exactly one listed above): " choice
  fi
  [[ "$choice" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || fail "invalid interface name for $label."
  local found=0 iface
  for iface in "${_ifaces[@]}"; do [[ "$choice" == "$iface" ]] && found=1; done
  (( found == 1 )) || fail "interface '$choice' is not among the default-route candidates listed for $label."
  printf '%s\n' "$choice"
}

# Ask for and validate the remote target before touching files or services.
prompt 'Overseas Gateway SSH target (user@IPv4-or-DNS; SSH key login required): ' REMOTE_TARGET
[[ "$REMOTE_TARGET" =~ ^[A-Za-z0-9_.-]+@[A-Za-z0-9.-]+$ ]] || fail 'SSH target must be user@IPv4-or-DNS (IPv6 SSH targets are not supported by this wizard).'
prompt 'SSH port [22]: ' SSH_PORT
SSH_PORT=${SSH_PORT:-22}
valid_port "$SSH_PORT" || fail 'invalid SSH port.'
REMOTE_HOST=${REMOTE_TARGET#*@}
prompt "Gateway certificate DNS name or public IPv4 [${REMOTE_HOST}]: " SERVER_NAME
SERVER_NAME=${SERVER_NAME:-$REMOTE_HOST}
[[ "$SERVER_NAME" =~ ^[A-Za-z0-9.-]+$ ]] || fail 'Gateway name must be a DNS name or IPv4 literal (no IPv6 in this wizard).'
prompt 'Gateway listener TCP port [8443]: ' LISTEN_PORT
LISTEN_PORT=${LISTEN_PORT:-8443}
valid_port "$LISTEN_PORT" || fail 'invalid Gateway listener port.'
prompt 'Iran TCP egress ports through Gateway [80,443]: ' TCP_PORTS
TCP_PORTS=${TCP_PORTS:-80,443}
prompt 'Iran UDP egress ports through Gateway [53,123,443]: ' UDP_PORTS
UDP_PORTS=${UDP_PORTS:-53,123,443}
validate_port_list 'TCP egress ports' "$TCP_PORTS"
validate_port_list 'UDP egress ports' "$UDP_PORTS"
TCP_PORTS=$(normalize_port_list "$TCP_PORTS")
UDP_PORTS=$(normalize_port_list "$UDP_PORTS")
[[ -n "$TCP_PORTS$UDP_PORTS" ]] || fail 'at least one TCP/UDP egress port must be selected.'
ALLOWED_PORTS=$(make_allowed_ports "$TCP_PORTS" "$UDP_PORTS")
# Reserve the tunnel peer's private speed-test port in the endpoint policy only;
# it is not added to the WAN egress-port selection.
ALLOWED_PORTS="${ALLOWED_PORTS:+$ALLOWED_PORTS,}tcp:9109"
SPEEDTEST_TOKEN="$(openssl rand -hex 32)"
[[ "$SPEEDTEST_TOKEN" =~ ^[0-9a-f]{64}$ ]] || fail 'could not generate shared speed-test token.'
printf 'PQTUNNEL_MANAGER_SPEEDTEST_TOKEN=%s\n' "$SPEEDTEST_TOKEN" > "$WORK_DIR/manager-speedtest.env"
chmod 0600 "$WORK_DIR/manager-speedtest.env"

printf '\nTopology: Iran = Dialer; %s = Gateway/Listener.\n' "$SERVER_NAME"
printf 'Only these egress ports from the Iran VPS will be selected: TCP [%s], UDP [%s].\n' "${TCP_PORTS:-none}" "${UDP_PORTS:-none}"
printf 'Destination prefix scope: IPv4/IPv6 internet addresses, but only the selected destination ports are marked for tunnelling. This is not a full-tunnel/default-route VPN.\n'
printf 'The listener uses TCP/%s. The provider firewall/security group must permit that port from Iran. The installer will not change provider firewall rules.\n' "$LISTEN_PORT"
printf 'Both managers will be restricted to loopback and new manager tokens will replace existing ones, if present.\n\n'
prompt 'Continue to read-only checks and prepare both servers? Type PREPARE: ' CONFIRM
[[ "$CONFIRM" == PREPARE ]] || fail 'cancelled by operator; no installation changes were made.'

SSH_OPTS=(-p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=8 -o ServerAliveInterval=15 -o ServerAliveCountMax=2)
if ! REMOTE_UID=$(ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" 'id -u' 2>/dev/null); then
  fail 'SSH key authentication failed. First verify SSH access to the Gateway and ensure the host key is trusted.'
fi
if [[ "$REMOTE_UID" != 0 ]]; then
  ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" 'sudo -n true' >/dev/null 2>&1 || fail 'remote user needs non-interactive sudo (or connect as root); no installation changes were made.'
  REMOTE_SUDO=1
else
  REMOTE_SUDO=0
fi
remote_privileged() {
  if [[ "$REMOTE_SUDO" == 1 ]]; then
    ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" 'sudo -n bash -s' "$@"
  else
    ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" 'bash -s' "$@"
  fi
}

# Local and remote role checks are read-only. Warnings are printed; hard failures stop setup.
printf '\n===== Iran/Dialer read-only preflight =====\n'
if ! bash "$SOURCE_DIR/scripts/site-to-site-preflight.sh" --role dialer; then
  fail 'Iran/Dialer read-only preflight reported FAIL. Review the report; no endpoint files were installed.'
fi
printf '\n===== Overseas/Gateway read-only preflight =====\n'
REMOTE_PREFLIGHT=$(cat <<'REMOTE_CHECK'
set -Eeuo pipefail
for cmd in bash ip nft sysctl systemctl systemd-analyze openssl stat awk grep sed install tar sha256sum ss; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing required command: $cmd" >&2; exit 1; }
done
[[ -d /run/systemd/system ]] || { echo 'systemd is not running.' >&2; exit 1; }
printf 'os='; . /etc/os-release; printf '%s %s\n' "${ID:-unknown}" "${VERSION_ID:-unknown}"
ip -o route show default
REMOTE_CHECK
)
if ! printf '%s\n' "$REMOTE_PREFLIGHT" | remote_privileged; then
  fail 'Overseas/Gateway read-only prerequisite checks failed; no endpoint files were installed.'
fi

# Refuse to overwrite any existing tunnel endpoint or partial install.
check_local_endpoint_clean() {
  local path
  for path in \
    /usr/local/sbin/pqtunneld /etc/systemd/system/pqtunneld.service /etc/default/pqtunneld \
    /usr/local/bin/pqtunnel-client /etc/systemd/system/pqtunnel-client.service /etc/default/pqtunnel-client \
    /etc/pqtunnel/pki/server.crt /etc/pqtunnel/pki/server.key /etc/pqtunnel/pki/client.crt /etc/pqtunnel/pki/client.key /etc/pqtunnel/pki/ca.crt /etc/pqtunnel/site-to-site.env \
    /usr/local/lib/pqtunnel/site-to-site-selective.sh /usr/local/lib/pqtunnel/run-client.sh /usr/local/lib/pqtunnel/stop-client-network.sh; do
    [[ ! -e "$path" ]] || fail "existing endpoint artifact found at $path; refusing to overwrite it."
  done
  systemctl cat pqtunneld.service >/dev/null 2>&1 && fail 'a pqtunneld systemd unit already exists (possibly under /usr/lib/systemd); refusing to replace it.'
  systemctl cat pqtunnel-client.service >/dev/null 2>&1 && fail 'a pqtunnel-client systemd unit already exists (possibly under /usr/lib/systemd); refusing to replace it.'
}
check_local_manager_state() {
  local count=0 p role
  for p in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service /etc/default/pqtunnel-manager; do [[ -e "$p" ]] && count=$((count+1)); done
  if (( count == 0 )); then return 0; fi
  (( count == 3 )) || fail 'partial manager installation found on Iran; repair/review it first.'
  role=$(sed -n 's/^PQTUNNEL_MANAGER_ROLE=//p' /etc/default/pqtunnel-manager | head -n1)
  [[ "$role" == dialer ]] || fail "existing Iran manager role is '$role', not 'dialer'; refusing to change roles."
}
install_or_check_manager() {
  local role=$1
  local count=0 p existing_role config token tmp speed_listen speed_peer
  config=/etc/default/pqtunnel-manager
  for p in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service "$config"; do [[ -e "$p" ]] && count=$((count+1)); done
  if (( count == 0 )); then
    bash "$SOURCE_DIR/scripts/install-manager.sh" --source "$SOURCE_DIR" --role "$role"
  elif (( count != 3 )); then
    fail "partial manager installation found for role $role."
  else
    existing_role=$(sed -n 's/^PQTUNNEL_MANAGER_ROLE=//p' "$config" | head -n1)
    [[ "$existing_role" == "$role" ]] || fail "manager role is '$existing_role', expected '$role'."
  fi
  token=$(openssl rand -hex 32)
  [[ "$token" =~ ^[0-9a-f]{64}$ ]] || fail 'could not generate manager token.'
  if [[ "$role" == dialer ]]; then
    speed_listen=10.66.0.2:9109; speed_peer=10.66.0.1:9109
  else
    speed_listen=10.66.0.1:9109; speed_peer=10.66.0.2:9109
  fi
  systemctl stop pqtunnel-manager >/dev/null 2>&1 || true
  cp -a "$config" "$config.backup.$(date +%Y%m%d-%H%M%S)"
  tmp=$(mktemp /etc/default/pqtunnel-manager.XXXXXX)
  awk '!/^[[:space:]]*PQTUNNEL_MANAGER_(ROLE|LISTEN|TOKEN|PUBLIC_HOST|ALLOW_INSECURE_PUBLIC_HTTP|TLS_CERT|TLS_KEY|SPEEDTEST_LISTEN|SPEEDTEST_PEER|SPEEDTEST_TOKEN)=/' "$config" > "$tmp"
  printf '\nPQTUNNEL_MANAGER_ROLE=%s\nPQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091\nPQTUNNEL_MANAGER_TOKEN=%s\nPQTUNNEL_MANAGER_SPEEDTEST_LISTEN=%s\nPQTUNNEL_MANAGER_SPEEDTEST_PEER=%s\nPQTUNNEL_MANAGER_SPEEDTEST_TOKEN=%s\n' "$role" "$token" "$speed_listen" "$speed_peer" "$SPEEDTEST_TOKEN" >> "$tmp"
  chown root:root "$tmp"; chmod 0600 "$tmp"; mv -f "$tmp" "$config"
  if [[ "$role" == dialer ]]; then TOKEN_DIALER=$token; else TOKEN_GATEWAY=$token; fi
  unset token
  systemctl daemon-reload
  systemd-analyze verify /etc/systemd/system/pqtunnel-manager.service
  systemctl enable --now pqtunnel-manager
}

check_local_endpoint_clean
check_local_manager_state
if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:|\\])${LISTEN_PORT}$"; then
  fail "TCP port $LISTEN_PORT appears to be in use on Iran; choose another listener port."
fi
# Secure/rotate the current Iran panel before staging the remote server.
install_or_check_manager dialer

REMOTE_PRECHECK=$(cat <<'REMOTE_PRECHECK_SCRIPT'
set -Eeuo pipefail
port=$1
systemctl cat pqtunneld.service >/dev/null 2>&1 && { echo 'a pqtunneld systemd unit already exists; refusing to replace it.' >&2; exit 1; }
for path in /usr/local/sbin/pqtunneld /etc/systemd/system/pqtunneld.service /etc/default/pqtunneld /etc/pqtunnel/pki/server.key /etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh; do
  [[ ! -e "$path" ]] || { echo "existing Gateway endpoint artifact at $path; refusing to overwrite." >&2; exit 1; }
done
count=0
for path in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service /etc/default/pqtunnel-manager; do [[ -e "$path" ]] && count=$((count+1)); done
if (( count != 0 && count != 3 )); then echo 'partial manager installation found on Gateway.' >&2; exit 1; fi
if (( count == 3 )); then
  role=$(sed -n 's/^PQTUNNEL_MANAGER_ROLE=//p' /etc/default/pqtunnel-manager | head -n1)
  [[ "$role" == gateway ]] || { echo "existing Gateway manager role is '$role', not 'gateway'." >&2; exit 1; }
fi
if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:|\\])${port}$"; then echo "TCP port $port is already in use on Gateway." >&2; exit 1; fi
printf 'Gateway precheck passed; no files, services or network state changed.\n'
REMOTE_PRECHECK_SCRIPT
)
if ! printf '%s\n' "$REMOTE_PRECHECK" | remote_privileged "$LISTEN_PORT"; then
  fail 'Gateway precheck failed. Existing files/services were preserved; no endpoint files were installed.'
fi

LOCAL_ROUTES=$(ip -o route show default 2>/dev/null || true)
DIALER_IF=$(choose_iface 'Iran/Dialer' "$LOCAL_ROUTES")
REMOTE_ROUTES=$(ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" 'ip -o route show default')
GATEWAY_IF=$(choose_iface 'Overseas/Gateway' "$REMOTE_ROUTES")
if ! ip link show dev "$DIALER_IF" >/dev/null 2>&1; then fail "Iran interface '$DIALER_IF' does not exist."; fi
if ! printf '%s\n' "$GATEWAY_IF" | grep -Eq '^[A-Za-z0-9_.:-]{1,15}$'; then fail 'invalid Gateway interface name.'; fi
ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" "ip link show dev '$GATEWAY_IF' >/dev/null"

# The PKI helper creates its output directory itself and refuses to overwrite it.
PQTUNNEL_PKI_BIN="$SOURCE_DIR/pqtunnel-pki" bash "$SOURCE_DIR/scripts/prepare-site-to-site-pki.sh" \
  --server-name "$SERVER_NAME" --client-ip 10.66.0.2 --out "$WORK_DIR/pki-bundle"

SERVER_ENDPOINT="$SERVER_NAME:$LISTEN_PORT"
DIALER_APP="$WORK_DIR/dialer-app.env"
GATEWAY_APP="$WORK_DIR/gateway-app.env"
DIALER_NETWORK="$WORK_DIR/dialer-network.env"
GATEWAY_NETWORK="$WORK_DIR/gateway-network.env"
cat > "$DIALER_APP" <<ENV
PQTUNNEL_SERVER=$SERVER_ENDPOINT
PQTUNNEL_SERVER_NAME=$SERVER_NAME
PQTUNNEL_LOCAL_PREFIXES=10.66.0.2/32
PQTUNNEL_REMOTE_PREFIXES=0.0.0.0/0,::/0
PQTUNNEL_ALLOWED_DST_PORTS=$ALLOWED_PORTS
ENV
cat > "$GATEWAY_APP" <<ENV
PQTUNNEL_LISTEN=0.0.0.0:$LISTEN_PORT,[::]:$LISTEN_PORT
PQTUNNEL_TLS_CERT=/etc/pqtunnel/pki/server.crt
PQTUNNEL_TLS_KEY=/etc/pqtunnel/pki/server.key
PQTUNNEL_CLIENT_CA=/etc/pqtunnel/pki/ca.crt
PQTUNNEL_MAX_CLIENTS=1
PQTUNNEL_PEER_PREFIXES=10.66.0.2/32
PQTUNNEL_LOCAL_PREFIXES=0.0.0.0/0,::/0
PQTUNNEL_PEER_NAME=10.66.0.2
PQTUNNEL_ALLOWED_DST_PORTS=$ALLOWED_PORTS
ENV
cat > "$DIALER_NETWORK" <<ENV
PQTUNNEL_ROLE=dialer
PQTUNNEL_WAN_IF=$DIALER_IF
PQTUNNEL_TUN=pqtun0
PQTUNNEL_TCP_EGRESS_PORTS=$TCP_PORTS
PQTUNNEL_UDP_EGRESS_PORTS=$UDP_PORTS
PQTUNNEL_TCP_FORWARD_RULES=
PQTUNNEL_UDP_FORWARD_RULES=
ENV
cat > "$GATEWAY_NETWORK" <<ENV
PQTUNNEL_ROLE=gateway
PQTUNNEL_WAN_IF=$GATEWAY_IF
PQTUNNEL_TUN=pqtun0
ENV
chmod 0600 "$DIALER_APP" "$GATEWAY_APP" "$DIALER_NETWORK" "$GATEWAY_NETWORK"

printf '\n===== Validate generated settings (read-only) =====\n'
bash "$SOURCE_DIR/scripts/pqtunnel-bootstrap.sh" check-config --kind dialer --app-env "$DIALER_APP" --network-env "$DIALER_NETWORK"
bash "$SOURCE_DIR/scripts/pqtunnel-bootstrap.sh" check-config --kind gateway --app-env "$GATEWAY_APP" --network-env "$GATEWAY_NETWORK"
PQTUNNEL_SITE_CONFIG="$DIALER_NETWORK" bash "$SOURCE_DIR/scripts/site-to-site-selective.sh" validate
PQTUNNEL_SITE_CONFIG="$DIALER_NETWORK" bash "$SOURCE_DIR/scripts/site-to-site-selective.sh" preview > "$WORK_DIR/dialer-network-preview.txt"
PQTUNNEL_SITE_CONFIG="$GATEWAY_NETWORK" bash "$SOURCE_DIR/scripts/site-to-site-selective.sh" validate
PQTUNNEL_SITE_CONFIG="$GATEWAY_NETWORK" bash "$SOURCE_DIR/scripts/site-to-site-selective.sh" preview > "$WORK_DIR/gateway-network-preview.txt"

# Keep the local manager safe before long-running staging: loopback-only, rotated token.
install_local_endpoint() {
  install -d -o root -g root -m 0750 /etc/pqtunnel /etc/pqtunnel/pki /usr/local/lib/pqtunnel /var/lib/pqtunnel
  install -o root -g root -m 0755 "$SOURCE_DIR/pqtunnel-client" /usr/local/bin/pqtunnel-client
  install -o root -g root -m 0755 "$SOURCE_DIR/scripts/site-to-site-selective.sh" /usr/local/lib/pqtunnel/site-to-site-selective.sh
  install -o root -g root -m 0755 "$SOURCE_DIR/scripts/run-pqtunnel-client.sh" /usr/local/lib/pqtunnel/run-client.sh
  install -o root -g root -m 0755 "$SOURCE_DIR/scripts/stop-pqtunnel-client-network.sh" /usr/local/lib/pqtunnel/stop-client-network.sh
  install -o root -g root -m 0644 "$WORK_DIR/pki-bundle/dialer-pki/ca.crt" /etc/pqtunnel/pki/ca.crt
  install -o root -g root -m 0644 "$WORK_DIR/pki-bundle/dialer-pki/client.crt" /etc/pqtunnel/pki/client.crt
  install -o root -g root -m 0600 "$WORK_DIR/pki-bundle/dialer-pki/client.key" /etc/pqtunnel/pki/client.key
  install -o root -g root -m 0640 "$DIALER_APP" /etc/default/pqtunnel-client
  install -o root -g root -m 0640 "$DIALER_NETWORK" /etc/pqtunnel/site-to-site.env
  install -o root -g root -m 0644 "$SOURCE_DIR/deploy/systemd/pqtunnel-client.service" /etc/systemd/system/pqtunnel-client.service
  PQTUNNEL_SITE_CONFIG=/etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh validate
  systemctl daemon-reload
  systemd-analyze verify /etc/systemd/system/pqtunnel-client.service
}

REMOTE_INSTALL=$(cat <<'REMOTE_INSTALL_SCRIPT'
set -Eeuo pipefail
STAGE=$1
VERSION=$2
fail() { echo "Gateway installer: $*" >&2; exit 1; }
[[ "$STAGE" =~ ^/tmp/pqtunnel-pair\.[A-Za-z0-9]+$ ]] || fail 'invalid staging path.'
trap 'rm -rf -- "$STAGE"' EXIT
cd "$STAGE"
. /etc/os-release
[[ "$ID" == ubuntu ]] || echo "WARNING: Gateway OS is $ID; only Ubuntu 24.04/26.04 is in the CI matrix." >&2
case "$(uname -m)" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) fail 'unsupported Gateway architecture.';; esac
ASSET="PQTunnel-${VERSION}-linux-${ARCH}.tar.gz"
[[ -s "$ASSET" && -s SHA256SUMS ]] || fail 'release asset or checksums missing.'
grep -Fq "  ./$ASSET" SHA256SUMS || fail 'asset not listed in SHA256SUMS.'
grep -F "  ./$ASSET" SHA256SUMS | sha256sum --check -
tar -xzf "$ASSET" -C "$STAGE"
SOURCE_DIR="$STAGE/PQTunnel-${VERSION}-linux-${ARCH}"
[[ -x "$SOURCE_DIR/pqtunneld" && -x "$SOURCE_DIR/pqtunnel-manager" ]] || fail 'release bundle is incomplete.'
count=0
for p in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service /etc/default/pqtunnel-manager; do [[ -e "$p" ]] && count=$((count+1)); done
if (( count == 0 )); then
  bash "$SOURCE_DIR/scripts/install-manager.sh" --source "$SOURCE_DIR" --role gateway
elif (( count != 3 )); then
  fail 'partial manager installation; refusing to overwrite it.'
else
  role=$(sed -n 's/^PQTUNNEL_MANAGER_ROLE=//p' /etc/default/pqtunnel-manager | head -n1)
  [[ "$role" == gateway ]] || fail "existing Gateway manager role is '$role', expected gateway."
fi
token=$(openssl rand -hex 32)
[[ "$token" =~ ^[0-9a-f]{64}$ ]] || fail 'failed to generate Gateway manager token.'
speedtest_token=$(sed -n 's/^PQTUNNEL_MANAGER_SPEEDTEST_TOKEN=//p' "$STAGE/manager-speedtest.env" | head -n1)
[[ "$speedtest_token" =~ ^[0-9a-f]{64}$ ]] || fail 'shared speed-test token is missing or invalid.'
systemctl stop pqtunnel-manager >/dev/null 2>&1 || true
cp -a /etc/default/pqtunnel-manager "/etc/default/pqtunnel-manager.backup.$(date +%Y%m%d-%H%M%S)"
tmp=$(mktemp /etc/default/pqtunnel-manager.XXXXXX)
awk '!/^[[:space:]]*PQTUNNEL_MANAGER_(ROLE|LISTEN|TOKEN|PUBLIC_HOST|ALLOW_INSECURE_PUBLIC_HTTP|TLS_CERT|TLS_KEY|SPEEDTEST_LISTEN|SPEEDTEST_PEER|SPEEDTEST_TOKEN)=/' /etc/default/pqtunnel-manager > "$tmp"
printf '\nPQTUNNEL_MANAGER_ROLE=gateway\nPQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091\nPQTUNNEL_MANAGER_TOKEN=%s\nPQTUNNEL_MANAGER_SPEEDTEST_LISTEN=10.66.0.1:9109\nPQTUNNEL_MANAGER_SPEEDTEST_PEER=10.66.0.2:9109\nPQTUNNEL_MANAGER_SPEEDTEST_TOKEN=%s\n' "$token" "$speedtest_token" >> "$tmp"
chown root:root "$tmp"; chmod 0600 "$tmp"; mv -f "$tmp" /etc/default/pqtunnel-manager
printf 'PAIR_GATEWAY_TOKEN=%s\n' "$token"
unset token speedtest_token
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/pqtunnel-manager.service
systemctl enable --now pqtunnel-manager
bash "$SOURCE_DIR/scripts/site-to-site-preflight.sh" --role gateway
bash "$SOURCE_DIR/scripts/install-server.sh" --source "$SOURCE_DIR" --pki "$STAGE/gateway-pki"
install -d -o root -g root -m 0750 /usr/local/lib/pqtunnel /etc/pqtunnel
install -o root -g root -m 0755 "$SOURCE_DIR/scripts/site-to-site-selective.sh" /usr/local/lib/pqtunnel/site-to-site-selective.sh
install -o root -g root -m 0640 "$STAGE/gateway-app.env" /etc/default/pqtunneld
install -o root -g root -m 0640 "$STAGE/gateway-network.env" /etc/pqtunnel/site-to-site.env
PQTUNNEL_SITE_CONFIG=/etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh validate
PQTUNNEL_SITE_CONFIG=/etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh preview >/dev/null
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/pqtunneld.service /etc/systemd/system/pqtunnel-manager.service
printf 'Gateway endpoint and manager installed; Gateway tunnel service remains stopped.\n'
REMOTE_INSTALL_SCRIPT
)
printf '%s\n' "$REMOTE_INSTALL" > "$WORK_DIR/remote-install.sh"
printf '%s\n' "$REMOTE_PRECHECK" > "$WORK_DIR/remote-precheck.sh"

# Prepare a Gateway-only payload: the Dialer private key and CA private key are never copied abroad.
case "$(ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" 'uname -m')" in
  x86_64|amd64) REMOTE_ARCH=amd64 ;;
  aarch64|arm64) REMOTE_ARCH=arm64 ;;
  *) fail 'unsupported Gateway architecture.' ;;
esac
REMOTE_ASSET="PQTunnel-${VERSION}-linux-${REMOTE_ARCH}.tar.gz"
REMOTE_BUNDLE="$WORK_DIR/$REMOTE_ASSET"
curl --fail --silent --show-error --location "$RELEASE_BASE/$REMOTE_ASSET" -o "$REMOTE_BUNDLE"
curl --fail --silent --show-error --location "$RELEASE_BASE/SHA256SUMS" -o "$WORK_DIR/SHA256SUMS"
grep -Fq "  ./$REMOTE_ASSET" "$WORK_DIR/SHA256SUMS" || fail 'Gateway asset is not listed in the release checksums.'
(cd "$WORK_DIR" && grep -F "  ./$REMOTE_ASSET" SHA256SUMS | sha256sum --check -)

REMOTE_STAGE=$(ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" 'umask 077; mktemp -d /tmp/pqtunnel-pair.XXXXXX')
[[ "$REMOTE_STAGE" =~ ^/tmp/pqtunnel-pair\.[A-Za-z0-9]+$ ]] || fail 'remote staging path did not pass validation.'
scp -P "$SSH_PORT" -o BatchMode=yes -r "$REMOTE_BUNDLE" "$WORK_DIR/SHA256SUMS" \
  "$GATEWAY_APP" "$GATEWAY_NETWORK" "$WORK_DIR/manager-speedtest.env" "$WORK_DIR/pki-bundle/gateway-pki" \
  "$REMOTE_TARGET:$REMOTE_STAGE/"

printf '\n===== Installing Gateway endpoint and manager (services kept stopped) =====\n'
REMOTE_OUTPUT=
REMOTE_RC=0
if [[ "$REMOTE_SUDO" == 1 ]]; then
  REMOTE_OUTPUT=$(ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" "sudo -n bash -s -- '$REMOTE_STAGE' '$VERSION'" < "$WORK_DIR/remote-install.sh" 2>&1) || REMOTE_RC=$?
else
  REMOTE_OUTPUT=$(ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" "bash -s -- '$REMOTE_STAGE' '$VERSION'" < "$WORK_DIR/remote-install.sh" 2>&1) || REMOTE_RC=$?
fi
TOKEN_GATEWAY=$(printf '%s\n' "$REMOTE_OUTPUT" | sed -n 's/^PAIR_GATEWAY_TOKEN=//p' | tail -n1)
printf '%s\n' "$REMOTE_OUTPUT" | sed '/^PAIR_GATEWAY_TOKEN=/d'
(( REMOTE_RC == 0 )) || fail "Gateway installation failed (exit $REMOTE_RC). No tunnel network rules were applied. Check the messages above."
[[ "$TOKEN_GATEWAY" =~ ^[0-9a-f]{64}$ ]] || fail 'Gateway install did not return its newly generated manager token; preserve the logs and inspect the Gateway manager config locally.'

printf '\n===== Installing Iran/Dialer endpoint and securing its manager =====\n'
install_local_endpoint

# The one-time CA signing key remains only in this root-only temporary directory and is removed by cleanup.
# Only each host's role-specific key/certificate/CA certificate was staged to that endpoint.
printf '\nBoth endpoint packages and loopback-only managers are installed. Tunnel services are still stopped.\n'
printf 'Before activation, ensure the Gateway provider firewall/security group allows inbound TCP/%s from the Iran VPS.\n' "$LISTEN_PORT"
printf 'Activation changes policy routing, nftables and forwarding on both hosts. It may interrupt SSH; use independent console/recovery access.\n'
prompt 'To start Gateway and Dialer and apply selected-port egress rules on both hosts, type APPLY-NETWORK: ' APPLY_CONFIRM
if [[ "$APPLY_CONFIRM" != APPLY-NETWORK ]]; then
  printf 'Activation skipped by operator. Both tunnel services remain stopped; no routes/NAT/forwarding were applied.\n'
  exit 0
fi
NETWORK_APPLY_ATTEMPTED=1

printf '\n===== Starting Gateway listener and applying Gateway rules =====\n'
REMOTE_START=$(cat <<'REMOTE_START_SCRIPT'
set -Eeuo pipefail
systemctl enable --now pqtunneld
/usr/local/lib/pqtunnel/site-to-site-selective.sh gateway-up
systemctl is-active --quiet pqtunneld
printf 'Gateway listener active and Gateway network helper applied.\n'
REMOTE_START_SCRIPT
)
if ! printf '%s\n' "$REMOTE_START" | remote_privileged; then
  remote_privileged <<'REMOTE_START_ROLLBACK'
systemctl stop pqtunneld >/dev/null 2>&1 || true
if [[ -f /var/lib/pqtunnel/site-selective-gateway.state ]]; then /usr/local/lib/pqtunnel/site-to-site-selective.sh gateway-down || true; fi
REMOTE_START_ROLLBACK
  fail 'Gateway start/network apply failed. Gateway service was stopped and its recorded network state was rolled back where possible.'
fi

# Check that the public listener is reachable from the Dialer before applying its policy rules.
if ! timeout 4 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$SERVER_NAME" "$LISTEN_PORT" >/dev/null 2>&1; then
  printf 'Gateway TCP/%s is not reachable from Iran. Stopping Gateway service; check provider firewall and listener settings.\n' "$LISTEN_PORT" >&2
  remote_privileged <<'REMOTE_ROLLBACK'
systemctl stop pqtunneld >/dev/null 2>&1 || true
if [[ -f /var/lib/pqtunnel/site-selective-gateway.state ]]; then /usr/local/lib/pqtunnel/site-to-site-selective.sh gateway-down || true; fi
REMOTE_ROLLBACK
  fail 'TCP listener check failed. Dialer was not started and Gateway policy state was rolled back where possible.'
fi

printf '\n===== Starting Iran/Dialer endpoint and applying Dialer rules =====\n'
if ! systemctl enable --now pqtunnel-client; then
  printf 'Dialer failed to start; attempting paired network rollback.\n' >&2
  systemctl stop pqtunnel-client >/dev/null 2>&1 || true
  remote_privileged <<'REMOTE_ROLLBACK'
systemctl stop pqtunneld >/dev/null 2>&1 || true
if [[ -f /var/lib/pqtunnel/site-selective-gateway.state ]]; then /usr/local/lib/pqtunnel/site-to-site-selective.sh gateway-down || true; fi
REMOTE_ROLLBACK
  fail 'Dialer start failed; Gateway was stopped and its recorded network state was rolled back where possible.'
fi
systemctl is-active --quiet pqtunnel-client || fail 'Dialer unit is not active after start.'
printf '\nSUCCESS: tunnel services are active. This does not prove end-to-end application connectivity or production readiness.\n'
printf 'Check peer status in the two management panels; use SSH forwarding, never expose TCP/9091 publicly.\n'
printf 'Iran panel forwarding from your own PC: ssh -N -L 9091:127.0.0.1:9091 USER@IRAN_PUBLIC_IP\n'
printf 'Gateway panel forwarding from your own PC: ssh -N -L 9092:127.0.0.1:9091 -p %s %s\n' "$SSH_PORT" "$REMOTE_TARGET"
printf 'Open http://127.0.0.1:9091/ for Iran and http://127.0.0.1:9092/ for Gateway.\n'
