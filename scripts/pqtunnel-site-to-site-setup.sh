#!/usr/bin/env bash
# Guided two-host PQTunnel setup. Selective-port only; refuses unmanaged network state.
set -Eeuo pipefail
umask 077
VERSION="${PQTUNNEL_SETUP_VERSION:-v0.3.0-rc5}"
REPO=hatinati2/PQTunnel
REL="https://github.com/$REPO/releases/download/$VERSION"
# Fetch the remote half from the same immutable release tag as the checked bundle.
RAW="https://raw.githubusercontent.com/$REPO/$VERSION"
WORK="" STAGE="" REMOTE="" SSH_PORT=22 DTOKEN="" GTOKEN="" STOKEN="" TOKENS_SHOWN=0 DIALER_TOKEN_NEW=1 DIALER_TOKEN_WAS_ROTATED=0
fail(){ printf 'PQTunnel setup: %s\n' "$*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || fail "Missing prerequisite: $1"; }
SETUP_INPUTS=()
SETUP_INPUT_INDEX=0
if [[ -n "${PQTUNNEL_SETUP_INPUT_FILE:-}" ]]; then
 [[ -f "$PQTUNNEL_SETUP_INPUT_FILE" && ! -L "$PQTUNNEL_SETUP_INPUT_FILE" ]] || fail 'Setup input file is missing or unsafe.'
 [[ "$(stat -c '%a' "$PQTUNNEL_SETUP_INPUT_FILE")" == 600 ]] || fail 'Setup input file must be mode 0600.'
 mapfile -t SETUP_INPUTS < "$PQTUNNEL_SETUP_INPUT_FILE"
fi
ask(){
 if [[ -n "${PQTUNNEL_SETUP_INPUT_FILE:-}" ]]; then
  if [[ "$1" == "Type exactly INSTALL to continue: " ]]; then
   [[ -n "${PQTUNNEL_SETUP_STATE_FILE:-}" && -n "${PQTUNNEL_SETUP_APPROVAL_FILE:-}" ]] || fail 'Graphical approval channel is not configured.'
   printf 'awaiting-confirmation\n' > "$PQTUNNEL_SETUP_STATE_FILE"
   chmod 0600 "$PQTUNNEL_SETUP_STATE_FILE"
   printf '\nWaiting for explicit approval in the authenticated management panel. No tunnel configuration or network rules have been applied yet.\n'
   local waited=0 approval=""
   while (( waited < 900 )); do
    if [[ -f "$PQTUNNEL_SETUP_APPROVAL_FILE" && ! -L "$PQTUNNEL_SETUP_APPROVAL_FILE" ]]; then
     approval="$(cat "$PQTUNNEL_SETUP_APPROVAL_FILE")"
     rm -f "$PQTUNNEL_SETUP_APPROVAL_FILE"
     [[ "$approval" == INSTALL ]] || fail 'The web approval value was invalid.'
     printf 'running\n' > "$PQTUNNEL_SETUP_STATE_FILE"
     chmod 0600 "$PQTUNNEL_SETUP_STATE_FILE"
     printf -v "$2" '%s' INSTALL
     return 0
    fi
    sleep 1
    waited=$((waited + 1))
   done
   fail 'Timed out waiting for web approval; no tunnel configuration or network rules were applied.'
  fi
  (( SETUP_INPUT_INDEX < ${#SETUP_INPUTS[@]} )) || fail 'Graphical setup input ended unexpectedly.'
  printf -v "$2" '%s' "${SETUP_INPUTS[$SETUP_INPUT_INDEX]}"
  SETUP_INPUT_INDEX=$((SETUP_INPUT_INDEX + 1))
 else
  [[ -r /dev/tty ]] || fail 'Run from an interactive terminal.'
  read -r -p "$1" "$2" </dev/tty
 fi
}
cleanup(){
 local rc=$?
 if [[ -n "$STAGE" && -n "$REMOTE" ]]; then ssh -p "$SSH_PORT" -o BatchMode=yes "$REMOTE" "rm -rf -- '$STAGE'" >/dev/null 2>&1 || true; fi
 if (( ! TOKENS_SHOWN )) && [[ ( "$DIALER_TOKEN_NEW" == 1 && -n "$DTOKEN" ) || -n "$GTOKEN" || -n "$STOKEN" ]]; then
  printf '\nWARNING: setup stopped part-way. Keep generated secrets private and verify which configs were installed.\n' >&2
  [[ -z "$DTOKEN" || "$DIALER_TOKEN_NEW" != 1 ]] || printf 'Iran/Dialer manager token: %s\n' "$DTOKEN" >&2
  [[ -z "$GTOKEN" ]] || printf 'Germany/Gateway manager token: %s\n' "$GTOKEN" >&2
  [[ -z "$STOKEN" ]] || printf 'Shared speed-test token: %s\n' "$STOKEN" >&2
  TOKENS_SHOWN=1
 fi
 [[ -z "$WORK" ]] || rm -rf "$WORK" || rc=1
 return "$rc"
}
trap cleanup EXIT
valid_host(){ python3 - "$1" <<'PY'
import ipaddress,re,sys
v=sys.argv[1]
try: raise SystemExit(0 if ipaddress.ip_address(v).version==4 else 1)
except ValueError: pass
if re.fullmatch(r'[0-9.]+', v): raise SystemExit(1)
if not v or len(v)>253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',x) for x in v.rstrip('.').split('.')): raise SystemExit(1)
PY
}
parse_ports(){
 local v="$1" label="$2" x out="" seen=","
 v="${v//[[:space:]]/}"; [[ "$v" == none || "$v" == - ]] && v=""
 [[ -z "$v" || "$v" =~ ^[0-9]+(,[0-9]+)*$ ]] || fail "$label must be comma-separated ports (or none)."
 IFS=',' read -r -a xs <<< "$v"
 for x in "${xs[@]}"; do [[ -n "$x" ]] || continue; ((10#$x>0 && 10#$x<65536)) || fail "Invalid port: $x"; x="$((10#$x))"; [[ "$seen" != *",$x,"* ]] || fail "Duplicate port: $x"; seen+="$x,"; out+="${out:+,}$x"; done
 printf '%s' "$out"
}
add_port(){ [[ ",$1," == *",$2,"* ]] && printf '%s' "$1" || printf '%s' "${1:+$1,}$2"; }
allowlist(){
 local out="" x; IFS=',' read -r -a xs <<< "$1"; for x in "${xs[@]}"; do [[ -n "$x" ]] && out+="${out:+,}tcp:$x"; done
 IFS=',' read -r -a xs <<< "$2"; for x in "${xs[@]}"; do [[ -n "$x" ]] && out+="${out:+,}udp:$x"; done; printf '%s' "$out"
}
arch(){ case "$(uname -m)" in x86_64|amd64) printf amd64;; aarch64|arm64) printf arm64;; *) return 1;; esac; }
ifname(){ [[ "$1" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]]; }
fetch_bundle(){
 local a="$1" asset="PQTunnel-$VERSION-linux-$1.tar.gz"
 curl -fsSL "$REL/$asset" -o "$WORK/$asset"
 [[ -s "$WORK/SHA256SUMS" ]] || curl -fsSL "$REL/SHA256SUMS" -o "$WORK/SHA256SUMS"
 grep -Fq "  ./$asset" "$WORK/SHA256SUMS" || fail "Release checksum list lacks $asset"
 (cd "$WORK" && grep -F "  ./$asset" SHA256SUMS | sha256sum --check -)
 [[ -d "$WORK/PQTunnel-$VERSION-linux-$a" ]] || tar -xzf "$WORK/$asset" -C "$WORK"
}
manager_check(){
 local role="$1" n=0 p got
 for p in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service /etc/default/pqtunnel-manager; do [[ ! -e "$p" ]] || n=$((n+1)); done
 (( n==0 )) && return 0; (( n==3 )) || fail 'Partial manager installation found; refusing overwrite.'
 got="$(sed -n 's/^PQTUNNEL_MANAGER_ROLE=//p' /etc/default/pqtunnel-manager | head -n1)"
 [[ "$got" == "$role" ]] || fail "Existing manager role is $got, expected $role; resolve it manually first."
}
secure_existing_local_manager(){
 local config=/etc/default/pqtunnel-manager count=0 path role tmp backup
 for path in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service "$config"; do
  [[ ! -e "$path" ]] || count=$((count+1))
 done
 (( count==0 )) && return 0
 (( count==3 )) || fail 'Partial local manager installation found; inspect it before continuing.'
 role="$(sed -n 's/^PQTUNNEL_MANAGER_ROLE=//p' "$config" | head -n1)"
 [[ "$role" == dialer ]] || fail "Existing local manager role is '$role', not 'dialer'; refusing to take over the wrong role."
 local current_listen current_insecure
 current_listen="$(sed -n 's/^PQTUNNEL_MANAGER_LISTEN=//p' "$config" | head -n1)"
 current_insecure="$(sed -n 's/^PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=//p' "$config" | head -n1)"
 if [[ "$current_insecure" != true && ( "$current_listen" =~ ^127\.0\.0\.1:[0-9]+$ || "$current_listen" =~ ^\[::1\]:[0-9]+$ ) ]]; then
  printf 'Existing manager is already loopback-only; preserving its token.\n'
  return 0
 fi
 DTOKEN="$(openssl rand -hex 32)"
 DIALER_TOKEN_WAS_ROTATED=1
 [[ "$DTOKEN" =~ ^[0-9a-f]{64}$ ]] || fail 'Could not generate a secure Dialer manager token.'
 backup="$config.backup.$(date +%Y%m%d-%H%M%S)"
 cp -a -- "$config" "$backup"; chown root:root "$backup"; chmod 0600 "$backup"
 tmp="$(mktemp /etc/default/pqtunnel-manager.XXXXXX)"
 awk '!/^[[:space:]]*PQTUNNEL_MANAGER_(ROLE|LISTEN|TOKEN|PUBLIC_HOST|ALLOW_INSECURE_PUBLIC_HTTP|TLS_CERT|TLS_KEY|SPEEDTEST_LISTEN|SPEEDTEST_PEER|SPEEDTEST_TOKEN)=/' "$config" > "$tmp"
 printf '\nPQTUNNEL_MANAGER_ROLE=dialer\nPQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091\nPQTUNNEL_MANAGER_TOKEN=%s\n' "$DTOKEN" >> "$tmp"
 chown root:root "$tmp"; chmod 0600 "$tmp"; mv -f "$tmp" "$config"
 systemctl daemon-reload
 systemd-analyze verify /etc/systemd/system/pqtunnel-manager.service
 if systemctl is-active --quiet pqtunnel-manager; then
  if ! systemctl restart pqtunnel-manager; then
   systemctl stop pqtunnel-manager >/dev/null 2>&1 || true
   fail 'Manager restart failed after hardening; service was stopped. The new token is printed on exit.'
  fi
 fi
 printf 'Existing Dialer manager is now restricted to loopback and its login token has been rotated.\n'
}
network_guard(){
 local label="$1" rules
 command -v ip >/dev/null && command -v nft >/dev/null && command -v sysctl >/dev/null || fail "$label needs iproute2, nftables and procps."
 if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then fail "$label has active UFW; refusing automatic firewall changes."; fi
 rules="$(nft list ruleset 2>/dev/null)" || fail "$label firewall state unreadable; refusing changes."
 ! grep -Eq '^[[:space:]]*table[[:space:]]' <<< "$rules" || fail "$label already has nftables rules; refusing overwrite."
 if command -v iptables-save >/dev/null 2>&1 && iptables-save 2>/dev/null | grep -qE '^-A[[:space:]]'; then fail "$label already has iptables rules; refusing changes."; fi
 [[ "$(sysctl -n net.ipv4.ip_forward)" == 0 && "$(sysctl -n net.ipv6.conf.all.forwarding)" == 0 ]] || fail "$label already has forwarding enabled; manual review required."
 ! ip -4 rule show | grep -Eq '^(10518|10519):' || fail "$label route priority already occupied."
 ! ip -6 rule show | grep -Eq '^(10518|10519):' || fail "$label IPv6 route priority occupied."
 [[ -z "$(ip -4 route show table 518 2>/dev/null)$(ip -6 route show table 518 2>/dev/null)$(ip -4 route show table 519 2>/dev/null)$(ip -6 route show table 519 2>/dev/null)" ]] || fail "$label route table 518/519 in use."
 ! ip link show dev pqtun0 >/dev/null 2>&1 || fail "$label already has pqtun0; refusing unmanaged TUN."
}
main(){
 [[ "$EUID" -eq 0 ]] || fail 'Run via sudo/root.'
 [[ "$VERSION" =~ ^v[0-9A-Za-z._-]+$ ]] || fail 'Invalid version.'
 for c in openssl systemctl systemd-analyze awk grep sed install stat cp date mktemp chown chmod mv head; do need "$c"; done
 [[ -d /run/systemd/system ]] || fail 'systemd is not running; no changes made.'
 WORK="$(mktemp -d -t pqtunnel-site-to-site.XXXXXX)"; chmod 0700 "$WORK"
 # Secure any existing public-HTTP panel before SSH checks, package setup, or network preflight.
 secure_existing_local_manager
 if [[ "${PQTUNNEL_SETUP_PRESERVE_DIALER_MANAGER_TOKEN:-0}" == 1 && "$DIALER_TOKEN_WAS_ROTATED" == 0 && -f /etc/default/pqtunnel-manager ]]; then
  existing_token="$(sed -n 's/^PQTUNNEL_MANAGER_TOKEN=//p' /etc/default/pqtunnel-manager | head -n1)"
  if [[ "$existing_token" =~ ^[0-9a-f]{64}$ ]]; then
   DTOKEN="$existing_token"
   DIALER_TOKEN_NEW=0
   printf 'Existing Dialer manager token will be preserved for the graphical session.\n'
  fi
 fi
 for c in curl sha256sum tar ssh scp python3 getent; do need "$c"; done
 printf '\nPQTunnel two-VPS setup %s (EXPERIMENTAL)\n' "$VERSION"
 printf 'Installs Iran/Dialer + Germany/Gateway and both panels. Routes selected destination ports only, not all device traffic.\n'
 ask 'Germany Gateway SSH target (root@DNS-or-IPv4; root SSH key required): ' REMOTE
 [[ "$REMOTE" =~ ^root@[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || fail 'Use root@DNS or root@IPv4; IPv6 SSH targets are unsupported in this wizard.'
 ask 'Gateway SSH port [22]: ' tmp; SSH_PORT="${tmp:-22}"; [[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] && ((10#$SSH_PORT>0 && 10#$SSH_PORT<65536)) || fail 'Invalid SSH port.'
 ask 'Gateway certificate DNS name or IPv4 (must match public endpoint): ' NAME; valid_host "$NAME" || fail 'Invalid certificate identity.'
 ask 'Gateway TLS listener port [8443]: ' tmp; TLS_PORT="${tmp:-8443}"; [[ "$TLS_PORT" =~ ^[0-9]{1,5}$ ]] && ((10#$TLS_PORT>0 && 10#$TLS_PORT<65536)) || fail 'Invalid TLS port.'
 ask 'TCP destination ports through Germany [443]: ' tmp; TCP="$(parse_ports "${tmp:-443}" TCP)"
 ask 'UDP destination ports through Germany [53,123; type none for none]: ' tmp; UDP="$(parse_ports "${tmp:-53,123}" UDP)"
 [[ -n "$TCP$UDP" ]] || fail 'Choose at least one destination port.'
 ALLOW="$(allowlist "$TCP" "$UDP")"; ALLOW="${ALLOW:+$ALLOW,}tcp:9109"
 ssh -p "$SSH_PORT" -o ConnectTimeout=8 "$REMOTE" 'test "$(id -u)" = 0 && echo ROOT_OK' | grep -q ROOT_OK || fail 'Root SSH failed; no tunnel or routing was configured.'
 LOCAL_ARCH="$(arch)" || fail 'Unsupported local architecture.'
 REMOTE_ARCH="$(ssh -p "$SSH_PORT" "$REMOTE" 'case "$(uname -m)" in x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; *) exit 2;; esac')" || fail 'Unsupported Gateway architecture.'
 getent ahostsv4 "$NAME" >/dev/null 2>&1 || [[ "$NAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Gateway name does not resolve to IPv4 from Iran.'
 GATEWAY_IP="$NAME"; [[ "$NAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || GATEWAY_IP="$(getent ahostsv4 "$NAME" | awk 'NR==1{print $1}')"
 fetch_bundle "$LOCAL_ARCH"; BUNDLE="$WORK/PQTunnel-$VERSION-linux-$LOCAL_ARCH"
 [[ -x "$BUNDLE/pqtunnel-client" && -x "$BUNDLE/pqtunnel-pki" && -x "$BUNDLE/pqtunnel-manager" ]] || fail 'Release bundle lacks a required binary.'
 fetch_bundle "$REMOTE_ARCH"
 curl -fsSL "$RAW/scripts/pqtunnel-site-to-site-remote.sh" -o "$WORK/remote-setup.sh"; bash -n "$WORK/remote-setup.sh"
 . /etc/os-release; [[ "${ID:-}" == ubuntu || "${ID:-}" == debian ]] || fail 'Automatic dependency installation supports Ubuntu/Debian only.';
 manager_check dialer
 for p in /usr/local/bin/pqtunnel-client /etc/systemd/system/pqtunnel-client.service /etc/pqtunnel/pki/client.crt /etc/pqtunnel/pki/client.key /etc/pqtunnel/pki/ca.crt /etc/default/pqtunnel-client /etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh /usr/local/lib/pqtunnel/run-client.sh /usr/local/lib/pqtunnel/stop-client-network.sh; do [[ ! -e "$p" ]] || fail "Existing Dialer artifact at $p; refusing overwrite."; done
 missing=(); for pair in 'ip:iproute2' 'nft:nftables' 'openssl:openssl' 'sysctl:procps' 'ss:iproute2' 'systemctl:systemd' 'systemd-analyze:systemd'; do c="${pair%%:*}"; p="${pair#*:}"; command -v "$c" >/dev/null 2>&1 || missing+=("$p"); done
 if (("${#missing[@]}")); then apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl tar python3 "${missing[@]}"; fi
 ssh -p "$SSH_PORT" "$REMOTE" 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl tar openssl iproute2 nftables procps systemd'
 bash "$BUNDLE/scripts/site-to-site-preflight.sh" --role dialer
 WAN="$(ip -o route get "$GATEWAY_IP" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}')"; [[ -n "$WAN" ]] || WAN="$(ip -o route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}')"
 ask "Iran WAN interface [$WAN]: " tmp; WAN="${tmp:-$WAN}"; ifname "$WAN" && ip link show dev "$WAN" >/dev/null 2>&1 || fail 'Invalid Iran WAN interface.'
 GW_WAN="$(ssh -p "$SSH_PORT" "$REMOTE" "ip -o route show default | awk '{for(i=1;i<=NF;i++) if(\\$i==\\"dev\\"){print \\$(i+1);exit}}'")"
 ask "Germany WAN interface [$GW_WAN]: " tmp; GW_WAN="${tmp:-$GW_WAN}"; ifname "$GW_WAN" || fail 'Invalid Gateway interface.'
 ssh -p "$SSH_PORT" "$REMOTE" "ip link show dev '$GW_WAN' >/dev/null" || fail 'Gateway WAN interface not found.'
 network_guard dialer
 ssh -p "$SSH_PORT" "$REMOTE" "bash -s -- '$TLS_PORT'" <<'GUARD'
set -Eeuo pipefail
TLS_PORT="${1:-}"
for cmd in ip nft sysctl ss; do
 command -v "$cmd" >/dev/null 2>&1 || { echo "Gateway prerequisite missing: $cmd" >&2; exit 1; }
done
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
 echo 'Gateway has active UFW; refusing automatic firewall integration.' >&2; exit 1
fi
rules="$(nft list ruleset 2>/dev/null)" || { echo 'Gateway nftables state cannot be read; refusing changes.' >&2; exit 1; }
if grep -Eq '^[[:space:]]*table[[:space:]]' <<< "$rules"; then
 echo 'Gateway has existing nftables tables/rules; refusing to overwrite them.' >&2; exit 1
fi
if command -v iptables-save >/dev/null 2>&1 && iptables-save 2>/dev/null | grep -qE '^-A[[:space:]]'; then
 echo 'Gateway has existing iptables rules; refusing to overwrite them.' >&2; exit 1
fi
if [[ "$(sysctl -n net.ipv4.ip_forward)" != 0 || "$(sysctl -n net.ipv6.conf.all.forwarding)" != 0 ]]; then
 echo 'Gateway forwarding is already enabled; manual network review is required.' >&2; exit 1
fi
if ip link show dev pqtun0 >/dev/null 2>&1; then
 echo 'Gateway already has pqtun0; refusing to take over an unmanaged TUN.' >&2; exit 1
fi
if ip -4 rule show | grep -Eq '^(10518|10519):' || ip -6 rule show | grep -Eq '^(10518|10519):'; then
 echo 'Gateway policy-routing priority 10518/10519 is occupied.' >&2; exit 1
fi
if [[ -n "$(ip -4 route show table 518)$(ip -6 route show table 518)$(ip -4 route show table 519)$(ip -6 route show table 519)" ]]; then
 echo 'Gateway policy-routing table 518/519 is already used.' >&2; exit 1
fi
for p in /usr/local/sbin/pqtunneld /etc/systemd/system/pqtunneld.service /etc/default/pqtunneld /etc/pqtunnel/pki/server.crt /etc/pqtunnel/pki/server.key /etc/pqtunnel/pki/ca.crt /etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh; do
 [[ ! -e "$p" ]] || { echo "Existing Gateway artifact: $p" >&2; exit 1; }
done
if ss -ltnH 2>/dev/null | awk -v p=":$TLS_PORT" '$4 ~ (p "$") {found=1} END {exit !found}'; then
 echo "Gateway TCP port $TLS_PORT is already in use." >&2; exit 1
fi
GUARD
 printf '\nPreflight plan: Iran/Dialer -> %s:%s; Iran WAN=%s; Germany WAN=%s; TCP destinations=%s; UDP destinations=%s.\n' "$NAME" "$TLS_PORT" "$WAN" "$GW_WAN" "$TCP" "${UDP:-none}"
 printf 'Both hosts passed local network guards and endpoint-artifact checks. Missing OS packages may already have been installed. No tunnel network rules have been applied yet.\n'
 printf 'The Gateway provider firewall is not modified. Confirm TCP/%s is allowed there before continuing.\n' "$TLS_PORT"
 ask 'Type exactly INSTALL to continue: ' CONFIRM; [[ "$CONFIRM" == INSTALL ]] || fail 'Cancelled before PKI creation or tunnel/network activation.'
 manager_check dialer
 [[ -n "$DTOKEN" ]] || DTOKEN="$(openssl rand -hex 32)"
 GTOKEN="$(openssl rand -hex 32)"; STOKEN="$(openssl rand -hex 32)"
 [[ "$DTOKEN$GTOKEN$STOKEN" =~ ^[0-9a-f]{192}$ ]] || fail 'Secure token generation failed.'
 mkdir -m 0700 "$WORK/tokens"
 mkdir -m 0700 "$WORK/authority" "$WORK/gateway-pki" "$WORK/dialer-pki"
 "$BUNDLE/pqtunnel-pki" init --server-name "$NAME" --out "$WORK/authority"
 "$BUNDLE/pqtunnel-pki" issue-client --ip 10.66.0.2 --out "$WORK/authority"
 install -m 0644 "$WORK/authority/server.crt" "$WORK/gateway-pki/server.crt"; install -m 0600 "$WORK/authority/server.key" "$WORK/gateway-pki/server.key"; install -m 0644 "$WORK/authority/ca.crt" "$WORK/gateway-pki/ca.crt"
 install -m 0644 "$WORK/authority/ca.crt" "$WORK/dialer-pki/ca.crt"; install -m 0644 "$WORK/authority/client-10_66_0_2.crt" "$WORK/dialer-pki/client.crt"; install -m 0600 "$WORK/authority/client-10_66_0_2.key" "$WORK/dialer-pki/client.key"
 printf '%s' "$GTOKEN" > "$WORK/tokens/gateway"; printf '%s' "$STOKEN" > "$WORK/tokens/speed"
 cat > "$WORK/gateway-app.env" <<ENV
PQTUNNEL_LISTEN=0.0.0.0:$TLS_PORT
PQTUNNEL_TLS_CERT=/etc/pqtunnel/pki/server.crt
PQTUNNEL_TLS_KEY=/etc/pqtunnel/pki/server.key
PQTUNNEL_CLIENT_CA=/etc/pqtunnel/pki/ca.crt
PQTUNNEL_MAX_CLIENTS=1
PQTUNNEL_PEER_PREFIXES=10.66.0.2/32,fd42:7061:7475::2/128
PQTUNNEL_LOCAL_PREFIXES=0.0.0.0/0,::/0
PQTUNNEL_PEER_NAME=10.66.0.2
PQTUNNEL_ALLOWED_DST_PORTS=$ALLOW
ENV
 cat > "$WORK/dialer-app.env" <<ENV
PQTUNNEL_SERVER=$NAME:$TLS_PORT
PQTUNNEL_SERVER_NAME=$NAME
PQTUNNEL_LOCAL_PREFIXES=10.66.0.2/32,fd42:7061:7475::2/128
PQTUNNEL_REMOTE_PREFIXES=0.0.0.0/0,::/0
PQTUNNEL_ALLOWED_DST_PORTS=$ALLOW
ENV
 cat > "$WORK/gateway-network.env" <<ENV
PQTUNNEL_ROLE=gateway
PQTUNNEL_WAN_IF=$GW_WAN
PQTUNNEL_TUN=pqtun0
ENV
 cat > "$WORK/dialer-network.env" <<ENV
PQTUNNEL_ROLE=dialer
PQTUNNEL_WAN_IF=$WAN
PQTUNNEL_TUN=pqtun0
PQTUNNEL_TCP_EGRESS_PORTS=$TCP
PQTUNNEL_UDP_EGRESS_PORTS=$UDP
PQTUNNEL_TCP_FORWARD_RULES=
PQTUNNEL_UDP_FORWARD_RULES=
ENV
 chmod 0600 "$WORK/"*.env "$WORK/tokens/"*
 bash "$BUNDLE/scripts/pqtunnel-bootstrap.sh" check-config --kind dialer --app-env "$WORK/dialer-app.env" --network-env "$WORK/dialer-network.env"
 PQTUNNEL_SITE_CONFIG="$WORK/dialer-network.env" bash "$BUNDLE/scripts/site-to-site-selective.sh" validate
 STAGE="$(ssh -p "$SSH_PORT" "$REMOTE" 'umask 077; mktemp -d /tmp/pqtunnel-site-to-site.XXXXXXXX')"
 [[ "$STAGE" =~ ^/tmp/pqtunnel-site-to-site\.[A-Za-z0-9]+$ ]] || fail 'Unsafe remote staging path.'
 scp -P "$SSH_PORT" "$WORK/PQTunnel-$VERSION-linux-$REMOTE_ARCH.tar.gz" "$WORK/SHA256SUMS" "$WORK/remote-setup.sh" "$WORK/gateway-app.env" "$WORK/gateway-network.env" "$REMOTE:$STAGE/"
 scp -P "$SSH_PORT" "$WORK/tokens/gateway" "$REMOTE:$STAGE/gateway-manager-token"
 scp -P "$SSH_PORT" "$WORK/tokens/speed" "$REMOTE:$STAGE/speedtest-token"
 scp -P "$SSH_PORT" -r "$WORK/gateway-pki" "$REMOTE:$STAGE/"
 ssh -p "$SSH_PORT" "$REMOTE" "bash '$STAGE/remote-setup.sh' preflight '$STAGE' '$VERSION' '$TLS_PORT'"
 ssh -p "$SSH_PORT" "$REMOTE" "bash '$STAGE/remote-setup.sh' install '$STAGE' '$VERSION' '$TLS_PORT'"
 timeout 8 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$NAME" "$TLS_PORT" || fail "Gateway TCP/$TLS_PORT unreachable. Open it in the provider firewall; Dialer routes not applied."
 ssh -p "$SSH_PORT" "$REMOTE" "bash '$STAGE/remote-setup.sh' apply-network '$STAGE' '$VERSION' '$TLS_PORT'"
 openssl verify -purpose sslclient -CAfile "$WORK/dialer-pki/ca.crt" "$WORK/dialer-pki/client.crt" >/dev/null
 cert_hash="$(openssl x509 -in "$WORK/dialer-pki/client.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')"
 key_hash="$(openssl pkey -in "$WORK/dialer-pki/client.key" -pubout -outform DER | sha256sum | awk '{print $1}')"; [[ "$cert_hash" == "$key_hash" ]] || fail 'Dialer key/certificate mismatch.'
 install -d -o root -g root -m 0750 /etc/pqtunnel /etc/pqtunnel/pki /usr/local/lib/pqtunnel /var/lib/pqtunnel
 install -o root -g root -m 0755 "$BUNDLE/pqtunnel-client" /usr/local/bin/pqtunnel-client
 install -o root -g root -m 0644 "$WORK/dialer-pki/ca.crt" /etc/pqtunnel/pki/ca.crt; install -o root -g root -m 0644 "$WORK/dialer-pki/client.crt" /etc/pqtunnel/pki/client.crt; install -o root -g root -m 0600 "$WORK/dialer-pki/client.key" /etc/pqtunnel/pki/client.key
 install -o root -g root -m 0640 "$WORK/dialer-app.env" /etc/default/pqtunnel-client; install -o root -g root -m 0640 "$WORK/dialer-network.env" /etc/pqtunnel/site-to-site.env
 install -o root -g root -m 0755 "$BUNDLE/scripts/site-to-site-selective.sh" /usr/local/lib/pqtunnel/site-to-site-selective.sh; install -o root -g root -m 0755 "$BUNDLE/scripts/run-pqtunnel-client.sh" /usr/local/lib/pqtunnel/run-client.sh; install -o root -g root -m 0755 "$BUNDLE/scripts/stop-pqtunnel-client-network.sh" /usr/local/lib/pqtunnel/stop-client-network.sh
 install -o root -g root -m 0644 "$BUNDLE/deploy/systemd/pqtunnel-client.service" /etc/systemd/system/pqtunnel-client.service
 systemctl daemon-reload; systemd-analyze verify /etc/systemd/system/pqtunnel-client.service
 manager_check dialer
 if [[ ! -x /usr/local/sbin/pqtunnel-manager ]]; then bash "$BUNDLE/scripts/install-manager.sh" --source "$BUNDLE" --role dialer; fi
 mt="$(mktemp)"; if [[ -f /etc/default/pqtunnel-manager ]]; then grep -Ev '^(PQTUNNEL_MANAGER_ROLE|PQTUNNEL_MANAGER_LISTEN|PQTUNNEL_MANAGER_TOKEN|PQTUNNEL_MANAGER_PUBLIC_HOST|PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP|PQTUNNEL_MANAGER_TLS_CERT|PQTUNNEL_MANAGER_TLS_KEY|PQTUNNEL_MANAGER_SPEEDTEST_LISTEN|PQTUNNEL_MANAGER_SPEEDTEST_PEER|PQTUNNEL_MANAGER_SPEEDTEST_TOKEN)=' /etc/default/pqtunnel-manager > "$mt" || true; fi
 printf 'PQTUNNEL_MANAGER_ROLE=dialer\nPQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091\nPQTUNNEL_MANAGER_TOKEN=%s\nPQTUNNEL_MANAGER_SPEEDTEST_LISTEN=10.66.0.2:9109\nPQTUNNEL_MANAGER_SPEEDTEST_PEER=10.66.0.1:9109\nPQTUNNEL_MANAGER_SPEEDTEST_TOKEN=%s\n' "$DTOKEN" "$STOKEN" >> "$mt"; install -o root -g root -m 0600 "$mt" /etc/default/pqtunnel-manager; rm -f "$mt"
 systemctl enable --now pqtunnel-client; systemctl --no-pager --full status pqtunnel-client
 systemctl enable --now pqtunnel-manager; systemctl restart pqtunnel-manager; systemctl --no-pager --full status pqtunnel-manager
 ssh -p "$SSH_PORT" "$REMOTE" 'systemctl --no-pager is-active pqtunneld && systemctl --no-pager is-active pqtunnel-manager'
 printf '\nSetup finished. Save newly generated tokens privately (one-time display).\n'
 if [[ "$DIALER_TOKEN_NEW" == 1 ]]; then printf 'Iran/Dialer manager token: %s\n' "$DTOKEN"; fi
 printf 'Germany/Gateway manager token: %s\nShared speed-test token: %s\n' "$GTOKEN" "$STOKEN"
 printf '\nPanels are loopback-only. On your admin computer use:\nGermany: ssh -N -L 9091:127.0.0.1:9091 -p %s %s\nIran:    ssh -N -L 9092:127.0.0.1:9091 USER@IRAN_PUBLIC_IP\nReplace USER@IRAN_PUBLIC_IP with your SSH user and public address for the Iran VPS.\nThen open http://127.0.0.1:9091 (Germany) or http://127.0.0.1:9092 (Iran).\n' "$SSH_PORT" "$REMOTE"
 printf 'Via Germany: TCP %s; UDP %s. Other destination ports remain direct. Provider firewall was not changed.\n' "$TCP" "${UDP:-none}"
 ssh -p "$SSH_PORT" "$REMOTE" "rm -rf -- '$STAGE'" || fail 'Setup completed, but remote staging directory cleanup failed.'
 STAGE=""; TOKENS_SHOWN=1
}
main "$@"
