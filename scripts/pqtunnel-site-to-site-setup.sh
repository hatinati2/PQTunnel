#!/usr/bin/env bash
# Guided pair setup: install a selective-port PQTunnel on this Dialer and a remote Gateway.
# Experimental. Network changes require exact confirmation and fail closed on existing rules.
set -Eeuo pipefail
umask 077
VERSION="${PQTUNNEL_SETUP_VERSION:-v0.3.0-rc4}"
REPO=hatinati2/PQTunnel
RELEASE="https://github.com/$REPO/releases/download/$VERSION"
RAW="https://raw.githubusercontent.com/$REPO/main"
WORK=""; STAGE=""; REMOTE=""; SSH_PORT=22
DIALER_TOKEN=""; GATEWAY_TOKEN=""; SPEED_TOKEN=""; TOKENS_READY=0; TOKENS_SHOWN=0
fail(){ printf 'PQTunnel setup: %s\n' "$*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || fail "missing prerequisite: $1"; }
ask(){ [[ -r /dev/tty ]] || fail 'run interactively from a terminal'; read -r -p "$1" "$2" </dev/tty; }
cleanup(){
  local rc=$?
  if [[ -n "$STAGE" && -n "$REMOTE" ]]; then ssh -p "$SSH_PORT" -o BatchMode=yes "$REMOTE" "rm -rf -- '$STAGE'" >/dev/null 2>&1 || true; fi
  if (( TOKENS_READY && ! TOKENS_SHOWN )); then
    printf '\nWARNING: setup stopped part-way; keep these generated tokens private and verify both configs before use.\n' >&2
    printf 'Iran/Dialer panel token: %s\nGermany/Gateway panel token: %s\nShared speed-test token: %s\n' "$DIALER_TOKEN" "$GATEWAY_TOKEN" "$SPEED_TOKEN" >&2
    TOKENS_SHOWN=1
  fi
  [[ -z "$WORK" ]] || rm -rf -- "$WORK" || rc=1
  return "$rc"
}
trap cleanup EXIT
valid_host(){ python3 - "$1" <<'PY'
import ipaddress,re,sys
v=sys.argv[1]
try: raise SystemExit(0 if ipaddress.ip_address(v).version==4 else 1)
except ValueError: pass
if not v or len(v)>253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',x) for x in v.rstrip('.').split('.')): raise SystemExit(1)
PY
}
ports(){
  local v="${1//[[:space:]]/}" label="$2" x out="" seen=","
  [[ "$v" == none || "$v" == - ]] && v=""
  [[ -z "$v" || "$v" =~ ^[0-9]+(,[0-9]+)*$ ]] || fail "$label must be comma-separated numbers (or none)."
  IFS=',' read -r -a xs <<< "$v"
  for x in "${xs[@]}"; do [[ -n "$x" ]] || continue; ((10#$x>=1 && 10#$x<=65535)) || fail "invalid $label port: $x"; x="$((10#$x))"; [[ "$seen" != *",$x,"* ]] || fail "duplicate $label port $x"; seen+="$x,"; out+="${out:+,}$x"; done
  printf '%s' "$out"
}
addport(){ [[ ",$1," == *",$2,"* ]] && printf '%s' "$1" || printf '%s' "${1:+$1,}$2"; }
allowlist(){ local out="" x; IFS=',' read -r -a xs <<< "$1"; for x in "${xs[@]}"; do [[ -n "$x" ]] && out+="${out:+,}tcp:$x"; done; IFS=',' read -r -a xs <<< "$2"; for x in "${xs[@]}"; do [[ -n "$x" ]] && out+="${out:+,}udp:$x"; done; printf '%s' "$out"; }
ifname(){ [[ "$1" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]]; }
arch(){ case "$(uname -m)" in x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; *) return 1;; esac; }
fetch_bundle(){
  local a="$1" asset="PQTunnel-$VERSION-linux-$1.tar.gz"
  curl -fsSL "$RELEASE/$asset" -o "$WORK/$asset"
  [[ -s "$WORK/SHA256SUMS" ]] || curl -fsSL "$RELEASE/SHA256SUMS" -o "$WORK/SHA256SUMS"
  grep -Fq "  ./$asset" "$WORK/SHA256SUMS" || fail "official SHA256SUMS lacks $asset"
  (cd "$WORK" && grep -F "  ./$asset" SHA256SUMS | sha256sum -c -)
  [[ -d "$WORK/PQTunnel-$VERSION-linux-$a" ]] || tar -xzf "$WORK/$asset" -C "$WORK"
}
manager_state(){
  local role="$1" n=0 p got
  for p in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service /etc/default/pqtunnel-manager; do [[ ! -e "$p" ]] || n=$((n+1)); done
  (( n==0 )) && return 0; (( n==3 )) || fail 'partial manager installation found; refusing overwrite.'
  got="$(sed -n 's/^PQTUNNEL_MANAGER_ROLE=//p' /etc/default/pqtunnel-manager | head -n1)"
  [[ "$got" == "$role" ]] || fail "existing manager role is $got, expected $role; resolve manually first."
}
network_guard(){
  local role="$1" rules
  command -v ip >/dev/null && command -v nft >/dev/null && command -v sysctl >/dev/null || fail "$role needs iproute2/nftables/procps"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then fail "$role has active UFW; no network changes made."; fi
  rules="$(nft list ruleset 2>/dev/null)" || fail "$role firewall state unreadable; refusing changes."
  ! grep -Eq '^[[:space:]]*table[[:space:]]' <<< "$rules" || fail "$role has existing nftables tables; refusing to overwrite firewall."
  if command -v iptables-save >/dev/null 2>&1 && iptables-save 2>/dev/null | grep -qE '^-A[[:space:]]'; then fail "$role has existing iptables rules; refusing changes."; fi
  [[ "$(sysctl -n net.ipv4.ip_forward)" == 0 && "$(sysctl -n net.ipv6.conf.all.forwarding)" == 0 ]] || fail "$role already has IP forwarding enabled; manual review required."
  ! ip -4 rule show | grep -Eq '^(10518|10519):' || fail "$role route priority is already used."
  ! ip -6 rule show | grep -Eq '^(10518|10519):' || fail "$role IPv6 route priority is already used."
  [[ -z "$(ip -4 route show table 518 2>/dev/null)$(ip -6 route show table 518 2>/dev/null)$(ip -4 route show table 519 2>/dev/null)$(ip -6 route show table 519 2>/dev/null)" ]] || fail "$role route table 518/519 already used."
  ! ip link show dev pqtun0 >/dev/null 2>&1 || fail "$role already has pqtun0; refusing unmanaged TUN interface."
}
write_manager(){
  local role="$1" token="$2" localip="$3" peerip="$4" speed="$5" temp line
  manager_state "$role"
  if [[ ! -x /usr/local/sbin/pqtunnel-manager ]]; then bash "$BUNDLE/scripts/install-manager.sh" --source "$BUNDLE" --role "$role"; fi
  temp="$(mktemp)"
  if [[ -f /etc/default/pqtunnel-manager ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      case "$line" in PQTUNNEL_MANAGER_ROLE=*|PQTUNNEL_MANAGER_LISTEN=*|PQTUNNEL_MANAGER_TOKEN=*|PQTUNNEL_MANAGER_PUBLIC_HOST=*|PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=*|PQTUNNEL_MANAGER_TLS_CERT=*|PQTUNNEL_MANAGER_TLS_KEY=*|PQTUNNEL_MANAGER_SPEEDTEST_LISTEN=*|PQTUNNEL_MANAGER_SPEEDTEST_PEER=*|PQTUNNEL_MANAGER_SPEEDTEST_TOKEN=*) ;; *) printf '%s\n' "$line";; esac
    done < /etc/default/pqtunnel-manager > "$temp"
  fi
  printf 'PQTUNNEL_MANAGER_ROLE=%s\nPQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091\nPQTUNNEL_MANAGER_TOKEN=%s\nPQTUNNEL_MANAGER_SPEEDTEST_LISTEN=%s:9109\nPQTUNNEL_MANAGER_SPEEDTEST_PEER=%s:9109\nPQTUNNEL_MANAGER_SPEEDTEST_TOKEN=%s\n' "$role" "$token" "$localip" "$peerip" "$speed" >> "$temp"
  install -o root -g root -m 0600 "$temp" /etc/default/pqtunnel-manager; rm -f "$temp"
}
main(){
  [[ $EUID -eq 0 ]] || fail 'run as root via sudo.'
  for c in curl sha256sum tar ssh scp python3 openssl awk sed grep install od tr systemctl getent timeout; do need "$c"; done
  [[ "$VERSION" =~ ^v[0-9A-Za-z._-]+$ ]] || fail 'invalid release version.'
  WORK="$(mktemp -d -t pqtunnel-pair.XXXXXX)"; chmod 0700 "$WORK"
  printf '\nPQTunnel two-VPS guided setup %s â experimental\n' "$VERSION"
  printf 'This installs the Iran Dialer and Germany Gateway, plus both web managers. It routes only selected destination ports, not all device traffic.\n'
  ask 'Germany Gateway SSH target (root@DNS-or-IPv4, key-based root SSH): ' REMOTE
  [[ "$REMOTE" =~ ^root@[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || fail 'use root@hostname or root@IPv4; IPv6 SSH targets not supported by this wizard.'
  ask 'SSH port [22]: ' tmp; SSH_PORT="${tmp:-22}"; [[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] && ((10#$SSH_PORT>=1 && 10#$SSH_PORT<=65535)) || fail 'invalid SSH port.'
  ask 'Gateway certificate DNS name or IPv4 (must match the public endpoint): ' GATEWAY_NAME; valid_host "$GATEWAY_NAME" || fail 'invalid Gateway certificate identity.'
  ask 'Gateway TLS listener port [8443]: ' tmp; TLS_PORT="${tmp:-8443}"; [[ 