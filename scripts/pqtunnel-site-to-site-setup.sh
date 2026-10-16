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
addport(){ [[ ",$1," == *",$2