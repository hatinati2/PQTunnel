#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Prepare a staged PKI bundle for one PQTunnel Gateway and one Dialer.
This script generates certificates only. It does not install services or alter network state.

Usage:
  bash scripts/prepare-site-to-site-pki.sh \
    --server-name vpn.example.com \
    --client-ip 10.66.0.2 \
    --out /secure/path/pqtunnel-pki-bundle

Output:
  OUT/ca-offline/       CA certificate and private CA key; keep offline.
  OUT/gateway-pki/      server.crt, server.key, ca.crt
  OUT/dialer-pki/       client.crt, client.key, ca.crt

Copy only gateway-pki to the Gateway and only dialer-pki to the Dialer.
Never copy ca-offline or ca.key to either endpoint.
The client certificate Common Name is the value of --client-ip.
USAGE
}

fail() { printf 'pqtunnel-pki-bundle: %s\n' "$*" >&2; exit 1; }

SERVER_NAME=
CLIENT_IP=
OUT_INPUT=

while (($#)); do
  case "$1" in
    --server-name) [[ $# -ge 2 ]] || fail 'missing --server-name value'; SERVER_NAME="$2"; shift 2 ;;
    --client-ip) [[ $# -ge 2 ]] || fail 'missing --client-ip value'; CLIENT_IP="$2"; shift 2 ;;
    --out) [[ $# -ge 2 ]] || fail 'missing --out value'; OUT_INPUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

[[ -n "$SERVER_NAME" ]] || fail '--server-name is required.'
[[ -n "$CLIENT_IP" ]] || fail '--client-ip is required.'
[[ -n "$OUT_INPUT" ]] || fail '--out is required.'
command -v python3 >/dev/null 2>&1 || fail 'Python 3 is required to validate the server name.'
if ! python3 - "$SERVER_NAME" <<'PY'
import ipaddress
import re
import sys

value = sys.argv[1]
try:
    ipaddress.ip_address(value)
    raise SystemExit(0)
except ValueError:
    pass

if all(char in "0123456789." for char in value):
    raise SystemExit(1)

name = value[:-1] if value.endswith(".") else value
labels = name.split(".")
if len(name) > 253 or not name or not all(
    re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
    for label in labels
):
    raise SystemExit(1)
PY
then
  fail '--server-name must be a valid DNS name or IP literal.'
fi
[[ "$CLIENT_IP" =~ ^[0-9.]+$ ]] || fail '--client-ip must be an IPv4 address.'

command -v go >/dev/null 2>&1 || fail 'Go is required to build cmd/pqtunnel-pki.'
command -v openssl >/dev/null 2>&1 || fail 'OpenSSL is required to validate generated certificates.'
[[ -f go.mod && -f cmd/pqtunnel-pki/main.go ]] || fail 'run this script from the PQTunnel repository root.'

OUT_PARENT="$(dirname -- "$OUT_INPUT")"
OUT_BASE="$(basename -- "$OUT_INPUT")"
[[ "$OUT_BASE" != "." && "$OUT_BASE" != "/" && -n "$OUT_BASE" ]] || fail 'invalid output directory.'
mkdir -p -- "$OUT_PARENT"
OUT_PARENT="$(cd -- "$OUT_PARENT" && pwd -P)"
OUT="$OUT_PARENT/$OUT_BASE"
[[ ! -e "$OUT" ]] || fail "output path already exists; refusing to overwrite: $OUT"

WORK="$(mktemp -d "$OUT_PARENT/.pqtunnel-pki.XXXXXX")"
chmod 0700 "$WORK"
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT

mkdir -m 0700 "$WORK/ca" "$WORK/output"
mkdir -m 0700 "$WORK/output/ca-offline" "$WORK/output/gateway-pki" "$WORK/output/dialer-pki"

BIN="$WORK/pqtunnel-pki"
(
  GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$BIN" ./cmd/pqtunnel-pki
)

"$BIN" init --server-name "$SERVER_NAME" --out "$WORK/ca"
"$BIN" issue-client --ip "$CLIENT_IP" --out "$WORK/ca"

CLIENT_STEM="client-${CLIENT_IP//./_}"
CLIENT_CERT="$WORK/ca/$CLIENT_STEM.crt"
CLIENT_KEY="$WORK/ca/$CLIENT_STEM.key"
[[ -s "$CLIENT_CERT" && -s "$CLIENT_KEY" ]] || fail 'client certificate issuance did not create expected files.'

openssl verify -purpose sslserver -CAfile "$WORK/ca/ca.crt" "$WORK/ca/server.crt" >/dev/null
openssl verify -purpose sslclient -CAfile "$WORK/ca/ca.crt" "$CLIENT_CERT" >/dev/null

install -m 0644 "$WORK/ca/ca.crt" "$WORK/output/ca-offline/ca.crt"
install -m 0600 "$WORK/ca/ca.key" "$WORK/output/ca-offline/ca.key"

install -m 0644 "$WORK/ca/ca.crt" "$WORK/output/gateway-pki/ca.crt"
install -m 0644 "$WORK/ca/server.crt" "$WORK/output/gateway-pki/server.crt"
install -m 0600 "$WORK/ca/server.key" "$WORK/output/gateway-pki/server.key"

install -m 0644 "$WORK/ca/ca.crt" "$WORK/output/dialer-pki/ca.crt"
install -m 0644 "$CLIENT_CERT" "$WORK/output/dialer-pki/client.crt"
install -m 0600 "$CLIENT_KEY" "$WORK/output/dialer-pki/client.key"

cat > "$WORK/output/README.txt" <<'INFO'
PQTunnel staged PKI bundle

1. Copy only gateway-pki/ to the Gateway host.
2. Copy only dialer-pki/ to the Dialer host.
3. Keep ca-offline/ offline. Never copy ca.key to either endpoint.
4. Configure PQTUNNEL_SERVER_NAME to match the server certificate SAN.
5. Configure Gateway PQTUNNEL_PEER_NAME to match the client certificate CN.
6. The client certificate CN is the IPv4 value passed as --client-ip.
7. This bundle contains keys. Transfer it only over a trusted channel.
INFO
chmod 0600 "$WORK/output/README.txt"

mv -- "$WORK/output" "$OUT"
printf 'PKI bundle created: %s\n' "$OUT"
printf 'Gateway files: %s/gateway-pki\n' "$OUT"
printf 'Dialer files: %s/dialer-pki\n' "$OUT"
printf 'Offline CA files: %s/ca-offline\n' "$OUT"
printf '%s\n' 'No services, routes, sysctls, or firewall rules were changed.'
