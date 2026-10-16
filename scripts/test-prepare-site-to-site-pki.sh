#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

BUNDLE="$TMP/pqtunnel-pki-bundle"
bash scripts/prepare-site-to-site-pki.sh \
  --server-name 198.51.100.10 \
  --client-ip 10.66.0.2 \
  --out "$BUNDLE"

for path in \
  "$BUNDLE/ca-offline/ca.crt" \
  "$BUNDLE/ca-offline/ca.key" \
  "$BUNDLE/gateway-pki/ca.crt" \
  "$BUNDLE/gateway-pki/server.crt" \
  "$BUNDLE/gateway-pki/server.key" \
  "$BUNDLE/dialer-pki/ca.crt" \
  "$BUNDLE/dialer-pki/client.crt" \
  "$BUNDLE/dialer-pki/client.key"
do
  [[ -s "$path" ]] || { echo "Missing generated file: $path" >&2; exit 1; }
done

[[ ! -e "$BUNDLE/gateway-pki/ca.key" ]]
[[ ! -e "$BUNDLE/dialer-pki/ca.key" ]]
[[ "$(stat -c '%a' "$BUNDLE/ca-offline/ca.key")" == 600 ]]
[[ "$(stat -c '%a' "$BUNDLE/gateway-pki/server.key")" == 600 ]]
[[ "$(stat -c '%a' "$BUNDLE/dialer-pki/client.key")" == 600 ]]

openssl verify -purpose sslserver \
  -CAfile "$BUNDLE/gateway-pki/ca.crt" \
  "$BUNDLE/gateway-pki/server.crt" >/dev/null

openssl verify -purpose sslclient \
  -CAfile "$BUNDLE/dialer-pki/ca.crt" \
  "$BUNDLE/dialer-pki/client.crt" >/dev/null

SUBJECT="$(openssl x509 -in "$BUNDLE/dialer-pki/client.crt" -noout -subject -nameopt RFC2253)"
[[ "$SUBJECT" == *"CN=10.66.0.2"* ]] || {
  echo "Unexpected client certificate identity: $SUBJECT" >&2
  exit 1
}

if bash scripts/prepare-site-to-site-pki.sh \
  --server-name 198.51.100.10 \
  --client-ip 10.66.0.2 \
  --out "$BUNDLE" >/dev/null 2>&1; then
  echo "PKI generator unexpectedly overwrote an existing output directory" >&2
  exit 1
fi

echo "PASS: staged PKI bundle has valid role-specific certificates and private-key permissions."
