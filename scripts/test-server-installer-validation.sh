#!/usr/bin/env bash
# Regression tests for server installer PKI validation.
# All fixtures live in a temporary directory; expected failures occur before installation.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT/scripts/install-server.sh"
command -v openssl >/dev/null 2>&1 || { echo 'FAIL: openssl is required' >&2; exit 2; }
command -v sudo >/dev/null 2>&1 || { echo 'FAIL: sudo is required' >&2; exit 2; }

TMP="$(mktemp -d -t pqtunnel-server-installer-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
SOURCE="$TMP/source"
PKI="$TMP/pki"
mkdir -p "$SOURCE/deploy/systemd" "$PKI"
printf '[Unit]\nDescription=Test fixture\n' > "$SOURCE/deploy/systemd/pqtunneld.service"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj '/CN=PQTunnel test CA' -keyout "$PKI/ca.key" -out "$PKI/ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=gateway.test' \
  -keyout "$PKI/server.key" -out "$TMP/server.csr" >/dev/null 2>&1
cat > "$TMP/server.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:gateway.test
EXT
openssl x509 -req -in "$TMP/server.csr" -CA "$PKI/ca.crt" -CAkey "$PKI/ca.key" \
  -CAcreateserial -days 2 -extfile "$TMP/server.ext" -out "$PKI/server.crt" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/wrong.key" >/dev/null 2>&1

run_expect_failure() {
  local label="$1" expected="$2" log="$TMP/run.log" rc
  if sudo bash "$INSTALLER" --source "$SOURCE" --pki "$PKI" >"$log" 2>&1; then
    echo "FAIL: installer unexpectedly succeeded for $label" >&2
    cat "$log" >&2
    exit 1
  else
    rc=$?
  fi
  if ! grep -Fq "$expected" "$log"; then
    echo "FAIL: installer rejected $label for an unexpected reason (exit $rc)" >&2
    cat "$log" >&2
    exit 1
  fi
  echo "PASS: installer rejects $label before installation."
}

# The CA signing key must never be staged in the endpoint PKI directory.
run_expect_failure 'an endpoint PKI directory containing ca.key' 'Keep the CA private key offline'

rm -f "$PKI/ca.key" "$PKI/ca.srl"
cp "$PKI/server.key" "$TMP/correct.key"
cp "$TMP/wrong.key" "$PKI/server.key"
run_expect_failure 'a certificate/private-key mismatch' 'does not match server.crt'

cp "$TMP/correct.key" "$PKI/server.key"
printf 'not a certificate\n' > "$PKI/server.crt"
run_expect_failure 'a malformed server certificate' 'not a valid PEM certificate'

echo 'PASS: server installer PKI validation regression tests completed.'
