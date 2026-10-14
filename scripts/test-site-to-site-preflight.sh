#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFLIGHT="$ROOT/scripts/site-to-site-preflight.sh"

[[ -f "$PREFLIGHT" ]] || { echo "missing preflight script" >&2; exit 1; }
bash -n "$PREFLIGHT"
bash -n "$ROOT/scripts/pqtunnel-bootstrap.sh"
BOOTSTRAP_HELP="$(bash "$ROOT/scripts/pqtunnel-bootstrap.sh" --help)"
grep -q 'install-server' <<< "$BOOTSTRAP_HELP"
grep -q 'install-client' <<< "$BOOTSTRAP_HELP"
HELP="$(bash "$PREFLIGHT" --help)"
grep -q 'READ-ONLY' <<< "$HELP"
if bash "$PREFLIGHT" --role invalid >/dev/null 2>&1; then
  echo "invalid role was unexpectedly accepted" >&2
  exit 1
fi
if bash "$PREFLIGHT" --unknown >/dev/null 2>&1; then
  echo "unknown option was unexpectedly accepted" >&2
  exit 1
fi

# Run against the disposable CI runner. The test checks a stable contract,
# not whether runner state matches any production VPS.
OUTPUT="$(bash "$PREFLIGHT" --role both)"
grep -q 'READ-ONLY GUARANTEE:' <<< "$OUTPUT"
BOOT_OUTPUT="$(bash "$ROOT/scripts/pqtunnel-bootstrap.sh" preflight --role both)"
grep -q 'READ-ONLY GUARANTEE:' <<< "$BOOT_OUTPUT"
grep -q '^SUMMARY pass=' <<< "$OUTPUT"
if grep -Eq 'sysctl -w|nft -f|ip link (set|add|del)|systemctl (start|stop|restart|enable|disable)|iptables(-restore)?[[:space:]]' "$PREFLIGHT"; then
  echo "Potential network-changing command detected in read-only preflight script" >&2
  exit 1
fi
printf '%s\n' "$OUTPUT"
echo 'PASS: read-only preflight entry points and non-mutating guard verified.'
