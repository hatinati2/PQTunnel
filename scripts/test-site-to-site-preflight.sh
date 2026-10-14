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
grep -q 'curl -fsSL .* install-server .*--start --apply-network' <<< "$BOOTSTRAP_HELP"
grep -q 'curl -fsSL .* install-client .*--start' <<< "$BOOTSTRAP_HELP"
grep -q 'PQTUNNEL_REF' <<< "$BOOTSTRAP_HELP"
grep -q 'REPLACE_WITH_REVIEWED_40_CHAR_SHA' <<< "$BOOTSTRAP_HELP"
if PQTUNNEL_REF=main bash "$ROOT/scripts/pqtunnel-bootstrap.sh" install-server >/dev/null 2>&1; then
  echo "install-server unexpectedly accepted a mutable source ref" >&2
  exit 1
fi
if PQTUNNEL_REF=main bash "$ROOT/scripts/pqtunnel-bootstrap.sh" install-client >/dev/null 2>&1; then
  echo "install-client unexpectedly accepted a mutable source ref" >&2
  exit 1
fi
bash "$ROOT/scripts/pqtunnel-bootstrap.sh" check-config --kind gateway --app-env "$ROOT/scripts/pqtunneld.site-to-site.env.example" --network-env "$ROOT/scripts/site-to-site-gateway.env.example"
bash "$ROOT/scripts/pqtunnel-bootstrap.sh" check-config --kind dialer --app-env "$ROOT/scripts/pqtunnel-client.env.example" --network-env "$ROOT/scripts/site-to-site.env.example"

# A shell-expression payload must be rejected as data, never evaluated.
TMP_CONFIG_DIR="$(mktemp -d)"
FAKE_BIN_DIR=""
trap 'rm -rf "$TMP_CONFIG_DIR" /tmp/pqtunnel-config-pwned; [[ -z "$FAKE_BIN_DIR" ]] || rm -rf "$FAKE_BIN_DIR"' EXIT
cp "$ROOT/scripts/pqtunneld.site-to-site.env.example" "$TMP_CONFIG_DIR/gateway.env"
sed -i 's|^PQTUNNEL_PEER_NAME=.*|PQTUNNEL_PEER_NAME=$(touch /tmp/pqtunnel-config-pwned)|' "$TMP_CONFIG_DIR/gateway.env"
if bash "$ROOT/scripts/pqtunnel-bootstrap.sh" check-config --kind gateway --app-env "$TMP_CONFIG_DIR/gateway.env" --network-env "$ROOT/scripts/site-to-site-gateway.env.example" >/dev/null 2>&1; then
  echo "unsafe shell expression was unexpectedly accepted" >&2
  exit 1
fi
if [[ -e /tmp/pqtunnel-config-pwned ]]; then
  echo "configuration validator evaluated a shell expression" >&2
  exit 1
fi

HELP="$(bash "$PREFLIGHT" --help)"
grep -q 'READ-ONLY' <<< "$HELP"
grep -q 'check_certificate_bundle' "$PREFLIGHT"
grep -q 'nftables query failed' "$PREFLIGHT"
grep -q 'iptables-save query failed' "$PREFLIGHT"
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
if grep -Eq '^[[:space:]]*(sysctl[[:space:]]+-w|nft[[:space:]]+-f|ip[[:space:]]+link[[:space:]]+(set|add|del)|systemctl[[:space:]]+(start|stop|restart|enable|disable)|iptables-restore[[:space:]]|iptables[[:space:]]+-)' "$PREFLIGHT"; then
  echo "Potential network-changing command detected in read-only preflight script" >&2
  exit 1
fi
printf '%s\n' "$OUTPUT"

# Simulate existing firewall rules without modifying runner networking.
# These wrappers return only read-only fixture data to the preflight.
FAKE_BIN_DIR="$(mktemp -d)"
cat >"$FAKE_BIN_DIR/nft" <<'NFT_WRAPPER'
#!/usr/bin/env bash
set -eu
case "$*" in
  "list tables")
    printf '%s\n' 'table ip filter' 'table ip raw' 'table ip mangle'
    ;;
  "list ruleset")
    cat <<'RULESET'
table ip raw {
  chain OUTPUT { type filter hook output priority raw; policy accept;
    tcp sport 45420-45547 notrack
  }
}
table ip mangle {
  chain OUTPUT { type route hook output priority mangle; policy accept;
    meta mark set 20561
  }
}
RULESET
    ;;
  *) exit 2 ;;
esac
NFT_WRAPPER
cat >"$FAKE_BIN_DIR/iptables-save" <<'IPTABLES_WRAPPER'
#!/usr/bin/env bash
cat <<'RULES'
*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp -m tcp --sport 45420:45547 -j NOTRACK
COMMIT
*mangle
:OUTPUT ACCEPT [0:0]
-A OUTPUT -j MARK --set-mark 20561
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT
RULES
IPTABLES_WRAPPER
cat >"$FAKE_BIN_DIR/ip6tables-save" <<'IP6TABLES_WRAPPER'
#!/usr/bin/env bash
printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' ':FORWARD ACCEPT [0:0]' ':OUTPUT ACCEPT [0:0]' 'COMMIT'
IP6TABLES_WRAPPER
chmod 0700 "$FAKE_BIN_DIR/nft" "$FAKE_BIN_DIR/iptables-save" "$FAKE_BIN_DIR/ip6tables-save"
DIAGNOSTIC_OUTPUT="$(PATH="$FAKE_BIN_DIR:$PATH" bash "$PREFLIGHT" --role both)"
grep -q 'Existing raw-table NOTRACK rules detected' <<< "$DIAGNOSTIC_OUTPUT"
grep -q 'Existing packet-marking rules detected' <<< "$DIAGNOSTIC_OUTPUT"
grep -q '^SUMMARY pass=' <<< "$DIAGNOSTIC_OUTPUT"
echo 'PASS: preflight reports simulated NOTRACK and packet-marking hazards.'
echo 'PASS: read-only preflight entry points and non-mutating guard verified.'
