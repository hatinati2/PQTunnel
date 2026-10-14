#!/usr/bin/env bash
# PQTunnel one-line bootstrap. Default mode is read-only preflight.
set -Eeuo pipefail

REPO_API="https://api.github.com/repos/hatinati2/PQTunnel/tarball/main"
RAW_BASE="https://raw.githubusercontent.com/hatinati2/PQTunnel/main"
MODE="${1:-preflight}"
if (($#)); then shift; fi

usage() {
  cat <<'USAGE'
PQTunnel one-line bootstrap

Read-only preflight (default mode):
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/scripts/pqtunnel-bootstrap.sh | bash
  ... | bash -s -- preflight --role dialer
  ... | bash -s -- preflight --role gateway

Install the gateway daemon, requiring pre-staged PKI and a reviewed plain KEY=VALUE file:
  ... | sudo bash -s -- install-server --pki-dir /root/pqtunnel-pki --server-env-file /root/pqtunneld.env
  Add --start to enable and start pqtunneld after settings are installed.

--start starts the daemon only. Policy routes, forwarding, firewall/NAT, and provider
firewall rules are deliberately separate and are never configured by this bootstrap.
Existing installations are refused; OS packages are not installed automatically.
USAGE
}
fail() { echo "pqtunnel-bootstrap: $*" >&2; exit 1; }

get_source() {
  if [[ -f ./go.mod && -f ./scripts/install-server.sh ]]; then
    SOURCE_DIR="$(pwd)"
    return
  fi
  command -v curl >/dev/null || fail 'curl is required; no changes made.'
  command -v tar >/dev/null || fail 'tar is required; no changes made.'
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  mkdir -p "$TMP_DIR/src"
  curl --fail --silent --show-error --location "$REPO_API" -o "$TMP_DIR/repo.tar.gz"
  tar -xzf "$TMP_DIR/repo.tar.gz" --strip-components=1 -C "$TMP_DIR/src"
  SOURCE_DIR="$TMP_DIR/src"
}

case "$MODE" in
  -h|--help|help) usage; exit 0 ;;
  preflight)
    ROLE=both
    ENDPOINT=
    while (($#)); do
      case "$1" in
        --role) [[ $# -ge 2 ]] || fail 'missing value for --role'; ROLE=$2; shift 2 ;;
        --endpoint) [[ $# -ge 2 ]] || fail 'missing value for --endpoint'; ENDPOINT=$2; shift 2 ;;
        *) echo "unknown preflight option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done
    if [[ -f ./scripts/site-to-site-preflight.sh ]]; then
      if [[ -n "$ENDPOINT" ]]; then
        if bash ./scripts/site-to-site-preflight.sh --role "$ROLE" --endpoint "$ENDPOINT"; then exit 0; else exit $?; fi
      else
        if bash ./scripts/site-to-site-preflight.sh --role "$ROLE"; then exit 0; else exit $?; fi
      fi
    fi
    command -v curl >/dev/null || fail 'curl is required to fetch the read-only checker.'
    TMP_CHECK="$(mktemp)"
    trap 'rm -f "$TMP_CHECK"' EXIT
    curl --fail --silent --show-error --location "$RAW_BASE/scripts/site-to-site-preflight.sh" -o "$TMP_CHECK"
    if [[ -n "$ENDPOINT" ]]; then
      if bash "$TMP_CHECK" --role "$ROLE" --endpoint "$ENDPOINT"; then exit 0; else exit $?; fi
    else
      if bash "$TMP_CHECK" --role "$ROLE"; then exit 0; else exit $?; fi
    fi
    ;;
  install-server)
    PKI_DIR=
    SERVER_ENV=
    START=0
    while (($#)); do
      case "$1" in
        --pki-dir) [[ $# -ge 2 ]] || fail 'missing value for --pki-dir'; PKI_DIR=$2; shift 2 ;;
        --server-env-file) [[ $# -ge 2 ]] || fail 'missing value for --server-env-file'; SERVER_ENV=$2; shift 2 ;;
        --start) START=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown install option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done
    [[ "$(id -u)" == 0 ]] || fail 'install-server mode requires root (sudo). No changes made.'
    [[ -n "$PKI_DIR" && -d "$PKI_DIR" ]] || fail '--pki-dir must point to a directory containing server.crt, server.key and ca.crt.'
    [[ -n "$SERVER_ENV" && -f "$SERVER_ENV" && -r "$SERVER_ENV" ]] || fail '--server-env-file is required and must be readable; no changes made.'
    for cmd in curl tar openssl systemctl ip stat grep awk; do
      command -v "$cmd" >/dev/null || fail "required command missing: $cmd; no packages are installed automatically."
    done
    for file in server.crt server.key ca.crt; do
      [[ -s "$PKI_DIR/$file" ]] || fail "missing $PKI_DIR/$file; no changes made."
    done
    [[ ! -e "$PKI_DIR/ca.key" ]] || fail 'ca.key must remain offline and must not be installed on the server.'
    ENV_MODE="$(stat -c '%a' "$SERVER_ENV" 2>/dev/null || printf 777)"
    ENV_PERM=$((8#$ENV_MODE))
    (( (ENV_PERM & 0022) == 0 )) || fail 'server env file must not be group/world-writable.'
    # Accept only plain systemd EnvironmentFile KEY=VALUE lines. Never source/evaluate it.
    if grep -Ev '^[[:space:]]*(#.*|[A-Z_][A-Z0-9_]*=[^[:space:]]*)?$' "$SERVER_ENV" >/dev/null; then
      fail 'server env file must contain only comments/blank lines or plain KEY=VALUE entries.'
    fi
    if ! awk -F= '/^[[:space:]]*[A-Z_][A-Z0-9_]*=/ { key=$1; gsub(/[[:space:]]/, "", key); if (seen[key]++) exit 1 }' "$SERVER_ENV"; then
      fail 'server env file contains duplicate keys.'
    fi
    for required in \
      'PQTUNNEL_TLS_CERT=/etc/pqtunnel/pki/server.crt' \
      'PQTUNNEL_TLS_KEY=/etc/pqtunnel/pki/server.key' \
      'PQTUNNEL_CLIENT_CA=/etc/pqtunnel/pki/ca.crt' \
      'PQTUNNEL_MAX_CLIENTS=1'; do
      grep -Fxq "$required" "$SERVER_ENV" || fail "required site-to-site setting missing: $required"
    done
    grep -Eq '^PQTUNNEL_PEER_PREFIXES=.+$' "$SERVER_ENV" || fail 'PQTUNNEL_PEER_PREFIXES must be set.'
    grep -Eq '^PQTUNNEL_LOCAL_PREFIXES=.+$' "$SERVER_ENV" || fail 'PQTUNNEL_LOCAL_PREFIXES must be set.'
    grep -Eq '^PQTUNNEL_PEER_NAME=.+$' "$SERVER_ENV" || fail 'PQTUNNEL_PEER_NAME must be set.'
    for artifact in /usr/local/sbin/pqtunneld /etc/systemd/system/pqtunneld.service /etc/pqtunnel/pki/server.key /etc/default/pqtunneld; do
      [[ ! -e "$artifact" ]] || fail "existing server artifact/config detected at $artifact; refusing to overwrite."
    done
    get_source
    echo 'Read-only host preflight before installation:'
    bash "$SOURCE_DIR/scripts/site-to-site-preflight.sh" --role gateway
    bash "$SOURCE_DIR/scripts/install-server.sh" --source "$SOURCE_DIR" --pki "$PKI_DIR"
    install -o root -g root -m 0640 "$SERVER_ENV" /etc/default/pqtunneld
    if (( START )); then
      systemctl enable --now pqtunneld
      echo 'pqtunneld was enabled and started with the supplied site-to-site environment.'
    else
      echo 'Daemon installed; it remains stopped/disabled with settings staged in /etc/default/pqtunneld.'
    fi
    echo 'No policy routes, nftables rules, forwarding, NAT, or provider firewall changes were applied.'
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    usage >&2
    exit 2
    ;;
esac
