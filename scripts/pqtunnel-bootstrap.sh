#!/usr/bin/env bash
# PQTunnel one-line bootstrap. Default mode is strictly read-only preflight.
set -Eeuo pipefail

REPO_API="https://api.github.com/repos/hatinati2/PQTunnel/tarball/main"
RAW_BASE="https://raw.githubusercontent.com/hatinati2/PQTunnel/main"
MODE="${1:-preflight}"
if (($#)); then shift; fi

usage() {
  cat <<'USAGE'
PQTunnel one-line bootstrap

Read-only (default):
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/scripts/pqtunnel-bootstrap.sh | bash

Check a specific role:
  ... | bash -s -- preflight --role dialer
  ... | bash -s -- preflight --role gateway

Install gateway/listener files (existing PKI must already be staged on this host):
  ... | sudo bash -s -- install-server --pki-dir /root/pqtunnel-pki
  ... | sudo bash -s -- install-server --pki-dir /root/pqtunnel-pki --start

The --start option starts/enables pqtunneld. Network routes, forwarding, firewall/NAT,
and provider firewall rules are deliberately separate and are never configured here.
The installer refuses an existing installation and does not install OS packages.
USAGE
}

get_source() {
  if [[ -f ./go.mod && -f ./scripts/install-server.sh ]]; then
    SOURCE_DIR="$(pwd)"
    return
  fi
  command -v curl >/dev/null || { echo 'curl is required; no changes made.' >&2; exit 1; }
  command -v tar >/dev/null || { echo 'tar is required; no changes made.' >&2; exit 1; }
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
        --role) [[ $# -ge 2 ]] || { echo 'missing value for --role' >&2; exit 2; }; ROLE=$2; shift 2 ;;
        --endpoint) [[ $# -ge 2 ]] || { echo 'missing value for --endpoint' >&2; exit 2; }; ENDPOINT=$2; shift 2 ;;
        *) echo "unknown preflight option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done
    if [[ -f ./scripts/site-to-site-preflight.sh ]]; then
      exec bash ./scripts/site-to-site-preflight.sh --role "$ROLE" ${ENDPOINT:+--endpoint "$ENDPOINT"}
    fi
    command -v curl >/dev/null || { echo 'curl is required to fetch the read-only checker.' >&2; exit 1; }
    TMP_CHECK="$(mktemp)"
    trap 'rm -f "$TMP_CHECK"' EXIT
    curl --fail --silent --show-error --location "$RAW_BASE/scripts/site-to-site-preflight.sh" -o "$TMP_CHECK"
    if [[ -n "$ENDPOINT" ]]; then exec bash "$TMP_CHECK" --role "$ROLE" --endpoint "$ENDPOINT"; else exec bash "$TMP_CHECK" --role "$ROLE"; fi
    ;;
  install-server)
    PKI_DIR=
    START=0
    while (($#)); do
      case "$1" in
        --pki-dir) [[ $# -ge 2 ]] || { echo 'missing value for --pki-dir' >&2; exit 2; }; PKI_DIR=$2; shift 2 ;;
        --start) START=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown install option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done
    [[ $(id -u) -eq 0 ]] || { echo 'install-server must run as root (sudo). No changes made.' >&2; exit 1; }
    [[ -n "$PKI_DIR" && -d "$PKI_DIR" ]] || { echo 'Provide --pki-dir pointing to a directory containing server.crt, server.key, and ca.crt.' >&2; exit 2; }
    for file in server.crt server.key ca.crt; do
      [[ -s "$PKI_DIR/$file" ]] || { echo "Missing $PKI_DIR/$file. No changes made." >&2; exit 1; }
    done
    for cmd in curl tar openssl systemctl ip; do
      command -v "$cmd" >/dev/null || { echo "Required command missing: $cmd. No changes made; no packages are installed automatically." >&2; exit 1; }
    done
    if [[ -e /usr/local/sbin/pqtunneld || -e /etc/systemd/system/pqtunneld.service || -e /etc/pqtunnel/pki/server.key || -e /etc/default/pqtunneld ]]; then
      echo 'Existing PQTunnel server artifact/config detected. Refusing to overwrite; no changes made.' >&2
      exit 1
    fi
    echo 'Running read-only checks before installation...'
    bash "$RAW_BASE/scripts/site-to-site-preflight.sh" 2>/dev/null && true
    get_source
    INSTALL_ARGS=(--source "$SOURCE_DIR" --pki "$PKI_DIR")
    if (( START )); then INSTALL_ARGS+=(--enable); fi
    bash "$SOURCE_DIR/scripts/install-server.sh" "${INSTALL_ARGS[@]}"
    echo 'NOTE: this installs only the server daemon and systemd unit.'
    echo 'It does NOT apply policy routes, nftables, forwarding, NAT, or provider firewall changes.'
    if (( START )); then
      echo 'The daemon was explicitly started. Review the logs and run the documented network plan only after the host preflight.'
    else
      echo 'The daemon is installed but remains stopped/disabled. Review /etc/default/pqtunneld before starting.'
    fi
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    usage >&2
    exit 2
    ;;
esac
