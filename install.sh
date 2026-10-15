#!/usr/bin/env bash
# PQTunnel one-line entry point. Default menu is interactive; preflight is read-only.
set -Eeuo pipefail

VERSION="v0.3.0-rc3"
REPO="hatinati2/PQTunnel"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${VERSION}"
RELEASE_BASE="https://github.com/${REPO}/releases/download/${VERSION}"
TMP_DIR=""

fail() { printf 'PQTunnel installer: %s\n' "$*" >&2; exit 1; }
cleanup() { [[ -z "$TMP_DIR" ]] || rm -rf -- "$TMP_DIR"; }
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is missing; no changes made."; }
prompt() {
  [[ -r /dev/tty ]] || fail 'interactive mode needs a terminal; pass --manager gateway|dialer or --preflight gateway|dialer|both.'
  read -r -p "$1" "$2" </dev/tty
}
usage() {
  cat <<'USAGE'
PQTunnel one-line installer (experimental release v0.3.0-rc3)

Usage:
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | sudo bash -s -- --manager dialer
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | bash -s -- --preflight dialer

Modes:
  --manager gateway|dialer   Download and checksum-verify the Linux release bundle,
                             then install the optional standalone manager. It remains stopped.
  --preflight gateway|dialer|both
                             Run read-only host checks; no files or network state are changed.
  --help                     Show this help.

This does NOT configure or start the tunnel. Tunnel setup needs reviewed role-specific
certificates and environment files. Existing firewall/routing state is never bypassed.
USAGE
}

MODE=""
ROLE=""
while (($#)); do
  case "$1" in
    --manager) MODE=manager; shift; if (($#)) && [[ "$1" != --* ]]; then ROLE="$1"; shift; fi ;;
    --preflight) MODE=preflight; shift; if (($#)) && [[ "$1" != --* ]]; then ROLE="$1"; shift; fi ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1 (use --help)." ;;
  esac
done

if [[ -z "$MODE" ]]; then
  printf '\nPQTunnel %s — one-line setup\n' "$VERSION"
  printf '  1) Read-only preflight (no changes)\n'
  printf '  2) Install standalone web manager (does not start it)\n'
  prompt 'Choose [1-2]: ' CHOICE
  case "$CHOICE" in
    1) MODE=preflight; ROLE=both ;;
    2) MODE=manager ;;
    *) fail 'choose 1 or 2.' ;;
  esac
fi

case "$MODE" in
  preflight)
    [[ -n "$ROLE" ]] || ROLE=both
    [[ "$ROLE" == both || "$ROLE" == gateway || "$ROLE" == dialer ]] || fail 'preflight role must be gateway, dialer or both.'
    need curl
    TMP_DIR="$(mktemp -d)"
    curl --fail --silent --show-error --location "$RAW_BASE/scripts/site-to-site-preflight.sh" -o "$TMP_DIR/site-to-site-preflight.sh"
    bash "$TMP_DIR/site-to-site-preflight.sh" --role "$ROLE"
    ;;
  manager)
    [[ "$EUID" -eq 0 ]] || fail 'manager installation requires root; rerun with sudo.'
    if [[ -z "$ROLE" ]]; then
      prompt 'Manager role on this server [gateway/dialer]: ' ROLE
    fi
    [[ "$ROLE" == gateway || "$ROLE" == dialer ]] || fail 'manager role must be gateway or dialer.'
    need curl; need tar; need sha256sum; need awk; need uname
    case "$(uname -m)" in
      x86_64|amd64) ARCH=amd64 ;;
      aarch64|arm64) ARCH=arm64 ;;
      *) fail "unsupported architecture: $(uname -m); supported Linux architectures: amd64, arm64." ;;
    esac
    ASSET="PQTunnel-${VERSION}-linux-${ARCH}.tar.gz"
    TMP_DIR="$(mktemp -d)"
    curl --fail --silent --show-error --location "$RELEASE_BASE/$ASSET" -o "$TMP_DIR/$ASSET"
    curl --fail --silent --show-error --location "$RELEASE_BASE/SHA256SUMS" -o "$TMP_DIR/SHA256SUMS"
    grep -Fq "  ./$ASSET" "$TMP_DIR/SHA256SUMS" || fail "release checksum file does not list $ASSET; refusing to install."
    (cd "$TMP_DIR" && grep -F "  ./$ASSET" SHA256SUMS | sha256sum --check -)
    tar -xzf "$TMP_DIR/$ASSET" -C "$TMP_DIR"
    SOURCE_DIR="$TMP_DIR/PQTunnel-${VERSION}-linux-${ARCH}"
    [[ -x "$SOURCE_DIR/pqtunnel-manager" && -f "$SOURCE_DIR/deploy/systemd/pqtunnel-manager.service" ]] || fail 'release bundle is missing manager binary or systemd unit.'
    bash "$SOURCE_DIR/scripts/install-manager.sh" --source "$SOURCE_DIR" --role "$ROLE"
    printf '\nManager binary installed; service is still stopped.\n'
    printf 'Next: set a random token of at least 32 bytes in /etc/default/pqtunnel-manager, review it, then start deliberately.\n'
    printf 'Remote access must use SSH forwarding; do not expose port 9091 publicly.\n'
    ;;
esac
