#!/usr/bin/env bash
# PQTunnel one-line entry point. Preflight is read-only; manager setup is automated.
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
                             install the manager, generate a strong token, configure it,
                             validate the unit, then enable and start the local-only manager.
  --preflight gateway|dialer|both
                             Run read-only host checks; no files or network state are changed.
  --help                     Show this help.

Manager setup does NOT configure or start the tunnel and does not change routes, firewall,
NAT, or forwarding. The web manager binds only to 127.0.0.1:9091; use SSH forwarding remotely.
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
  printf '  2) Install, securely configure, and start local web manager\n'
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
    need curl; need tar; need sha256sum; need awk; need uname; need od; need tr; need systemctl; need systemd-analyze; need sed; need grep
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

    # Generate a fresh 256-bit web token locally; never print it to stdout.
    TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
    [[ "${#TOKEN}" -eq 64 ]] || fail 'could not generate a secure manager token; service left stopped.'
    CONFIG=/etc/default/pqtunnel-manager
    [[ -f "$CONFIG" ]] || fail "manager config not found at $CONFIG; service left stopped."
    if grep -q '^PQTUNNEL_MANAGER_TOKEN=.' "$CONFIG"; then
      fail "manager token is already configured in $CONFIG; refusing to replace it automatically."
    fi
    sed -i "s/^PQTUNNEL_MANAGER_TOKEN=$/PQTUNNEL_MANAGER_TOKEN=$TOKEN/" "$CONFIG"
    chown root:root "$CONFIG"
    chmod 0600 "$CONFIG"
    unset TOKEN

    if ! grep -q '^PQTUNNEL_MANAGER_TOKEN=[[:xdigit:]]\{64\}$' "$CONFIG"; then
      fail "token configuration validation failed; service left stopped. Inspect $CONFIG locally."
    fi
    systemctl daemon-reload
    systemd-analyze verify /etc/systemd/system/pqtunnel-manager.service
    systemctl enable --now pqtunnel-manager
    systemctl --no-pager --full status pqtunnel-manager
    printf '\nPQTunnel manager installed and started. Its token is stored root-only in %s.\n' "$CONFIG"
    printf 'The token was not printed. Keep port 9091 private; remote access must use SSH local forwarding.\n'
    printf 'No tunnel service, route, firewall, NAT, or forwarding settings were changed.\n'
    ;;
esac
