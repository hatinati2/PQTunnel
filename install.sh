#!/usr/bin/env bash
# PQTunnel one-line entry point. Preflight is read-only; manager setup can print a new token once.
set -Eeuo pipefail

VERSION="v0.3.0-rc5"
REPO="hatinati2/PQTunnel"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${VERSION}"
SOURCE_RAW_BASE="$RAW_BASE"
RELEASE_BASE="https://github.com/${REPO}/releases/download/${VERSION}"
TMP_DIR=""
TOKEN=""
TOKEN_GENERATED=0

fail() { printf 'PQTunnel installer: %s\n' "$*" >&2; exit 1; }
cleanup() {
  local status=$?
  if (( TOKEN_GENERATED )); then
    if (( status == 0 )); then
      printf '\nPQTunnel manager installed and started. Save this newly generated token now; it is shown only once:\nPQTUNNEL_MANAGER_TOKEN=%s\n' "$TOKEN"
      printf 'Keep it private. It grants access to the management panel.\n'
    else
      printf '\nPQTunnel setup did not finish successfully. A token was generated and saved; keep it for recovery and do not share it:\nPQTUNNEL_MANAGER_TOKEN=%s\n' "$TOKEN" >&2
    fi
    unset TOKEN
  fi
  [[ -z "$TMP_DIR" ]] || rm -rf -- "$TMP_DIR" || status=1
  return "$status"
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is missing; no changes made."; }
prompt() {
  [[ -r /dev/tty ]] || fail 'interactive mode needs a terminal; pass --manager gateway|dialer or --preflight gateway|dialer|both.'
  read -r -p "$1" "$2" </dev/tty
}
usage() {
  cat <<'USAGE'
PQTunnel one-line installer (experimental release v0.3.0-rc5)

Usage:
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | sudo bash -s -- --manager dialer
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | sudo bash -s -- --manager-upgrade dialer
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | sudo bash -s -- --pair
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | sudo bash -s -- --site-to-site
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | bash -s -- --preflight dialer

Modes:
  --site-to-site / --full    Guided setup for both VPSes: Gateway over root SSH, Dialer locally,
                             mutual-TLS PKI, tunnel endpoints, selective-port routing, and both panels.
  --pair                     Legacy paired installer; requires SSH-key root access to Germany.
  --manager gateway|dialer   Install the optional local web manager only.
  --manager-upgrade gateway|dialer
                             Back up and upgrade a complete existing manager to a release with
                             the graphical setup wizard. Public/insecure listeners are moved to
                             loopback and the login token is rotated.
  --preflight gateway|dialer|both
                             Run read-only host checks; no files or network state are changed.
  --help                     Show this help.

--manager installs only the local web manager. --site-to-site/--full configures both the Iran Dialer and overseas Gateway, generates role-specific mutual-TLS certificates, installs both endpoint services and manager panels, and configures a bounded speed-test agent. --pair remains available as the legacy mode. It defaults to selected-port egress (TCP 80/443, UDP 53/123/443), not a full-tunnel VPN. It refuses to overwrite an existing tunnel endpoint. Services and network rules remain unactivated until the explicit APPLY-NETWORK confirmation. Provider firewalls/security groups are not modified. This project remains experimental; use out-of-band recovery access and do not use on production systems.
USAGE
}

MODE=""
ROLE=""
PUBLIC_IP=""
while (($#)); do
  case "$1" in
    --site-to-site|--full) MODE=site-to-site; shift ;;
    --pair) MODE=pair; shift ;;
    --manager) MODE=manager; shift; if (($#)) && [[ "$1" != --* ]]; then ROLE="$1"; shift; fi ;;
    --manager-upgrade) MODE=manager-upgrade; shift; if (($#)) && [[ "$1" != --* ]]; then ROLE="$1"; shift; fi ;;
    --node) MODE=node; shift; if (($#)) && [[ "$1" != --* ]]; then ROLE="$1"; shift; fi ;;
    --public-ip) PUBLIC_IP="${2:?missing public IPv4 address}"; shift 2 ;;
    --preflight) MODE=preflight; shift; if (($#)) && [[ "$1" != --* ]]; then ROLE="$1"; shift; fi ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1 (use --help)." ;;
  esac
done

if [[ -z "$MODE" ]]; then
  printf '\nPQTunnel %s — one-line setup\n' "$VERSION"
  printf '  1) Read-only preflight (no changes)\n'
  printf '  2) Install/start local web manager only\n'
  printf '  3) Guided full two-VPS setup (tunnel + both management panels, run on Iran)\n'
  prompt 'Choose [1-3]: ' CHOICE
  case "$CHOICE" in
    1) MODE=preflight; ROLE=both ;;
    2) MODE=manager ;;
    3) MODE=site-to-site ;;
    *) fail 'choose 1, 2 or 3.' ;;
  esac
fi

case "$MODE" in
  site-to-site)
    [[ "$EUID" -eq 0 ]] || fail 'two-VPS setup requires root; run on the Iran/Dialer VPS.'
    need curl; need mktemp; need bash
    TMP_DIR="$(mktemp -d)"
    curl --fail --silent --show-error --location "$SOURCE_RAW_BASE/scripts/pqtunnel-site-to-site-setup.sh" -o "$TMP_DIR/pqtunnel-site-to-site-setup.sh"
    bash -n "$TMP_DIR/pqtunnel-site-to-site-setup.sh"
    PQTUNNEL_SETUP_VERSION="$VERSION" bash "$TMP_DIR/pqtunnel-site-to-site-setup.sh"
    ;;
  pair)
    [[ "$EUID" -eq 0 ]] || fail 'paired installation requires root; rerun with sudo on the Iran/Dialer VPS.'
    need curl; need tar; need sha256sum; need awk; need uname; need grep
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
    [[ -x "$SOURCE_DIR/pqtunnel-pki" && -x "$SOURCE_DIR/pqtunnel-manager" ]] || fail 'release bundle is missing required Linux binaries.'
    # The release binary bundle stays version-pinned; fetch the small orchestration scripts from main.
    curl --fail --silent --show-error --location "$SOURCE_RAW_BASE/scripts/pqtunnel-oneclick-pair.sh" -o "$SOURCE_DIR/scripts/pqtunnel-oneclick-pair.sh"
    curl --fail --silent --show-error --location "$SOURCE_RAW_BASE/scripts/prepare-site-to-site-pki.sh" -o "$SOURCE_DIR/scripts/prepare-site-to-site-pki.sh"
    [[ -s "$SOURCE_DIR/scripts/pqtunnel-oneclick-pair.sh" && -s "$SOURCE_DIR/scripts/prepare-site-to-site-pki.sh" ]] || fail 'could not retrieve paired installer scripts.'
    chmod 0700 "$SOURCE_DIR/scripts/pqtunnel-oneclick-pair.sh" "$SOURCE_DIR/scripts/prepare-site-to-site-pki.sh"
    bash "$SOURCE_DIR/scripts/pqtunnel-oneclick-pair.sh" --source "$SOURCE_DIR" --version "$VERSION" --release-base "$RELEASE_BASE"
    ;;
  preflight)
    [[ -n "$ROLE" ]] || ROLE=both
    [[ "$ROLE" == both || "$ROLE" == gateway || "$ROLE" == dialer ]] || fail 'preflight role must be gateway, dialer or both.'
    need curl
    TMP_DIR="$(mktemp -d)"
    curl --fail --silent --show-error --location "$RAW_BASE/scripts/site-to-site-preflight.sh" -o "$TMP_DIR/site-to-site-preflight.sh"
    bash "$TMP_DIR/site-to-site-preflight.sh" --role "$ROLE"
    ;;
  manager|manager-upgrade|node)
    [[ "$EUID" -eq 0 ]] || fail 'manager installation requires root; rerun with sudo.'
    if [[ -z "$ROLE" ]]; then
      prompt 'Manager role on this server [gateway/dialer]: ' ROLE
    fi
    [[ "$ROLE" == gateway || "$ROLE" == dialer ]] || fail 'manager role must be gateway or dialer.'
    if [[ "$MODE" == node ]]; then
      [[ -n "$PUBLIC_IP" ]] || prompt 'Public IPv4 address for this VPS: ' PUBLIC_IP
      need python3
      python3 - "$PUBLIC_IP" <<'PY'
import ipaddress, sys
try:
    value = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("public IP must be a literal IPv4 address")
if value.version != 4 or not value.is_global:
    raise SystemExit("public IP must be a global IPv4 address")
PY
    fi
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
    CONFIG=/etc/default/pqtunnel-manager
    if [[ -x /usr/local/sbin/pqtunnel-manager && -f /etc/systemd/system/pqtunnel-manager.service && -f "$CONFIG" ]]; then
      EXISTING_ROLE="$(sed -n 's/^PQTUNNEL_MANAGER_ROLE=//p' "$CONFIG" | head -n1)"
      [[ "$EXISTING_ROLE" == "$ROLE" ]] || fail "existing manager role is '$EXISTING_ROLE', not '$ROLE'; refusing to change it."
      if [[ "$MODE" == node ]]; then
        bash "$SOURCE_DIR/scripts/install-manager.sh" --source "$SOURCE_DIR" --role "$ROLE" --upgrade --with-node-endpoint --public-http --public-host "$PUBLIC_IP"
      elif [[ "$MODE" == manager-upgrade ]]; then
        bash "$SOURCE_DIR/scripts/install-manager.sh" --source "$SOURCE_DIR" --role "$ROLE" --upgrade
      else
        printf 'Existing manager installation found; keeping its binary, unit, and role. Use --manager-upgrade %s to upgrade it.\n' "$ROLE"
      fi
    else
      [[ "$MODE" != manager-upgrade ]] || fail '--manager-upgrade requires a complete existing manager installation; use --manager for a first install.'
      bash "$SOURCE_DIR/scripts/install-manager.sh" --source "$SOURCE_DIR" --role "$ROLE"
    fi

    [[ -f "$CONFIG" ]] || fail "manager config not found at $CONFIG; service left stopped."
    # Generate a fresh 256-bit secret only when no token is already configured.
    # The EXIT trap prints a new token once, including if a later setup step fails.
    if ! grep -q '^PQTUNNEL_MANAGER_TOKEN=.' "$CONFIG"; then
      TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
      [[ "$TOKEN" =~ ^[0-9a-f]{64}$ ]] || fail 'could not generate a secure manager token; service left stopped.'
      sed -i "s/^PQTUNNEL_MANAGER_TOKEN=$/PQTUNNEL_MANAGER_TOKEN=$TOKEN/" "$CONFIG"
      grep -Fxq "PQTUNNEL_MANAGER_TOKEN=$TOKEN" "$CONFIG" || fail 'token could not be saved; service left stopped.'
      TOKEN_GENERATED=1
    fi
    chown root:root "$CONFIG"
    chmod 0600 "$CONFIG"

    if ! grep -q '^PQTUNNEL_MANAGER_TOKEN=.' "$CONFIG"; then
      fail "token configuration validation failed; service left stopped. Inspect $CONFIG locally."
    fi
    systemctl daemon-reload
    systemd-analyze verify /etc/systemd/system/pqtunnel-manager.service
    systemctl enable --now pqtunnel-manager
    systemctl --no-pager --full status pqtunnel-manager
    printf '\nManager token configuration is stored root-only in %s. Default access is loopback-only; use SSH forwarding for remote access.\n' "$CONFIG"
    printf 'This mode does not install or start the tunnel endpoint, and does not change routes, firewall, NAT, or forwarding.\n'
    ;;
esac
