#!/usr/bin/env bash
# PQTunnel bootstrap: read-only preflight by default; operational modes are explicit.
set -Eeuo pipefail

MODE=preflight
if (($#)); then MODE="$1"; shift; fi
PQTUNNEL_REF="${PQTUNNEL_REF:-main}"
if [[ ! "$PQTUNNEL_REF" =~ ^[A-Za-z0-9._/-]+$ || "$PQTUNNEL_REF" == *..* ]]; then
  printf 'pqtunnel-bootstrap: invalid PQTUNNEL_REF; use main for read-only checks or a reviewed commit SHA for installation.\n' >&2
  exit 2
fi
RAW_BASE="https://raw.githubusercontent.com/hatinati2/PQTunnel/${PQTUNNEL_REF}"
API_TARBALL="https://api.github.com/repos/hatinati2/PQTunnel/tarball/${PQTUNNEL_REF}"
WORK_DIR=

fail() { printf 'pqtunnel-bootstrap: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
cleanup() { [[ -z "$WORK_DIR" ]] || rm -rf "$WORK_DIR"; }
trap cleanup EXIT

usage() {
  cat <<'USAGE'
PQTunnel bootstrap. The default "preflight" mode is read-only.

  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/scripts/pqtunnel-bootstrap.sh | bash
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/scripts/pqtunnel-bootstrap.sh | bash -s -- preflight --role gateway
  bash scripts/pqtunnel-bootstrap.sh check-config --kind gateway --app-env APP.env --network-env NETWORK.env

Install modes require pre-created certificates and manually reviewed config files.
One-line examples below change services/network state; use them only on a disposable lab host
after review, and replace every example path with staged files on the destination host.

  # Use a reviewed 40-character commit SHA, replacing the placeholder below:
  REF=REPLACE_WITH_REVIEWED_40_CHAR_SHA; curl -fsSL "https://raw.githubusercontent.com/hatinati2/PQTunnel/${REF}/scripts/pqtunnel-bootstrap.sh" | sudo env PQTUNNEL_REF="$REF" bash -s -- install-server --pki-dir /root/pqtunnel-input/germany-pki --server-env-file /root/pqtunnel-input/germany-app.env --network-env-file /root/pqtunnel-input/germany-network.env --start --apply-network

  REF=REPLACE_WITH_REVIEWED_40_CHAR_SHA; curl -fsSL "https://raw.githubusercontent.com/hatinati2/PQTunnel/${REF}/scripts/pqtunnel-bootstrap.sh" | sudo env PQTUNNEL_REF="$REF" bash -s -- install-client --pki-dir /root/pqtunnel-input/iran-pki --client-env-file /root/pqtunnel-input/iran-app.env --network-env-file /root/pqtunnel-input/iran-network.env --start

Install modes require PQTUNNEL_REF to be a reviewed 40-character commit SHA. The bootstrap
script and source tarball both use that same ref; mutable branches such as main are refused.
--start is an explicit operational action. Gateway network apply requires the separate
--apply-network flag. Starting the dialer unit applies its network helper. This project is
experimental: retain console/out-of-band access, review every file, and test in a lab first.
No OS packages are installed automatically; Go 1.24+ and role-specific certificates/configs
must be staged first. Existing installations are not overwritten.
USAGE
}

get_source() {
  if [[ -f ./go.mod && -f ./scripts/install-server.sh ]] && grep -Fxq 'module github.com/hatinati2/PQTunnel' ./go.mod; then
    SOURCE_DIR="$(pwd)"
    return
  fi
  have curl || fail 'curl is required; no changes made.'
  have tar || fail 'tar is required; no changes made.'
  WORK_DIR="$(mktemp -d)"
  mkdir -p "$WORK_DIR/src"
  curl --fail --silent --show-error --location "$API_TARBALL" -o "$WORK_DIR/source.tar.gz"
  tar -xzf "$WORK_DIR/source.tar.gz" --strip-components=1 -C "$WORK_DIR/src"
  SOURCE_DIR="$WORK_DIR/src"
}

validate_env_file() {
  local file="$1" line key value mode perm
  [[ -n "$file" && -f "$file" && -r "$file" ]] || fail "configuration file missing or unreadable: $file"
  mode="$(stat -c '%a' "$file" 2>/dev/null || printf 777)"
  perm=$((8#$mode))
  (( (perm & 0022) == 0 )) || fail "configuration must not be group/world-writable: $file"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" == *=* ]] || fail "configuration entry must be KEY=VALUE: $file"
    key="${line%%=*}"
    value="${line#*=}"
    [[ "$key" =~ ^PQTUNNEL_[A-Z0-9_]+$ ]] || fail "only PQTUNNEL_* keys are allowed: $file"
    [[ "$value" =~ ^([A-Za-z0-9_.,:/=-]|\[|\])*$ ]] || fail "unsupported characters or whitespace in configuration value: $file"
  done < "$file"
  if ! awk -F= '/^[[:space:]]*PQTUNNEL_[A-Z0-9_]+=/ { key=$1; gsub(/[[:space:]]/, "", key); if (seen[key]++) exit 1 }' "$file"; then
    fail "configuration contains duplicate keys: $file"
  fi
}

require_exact() {
  local file="$1" expected="$2"
  grep -Fxq "$expected" "$file" || fail "required setting missing from $file: $expected"
}
require_nonempty() {
  local file="$1" key="$2"
  grep -Eq "^$key=.+$" "$file" || fail "$key must be set in $file"
}
require_role_and_wan() {
  local file="$1" role="$2"
  require_exact "$file" "PQTUNNEL_ROLE=$role"
  grep -Eq '^PQTUNNEL_WAN_IF=[a-zA-Z0-9_.:-]+$' "$file" || fail "PQTUNNEL_WAN_IF must be set in $file"
}
check_os_prerequisites() {
  local cmd
  for cmd in "$@"; do have "$cmd" || fail "required command '$cmd' is missing; no packages are installed automatically."; done
}
validate_gateway_config() {
  local app="$1" network="$2"
  validate_env_file "$app"; validate_env_file "$network"
  require_exact "$app" 'PQTUNNEL_TLS_CERT=/etc/pqtunnel/pki/server.crt'
  require_exact "$app" 'PQTUNNEL_TLS_KEY=/etc/pqtunnel/pki/server.key'
  require_exact "$app" 'PQTUNNEL_CLIENT_CA=/etc/pqtunnel/pki/ca.crt'
  require_exact "$app" 'PQTUNNEL_MAX_CLIENTS=1'
  require_nonempty "$app" PQTUNNEL_PEER_PREFIXES
  require_nonempty "$app" PQTUNNEL_LOCAL_PREFIXES
  require_nonempty "$app" PQTUNNEL_PEER_NAME
  require_nonempty "$app" PQTUNNEL_ALLOWED_DST_PORTS
  require_role_and_wan "$network" gateway
}
validate_dialer_config() {
  local app="$1" network="$2"
  validate_env_file "$app"; validate_env_file "$network"
  require_nonempty "$app" PQTUNNEL_SERVER
  require_nonempty "$app" PQTUNNEL_SERVER_NAME
  require_nonempty "$app" PQTUNNEL_LOCAL_PREFIXES
  require_nonempty "$app" PQTUNNEL_REMOTE_PREFIXES
  require_nonempty "$app" PQTUNNEL_ALLOWED_DST_PORTS
  require_role_and_wan "$network" dialer
  if ! grep -Eq '^PQTUNNEL_(TCP_EGRESS_PORTS|UDP_EGRESS_PORTS|TCP_FORWARD_RULES|UDP_FORWARD_RULES)=.+' "$network"; then
    fail 'configure at least one egress port list or port-forward rule in the network config.'
  fi
}
check_no_existing() {
  local path
  for path in "$@"; do [[ ! -e "$path" ]] || fail "existing artifact detected at $path; refusing to overwrite."; done
}

require_pinned_source_ref() {
  [[ "$PQTUNNEL_REF" =~ ^[0-9a-f]{40}$ ]] || fail 'install modes require PQTUNNEL_REF to be a reviewed, lowercase 40-character commit SHA; no changes made.'
  if [[ -f ./go.mod && -f ./scripts/install-server.sh ]] && grep -Fxq 'module github.com/hatinati2/PQTunnel' ./go.mod; then
    local checkout_sha
    checkout_sha="$(git rev-parse HEAD 2>/dev/null)" || fail 'cannot verify the local checkout commit; use a clean checkout matching PQTUNNEL_REF.'
    [[ "$checkout_sha" == "$PQTUNNEL_REF" ]] || fail "local checkout HEAD ($checkout_sha) does not match PQTUNNEL_REF ($PQTUNNEL_REF); no changes made."
    [[ -z "$(git status --porcelain 2>/dev/null)" ]] || fail 'local checkout has uncommitted or untracked changes; use a clean checkout matching PQTUNNEL_REF.'
  fi
}

case "$MODE" in
  -h|--help|help) usage; exit 0 ;;
  preflight)
    ROLE=both; ENDPOINT=
    while (($#)); do
      case "$1" in
        --role) [[ $# -ge 2 ]] || fail 'missing --role value'; ROLE="$2"; shift 2 ;;
        --endpoint) [[ $# -ge 2 ]] || fail 'missing --endpoint value'; ENDPOINT="$2"; shift 2 ;;
        *) echo "unknown preflight option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done
    [[ "$ROLE" == both || "$ROLE" == gateway || "$ROLE" == dialer ]] || fail 'role must be both, gateway or dialer.'
    if [[ -f ./scripts/site-to-site-preflight.sh ]]; then PREFLIGHT=./scripts/site-to-site-preflight.sh
    else
      check_os_prerequisites curl
      PREFLIGHT="$(mktemp)"
      trap 'rm -f "$PREFLIGHT"; cleanup' EXIT
      curl --fail --silent --show-error --location "$RAW_BASE/scripts/site-to-site-preflight.sh" -o "$PREFLIGHT"
    fi
    if [[ -n "$ENDPOINT" ]]; then bash "$PREFLIGHT" --role "$ROLE" --endpoint "$ENDPOINT"
    else bash "$PREFLIGHT" --role "$ROLE"; fi
    ;;
  check-config)
    KIND=; APP_ENV=; NETWORK_ENV=
    while (($#)); do
      case "$1" in
        --kind) [[ $# -ge 2 ]] || fail 'missing --kind value'; KIND="$2"; shift 2 ;;
        --app-env) [[ $# -ge 2 ]] || fail 'missing --app-env value'; APP_ENV="$2"; shift 2 ;;
        --network-env) [[ $# -ge 2 ]] || fail 'missing --network-env value'; NETWORK_ENV="$2"; shift 2 ;;
        *) echo "unknown check-config option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done
    case "$KIND" in gateway) validate_gateway_config "$APP_ENV" "$NETWORK_ENV";; dialer) validate_dialer_config "$APP_ENV" "$NETWORK_ENV";; *) fail 'check-config --kind must be gateway or dialer.';; esac
    echo "PASS: $KIND environment files validated; no system files or network state changed."
    ;;
  install-server)
    PKI_DIR=; SERVER_ENV=; NETWORK_ENV=; START=0; APPLY_NETWORK=0
    while (($#)); do
      case "$1" in
        --pki-dir) [[ $# -ge 2 ]] || fail 'missing --pki-dir value'; PKI_DIR="$2"; shift 2 ;;
        --server-env-file) [[ $# -ge 2 ]] || fail 'missing --server-env-file value'; SERVER_ENV="$2"; shift 2 ;;
        --network-env-file) [[ $# -ge 2 ]] || fail 'missing --network-env-file value'; NETWORK_ENV="$2"; shift 2 ;;
        --start) START=1; shift ;;
        --apply-network) APPLY_NETWORK=1; shift ;;
        *) echo "unknown install-server option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done
    require_pinned_source_ref
    [[ "$(id -u)" == 0 ]] || fail 'install-server requires root (sudo); no changes made.'
    [[ -n "$PKI_DIR" && -d "$PKI_DIR" ]] || fail '--pki-dir must contain server.crt, server.key and ca.crt.'
    check_os_prerequisites curl tar go openssl systemctl ip stat grep awk install
    GV="$(go env GOVERSION | sed 's/^go//')"
    if ! awk -v v="$GV" 'BEGIN { split(v,a,"."); exit !((a[1]+0)>1 || ((a[1]+0)==1 && (a[2]+0)>=24)) }'; then fail "Go 1.24+ is required; found $GV."; fi
    validate_gateway_config "$SERVER_ENV" "$NETWORK_ENV"
    [[ ! -e "$PKI_DIR/ca.key" ]] || fail 'ca.key must remain offline; it must not be copied to a server.'
    local_file=
    for local_file in server.crt server.key ca.crt; do [[ -s "$PKI_DIR/$local_file" ]] || fail "missing $PKI_DIR/$local_file."; done
    for local_file in /usr/local/sbin/pqtunneld /etc/systemd/system/pqtunneld.service /etc/pqtunnel/pki/server.crt /etc/pqtunnel/pki/server.key /etc/pqtunnel/pki/ca.crt /etc/default/pqtunneld /etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh; do [[ ! -e "$local_file" ]] || fail "existing artifact at $local_file; refusing to overwrite."; done
    (( APPLY_NETWORK == 0 || START == 1 )) || fail '--apply-network requires --start.'
    get_source
    echo 'Read-only preflight on this host (no network changes):'
    bash "$SOURCE_DIR/scripts/site-to-site-preflight.sh" --role gateway
    bash "$SOURCE_DIR/scripts/install-server.sh" --source "$SOURCE_DIR" --pki "$PKI_DIR"
    install -d -o root -g root -m 0750 /usr/local/lib/pqtunnel
    install -o root -g root -m 0755 "$SOURCE_DIR/scripts/site-to-site-selective.sh" /usr/local/lib/pqtunnel/site-to-site-selective.sh
    install -o root -g root -m 0640 "$SERVER_ENV" /etc/default/pqtunneld
    install -o root -g root -m 0640 "$NETWORK_ENV" /etc/pqtunnel/site-to-site.env
    systemctl daemon-reload
    if (( START )); then
      systemctl enable --now pqtunneld
      if (( APPLY_NETWORK )); then /usr/local/lib/pqtunnel/site-to-site-selective.sh gateway-up; fi
    fi
    echo 'Gateway install completed. Provider firewall was not modified.'
    ;;
  install-client)
    PKI_DIR=; CLIENT_ENV=; NETWORK_ENV=; START=0
    while (($#)); do
      case "$1" in
        --pki-dir) [[ $# -ge 2 ]] || fail 'missing --pki-dir value'; PKI_DIR="$2"; shift 2 ;;
        --client-env-file) [[ $# -ge 2 ]] || fail 'missing --client-env-file value'; CLIENT_ENV="$2"; shift 2 ;;
        --network-env-file) [[ $# -ge 2 ]] || fail 'missing --network-env-file value'; NETWORK_ENV="$2"; shift 2 ;;
        --start) START=1; shift ;;
        *) echo "unknown install-client option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done
    require_pinned_source_ref
    [[ "$(id -u)" == 0 ]] || fail 'install-client requires root (sudo); no changes made.'
    [[ -n "$PKI_DIR" && -d "$PKI_DIR" ]] || fail '--pki-dir must contain client.crt, client.key and ca.crt.'
    check_os_prerequisites curl tar go openssl systemctl ip nft sysctl stat grep awk install sha256sum sed
    validate_dialer_config "$CLIENT_ENV" "$NETWORK_ENV"
    [[ ! -e "$PKI_DIR/ca.key" ]] || fail 'ca.key must remain offline; it must not be copied to a client.'
    for local_file in client.crt client.key ca.crt; do [[ -s "$PKI_DIR/$local_file" ]] || fail "missing $PKI_DIR/$local_file."; done
    GV="$(go env GOVERSION | sed 's/^go//')"
    if ! awk -v v="$GV" 'BEGIN { split(v,a,"."); exit !((a[1]+0)>1 || ((a[1]+0)==1 && (a[2]+0)>=24)) }'; then fail "Go 1.24+ is required; found $GV."; fi
    openssl x509 -in "$PKI_DIR/client.crt" -noout >/dev/null || fail 'client.crt is not a valid PEM certificate.'
    openssl pkey -in "$PKI_DIR/client.key" -noout >/dev/null || fail 'client.key is not a valid PEM private key.'
    openssl verify -purpose sslclient -CAfile "$PKI_DIR/ca.crt" "$PKI_DIR/client.crt" >/dev/null || fail 'client certificate does not validate against ca.crt.'
    CERT_PUB="$(openssl x509 -in "$PKI_DIR/client.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')"
    KEY_PUB="$(openssl pkey -in "$PKI_DIR/client.key" -pubout -outform DER | sha256sum | awk '{print $1}')"
    [[ "$CERT_PUB" == "$KEY_PUB" ]] || fail 'client.key does not match client.crt.'
    for local_file in /usr/local/bin/pqtunnel-client /etc/systemd/system/pqtunnel-client.service /etc/pqtunnel/pki/client.crt /etc/pqtunnel/pki/client.key /etc/default/pqtunnel-client /etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh /usr/local/lib/pqtunnel/run-client.sh /usr/local/lib/pqtunnel/stop-client-network.sh; do [[ ! -e "$local_file" ]] || fail "existing artifact at $local_file; refusing to overwrite."; done
    get_source
    echo 'Read-only preflight on this host (no network changes):'
    bash "$SOURCE_DIR/scripts/site-to-site-preflight.sh" --role dialer
    BUILD_DIR="$(mktemp -d)"
    trap 'rm -rf "$BUILD_DIR"; cleanup' EXIT
    
    (
      cd "$SOURCE_DIR"
      GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$BUILD_DIR/pqtunnel-client" ./cmd/pqtunnel-client
    )
    install -d -o root -g root -m 0750 /etc/pqtunnel /etc/pqtunnel/pki /usr/local/lib/pqtunnel /var/lib/pqtunnel
    install -o root -g root -m 0755 "$BUILD_DIR/pqtunnel-client" /usr/local/bin/pqtunnel-client
    install -o root -g root -m 0755 "$SOURCE_DIR/scripts/site-to-site-selective.sh" /usr/local/lib/pqtunnel/site-to-site-selective.sh
    install -o root -g root -m 0755 "$SOURCE_DIR/scripts/run-pqtunnel-client.sh" /usr/local/lib/pqtunnel/run-client.sh
    install -o root -g root -m 0644 "$PKI_DIR/ca.crt" /etc/pqtunnel/pki/ca.crt
    install -o root -g root -m 0644 "$PKI_DIR/client.crt" /etc/pqtunnel/pki/client.crt
    install -o root -g root -m 0600 "$PKI_DIR/client.key" /etc/pqtunnel/pki/client.key
    install -o root -g root -m 0640 "$CLIENT_ENV" /etc/default/pqtunnel-client
    install -o root -g root -m 0640 "$NETWORK_ENV" /etc/pqtunnel/site-to-site.env
    install -o root -g root -m 0644 "$SOURCE_DIR/deploy/systemd/pqtunnel-client.service" /etc/systemd/system/pqtunnel-client.service
    systemctl daemon-reload
    if (( START )); then systemctl enable --now pqtunnel-client; else echo 'Client installed but remains stopped/disabled; networking unchanged.'; fi
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    usage >&2
    exit 2
    ;;
esac
