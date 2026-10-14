#!/usr/bin/env bash
# PQTunnel one-line bootstrap. Default mode is read-only preflight.
set -Eeuo pipefail

REPO_API="https://api.github.com/repos/hatinati2/PQTunnel/tarball/main"
RAW_BASE="https://raw.githubusercontent.com/hatinati2/PQTunnel/main"
MODE=preflight
if (($#)); then MODE=$1; shift; fi
WORK_DIR=
cleanup() { [[ -z "$WORK_DIR" ]] || rm -rf "$WORK_DIR"; }
trap cleanup EXIT

usage() {
  cat <<'USAGE'
PQTunnel one-line bootstrap

Read-only first step (default):
  curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/scripts/pqtunnel-bootstrap.sh | bash
  ... | bash -s -- preflight --role gateway
  ... | bash -s -- preflight --role dialer

Gateway install (PKI and reviewed config files must already exist on the host):
  ... | sudo bash -s -- install-server --pki-dir /root/pki --server-env-file /root/pqtunneld.env --network-env-file /root/site-to-site.env
  Append --start to enable/start the daemon; append --apply-network too only after preflight/recovery review.

Dialer install (Go 1.24+ must already be installed):
  ... | sudo bash -s -- install-client --pki-dir /root/pki --client-env-file /root/pqtunnel-client.env --network-env-file /root/site-to-site.env
  Append --start only when ready to apply dialer networking and start the client.

The default mode is read-only. Install modes refuse existing artifacts, do not install OS
packages, and do not evaluate configuration as shell when validating it. The dialer service
applies the selective network helper at start and calls its rollback action after stopping.
This project remains experimental; review the scripts and keep console/out-of-band recovery.
USAGE
}
fail() { echo "pqtunnel-bootstrap: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

get_source() {
  if [[ -f ./go.mod && -f ./scripts/install-server.sh ]] && grep -Fxq 'module github.com/hatinati2/PQTunnel' ./go.mod; then
    SOURCE_DIR="$(pwd)"
    return
  fi
  have curl || fail 'curl is required; no changes made.'
  have tar || fail 'tar is required; no changes made.'
  WORK_DIR="$(mktemp -d)"
  mkdir -p "$WORK_DIR/src"
  curl --fail --silent --show-error --location "$REPO_API" -o "$WORK_DIR/repo.tar.gz"
  tar -xzf "$WORK_DIR/repo.tar.gz" --strip-components=1 -C "$WORK_DIR/src"
  SOURCE_DIR="$WORK_DIR/src"
}

validate_env_file() {
  local file="$1" line key value extra mode perm
  [[ -f "$file" && -r "$file" ]] || fail "configuration file missing or unreadable: $file"
  mode="$(stat -c '%a' "$file" 2>/dev/null || printf 777)"
  perm=$((8#$mode))
  (( (perm & 0022) == 0 )) || fail "configuration must not be group/world-writable: $file"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue
    IFS='=' read -r key value extra <<< "$line"
    [[ "$key" =~ ^PQTUNNEL_[A-Z0-9_]+$ ]] || fail "configuration has a non-PQTUNNEL key: $file"
    [[ -z "$extra" ]] || fail "configuration line must contain exactly one '=': $file"
    [[ "$value" =~ ^([A-Za-z0-9_.,:/-]|\[|\])*$ ]] || fail "configuration contains unsupported characters/whitespace: $file"
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
  grep -Eq '^PQTUNNEL_WAN_IF=[A-Za-z0-9_.:-]+$' "$file" || fail "PQTUNNEL_WAN_IF must be set in $file"
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
    have curl || fail 'curl is required to fetch the read-only checker.'
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
    PKI_DIR=; SERVER_ENV=; NETWORK_ENV=; START=0; APPLY_NETWORK=0
    while (($#)); do
      case "$1" in
        --pki-dir) [[ $# -ge 2 ]] || fail 'missing value for --pki-dir'; PKI_DIR=$2; shift 2 ;;
        --server-env-file) [[ $# -ge 2 ]] || fail 'missing value for --server-env-file'; SERVER_ENV=$2; shift 2 ;;
        --network-env-file) [[ $# -ge 2 ]] || fail 'missing value for --network-env-file'; NETWORK_ENV=$2; shift 2 ;;
        --start) START=1; shift ;;
        --apply-network) APPLY_NETWORK=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown install option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done
    [[ "$(id -u)" == 0 ]] || fail 'install-server requires root (sudo). No changes made.'
    [[ -n "$PKI_DIR" && -d "$PKI_DIR" ]] || fail '--pki-dir must contain server.crt, server.key and ca.crt.'
    for cmd in curl tar openssl systemctl ip stat grep awk install; do have "$cmd" || fail "required command missing: $cmd; no changes made."; done
    validate_env_file "$SERVER_ENV"
    validate_env_file "$NETWORK_ENV"
    [[ ! -e "$PKI_DIR/ca.key" ]] || fail 'ca.key must remain offline and must not be installed on the server.'
    for file in server.crt server.key ca.crt; do [[ -s "$PKI_DIR/$file" ]] || fail "missing $PKI_DIR/$file"; done
    require_exact "$SERVER_ENV" 'PQTUNNEL_TLS_CERT=/etc/pqtunnel/pki/server.crt'
    require_exact "$SERVER_ENV" 'PQTUNNEL_TLS_KEY=/etc/pqtunnel/pki/server.key'
    require_exact "$SERVER_ENV" 'PQTUNNEL_CLIENT_CA=/etc/pqtunnel/pki/ca.crt'
    require_exact "$SERVER_ENV" 'PQTUNNEL_MAX_CLIENTS=1'
    require_nonempty "$SERVER_ENV" PQTUNNEL_PEER_PREFIXES
    require_nonempty "$SERVER_ENV" PQTUNNEL_LOCAL_PREFIXES
    require_nonempty "$SERVER_ENV" PQTUNNEL_PEER_NAME
    require_nonempty "$SERVER_ENV" PQTUNNEL_ALLOWED_DST_PORTS
    require_role_and_wan "$NETWORK_ENV" gateway
    (( APPLY_NETWORK == 0 || START == 1 )) || fail '--apply-network requires --start so the listener TUN is ready first.'
    for artifact in /usr/local/sbin/pqtunneld /etc/systemd/system/pqtunneld.service /etc/pqtunnel/pki/server.crt /etc/pqtunnel/pki/server.key /etc/pqtunnel/pki/ca.crt /etc/default/pqtunneld /etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh; do
      [[ ! -e "$artifact" ]] || fail "existing server artifact/config detected at $artifact; refusing to overwrite."
    done
    get_source
    echo 'Read-only host preflight before installation:'
    bash "$SOURCE_DIR/scripts/site-to-site-preflight.sh" --role gateway
    bash "$SOURCE_DIR/scripts/install-server.sh" --source "$SOURCE_DIR" --pki "$PKI_DIR"
    install -d -o root -g root -m 0750 /usr/local/lib/pqtunnel
    install -o root -g root -m 0755 "$SOURCE_DIR/scripts/site-to-site-selective.sh" /usr/local/lib/pqtunnel/site-to-site-selective.sh
    install -o root -g root -m 0640 "$SERVER_ENV" /etc/default/pqtunneld
    install -o root -g root -m 0640 "$NETWORK_ENV" /etc/pqtunnel/site-to-site.env
    systemctl daemon-reload
    if (( START )); then
      systemctl enable --now pqtunneld
      if (( APPLY_NETWORK )); then
        if ! /usr/local/lib/pqtunnel/site-to-site-selective.sh gateway-up; then
          fail 'gateway network apply failed; helper should have rolled back its own partial changes. pqtunneld remains active for inspection.'
        fi
      fi
      echo 'Gateway daemon started. Network helper was applied only because --apply-network was explicitly supplied.'
    else
      echo 'Gateway daemon and configs installed; service remains stopped/disabled.'
    fi
    echo 'The provider firewall is never changed by this script.'
    ;;
  install-client)
    PKI_DIR=; CLIENT_ENV=; NETWORK_ENV=; START=0
    while (($#)); do
      case "$1" in
        --pki-dir) [[ $# -ge 2 ]] || fail 'missing value for --pki-dir'; PKI_DIR=$2; shift 2 ;;
        --client-env-file) [[ $# -ge 2 ]] || fail 'missing value for --client-env-file'; CLIENT_ENV=$2; shift 2 ;;
        --network-env-file) [[ $# -ge 2 ]] || fail 'missing value for --network-env-file'; NETWORK_ENV=$2; shift 2 ;;
        --start) START=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown install option: $1" >&2; usage >&2; exit 2 ;;
      esac
    done
    [[ "$(id -u)" == 0 ]] || fail 'install-client requires root (sudo). No changes made.'
    [[ -n "$PKI_DIR" && -d "$PKI_DIR" ]] || fail '--pki-dir must contain client.crt, client.key and ca.crt.'
    for cmd in go openssl install systemctl ip nft sysctl stat grep awk sha256sum sed; do have "$cmd" || fail "required command missing: $cmd; no packages are installed automatically."; done
    validate_env_file "$CLIENT_ENV"
    validate_env_file "$NETWORK_ENV"
    [[ ! -e "$PKI_DIR/ca.key" ]] || fail 'ca.key must remain offline and must not be installed on the client.'
    for file in client.crt client.key ca.crt; do [[ -s "$PKI_DIR/$file" ]] || fail "missing $PKI_DIR/$file"; done
    require_nonempty "$CLIENT_ENV" PQTUNNEL_SERVER
    require_nonempty "$CLIENT_ENV" PQTUNNEL_SERVER_NAME
    require_nonempty "$CLIENT_ENV" PQTUNNEL_LOCAL_PREFIXES
    require_nonempty "$CLIENT_ENV" PQTUNNEL_REMOTE_PREFIXES
    require_nonempty "$CLIENT_ENV" PQTUNNEL_ALLOWED_DST_PORTS
    require_role_and_wan "$NETWORK_ENV" dialer
    if ! grep -Eq '^PQTUNNEL_(TCP_EGRESS_PORTS|UDP_EGRESS_PORTS|TCP_FORWARD_RULES|UDP_FORWARD_RULES)=.+    for artifact in /usr/local/bin/pqtunnel-client /etc/systemd/system/pqtunnel-client.service /etc/pqtunnel/pki/client.crt /etc/pqtunnel/pki/client.key /etc/default/pqtunnel-client /etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh; do
      [[ ! -e "$artifact" ]] || fail "existing dialer artifact/config detected at $artifact; refusing to overwrite."
    done
    GV="$(go env GOVERSION | sed 's/^go//')"
    if ! awk -v v="$GV" 'BEGIN { split(v,a,"."); exit !((a[1]+0)>1 || ((a[1]+0)==1 && (a[2]+0)>=24)) }'; then fail "Go 1.24+ required; found $GV."; fi
    openssl x509 -in "$PKI_DIR/client.crt" -noout >/dev/null || fail 'client.crt is not a valid PEM certificate.'
    openssl pkey -in "$PKI_DIR/client.key" -noout >/dev/null || fail 'client.key is not a valid PEM private key.'
    openssl verify -purpose sslclient -CAfile "$PKI_DIR/ca.crt" "$PKI_DIR/client.crt" >/dev/null || fail 'client certificate does not validate against ca.crt.'
    CERT_PUB="$(openssl x509 -in "$PKI_DIR/client.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')"
    KEY_PUB="$(openssl pkey -in "$PKI_DIR/client.key" -pubout -outform DER | sha256sum | awk '{print $1}')"
    [[ "$CERT_PUB" == "$KEY_PUB" ]] || fail 'client.key does not match client.crt.'
    get_source
    echo 'Read-only host preflight before installation:'
    bash "$SOURCE_DIR/scripts/site-to-site-preflight.sh" --role dialer
    WORK_DIR_BUILD="$(mktemp -d)"
    trap 'rm -rf "$WORK_DIR_BUILD"; cleanup' EXIT
    (
      cd "$SOURCE_DIR"
      GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$WORK_DIR_BUILD/pqtunnel-client" ./cmd/pqtunnel-client
    )
    install -d -o root -g root -m 0750 /etc/pqtunnel /etc/pqtunnel/pki /usr/local/lib/pqtunnel /var/lib/pqtunnel
    install -o root -g root -m 0755 "$WORK_DIR_BUILD/pqtunnel-client" /usr/local/bin/pqtunnel-client
    install -o root -g root -m 0755 "$SOURCE_DIR/scripts/site-to-site-selective.sh" /usr/local/lib/pqtunnel/site-to-site-selective.sh
    install -o root -g root -m 0644 "$PKI_DIR/ca.crt" /etc/pqtunnel/pki/ca.crt
    install -o root -g root -m 0644 "$PKI_DIR/client.crt" /etc/pqtunnel/pki/client.crt
    install -o root -g root -m 0600 "$PKI_DIR/client.key" /etc/pqtunnel/pki/client.key
    install -o root -g root -m 0640 "$CLIENT_ENV" /etc/default/pqtunnel-client
    install -o root -g root -m 0640 "$NETWORK_ENV" /etc/pqtunnel/site-to-site.env
    install -o root -g root -m 0644 "$SOURCE_DIR/deploy/systemd/pqtunnel-client.service" /etc/systemd/system/pqtunnel-client.service
    systemctl daemon-reload
    if (( START )); then
      systemctl enable --now pqtunnel-client
      echo 'Dialer service started. The unit applies the selective network helper and rolls it back after stop.'
    else
      echo 'Dialer binary, certificates and configs installed; service remains stopped/disabled and networking is unchanged.'
    fi
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    usage >&2
    exit 2
    ;;
esac
 "$NETWORK_ENV"; then
      fail 'configure at least one egress port list or port-forward rule in the network env file.'
    fi
    for artifact in /usr/local/bin/pqtunnel-client /etc/systemd/system/pqtunnel-client.service /etc/pqtunnel/pki/client.crt /etc/pqtunnel/pki/client.key /etc/default/pqtunnel-client /etc/pqtunnel/site-to-site.env /usr/local/lib/pqtunnel/site-to-site-selective.sh; do
      [[ ! -e "$artifact" ]] || fail "existing dialer artifact/config detected at $artifact; refusing to overwrite."
    done
    for cmd in go openssl install systemctl ip; do have "$cmd" || fail "required command missing: $cmd; no packages are installed automatically."; done
    GV="$(go env GOVERSION | sed 's/^go//')"
    if ! awk -v v="$GV" 'BEGIN { split(v,a,"."); exit !((a[1]+0)>1 || ((a[1]+0)==1 && (a[2]+0)>=24)) }'; then fail "Go 1.24+ required; found $GV."; fi
    openssl x509 -in "$PKI_DIR/client.crt" -noout >/dev/null || fail 'client.crt is not a valid PEM certificate.'
    openssl pkey -in "$PKI_DIR/client.key" -noout >/dev/null || fail 'client.key is not a valid PEM private key.'
    openssl verify -purpose sslclient -CAfile "$PKI_DIR/ca.crt" "$PKI_DIR/client.crt" >/dev/null || fail 'client certificate does not validate against ca.crt.'
    CERT_PUB="$(openssl x509 -in "$PKI_DIR/client.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')"
    KEY_PUB="$(openssl pkey -in "$PKI_DIR/client.key" -pubout -outform DER | sha256sum | awk '{print $1}')"
    [[ "$CERT_PUB" == "$KEY_PUB" ]] || fail 'client.key does not match client.crt.'
    get_source
    echo 'Read-only host preflight before installation:'
    bash "$SOURCE_DIR/scripts/site-to-site-preflight.sh" --role dialer
    WORK_DIR_BUILD="$(mktemp -d)"
    trap 'rm -rf "$WORK_DIR_BUILD"; cleanup' EXIT
    (
      cd "$SOURCE_DIR"
      GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$WORK_DIR_BUILD/pqtunnel-client" ./cmd/pqtunnel-client
    )
    install -d -o root -g root -m 0750 /etc/pqtunnel /etc/pqtunnel/pki /usr/local/lib/pqtunnel /var/lib/pqtunnel
    install -o root -g root -m 0755 "$WORK_DIR_BUILD/pqtunnel-client" /usr/local/bin/pqtunnel-client
    install -o root -g root -m 0755 "$SOURCE_DIR/scripts/site-to-site-selective.sh" /usr/local/lib/pqtunnel/site-to-site-selective.sh
    install -o root -g root -m 0644 "$PKI_DIR/ca.crt" /etc/pqtunnel/pki/ca.crt
    install -o root -g root -m 0644 "$PKI_DIR/client.crt" /etc/pqtunnel/pki/client.crt
    install -o root -g root -m 0600 "$PKI_DIR/client.key" /etc/pqtunnel/pki/client.key
    install -o root -g root -m 0640 "$CLIENT_ENV" /etc/default/pqtunnel-client
    install -o root -g root -m 0640 "$NETWORK_ENV" /etc/pqtunnel/site-to-site.env
    install -o root -g root -m 0644 "$SOURCE_DIR/deploy/systemd/pqtunnel-client.service" /etc/systemd/system/pqtunnel-client.service
    systemctl daemon-reload
    if (( START )); then
      systemctl enable --now pqtunnel-client
      echo 'Dialer service started. The unit applies the selective network helper and rolls it back after stop.'
    else
      echo 'Dialer binary, certificates and configs installed; service remains stopped/disabled and networking is unchanged.'
    fi
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    usage >&2
    exit 2
    ;;
esac
