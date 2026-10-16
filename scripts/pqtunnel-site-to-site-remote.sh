#!/usr/bin/env bash
# Remote half of the guided one-line site-to-site installer.
# Intended to run over SSH as root; it fails closed on existing network policy.
set -Eeuo pipefail
umask 077

ACTION="$1"
STAGE="$2"
VERSION="$3"
TLS_PORT="$4"

fail() { printf 'PQTunnel remote setup: %s\n' "$*" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || fail 'connect as root over SSH for the guided installer.'
[[ "$STAGE" =~ ^/tmp/pqtunnel-site-to-site\.[A-Za-z0-9]+$ ]] || fail 'unsafe staging path.'
[[ "$VERSION" =~ ^v[0-9A-Za-z._-]+$ ]] || fail 'invalid release version.'
[[ "$TLS_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$TLS_PORT >= 1 && 10#$TLS_PORT <= 65535 )) || fail 'invalid TLS port.'

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) fail "unsupported remote architecture: $(uname -m)" ;;
esac
ASSET="PQTunnel-$VERSION-linux-$ARCH.tar.gz"
BUNDLE="$STAGE/PQTunnel-$VERSION-linux-$ARCH"

verify_bundle() {
  [[ -s "$STAGE/$ASSET" && -s "$STAGE/SHA256SUMS" ]] || fail "release bundle/checksum missing in $STAGE."
  grep -Fq "  ./$ASSET" "$STAGE/SHA256SUMS" || fail "official checksum file does not list $ASSET."
  (cd "$STAGE" && grep -F "  ./$ASSET" SHA256SUMS | sha256sum --check -)
  if [[ ! -d "$BUNDLE" ]]; then tar -xzf "$STAGE/$ASSET" -C "$STAGE"; fi
  [[ -x "$BUNDLE/pqtunneld" && -x "$BUNDLE/pqtunnel-client" && -x "$BUNDLE/pqtunnel-manager" && -x "$BUNDLE/pqtunnel-pki" ]] || fail 'release archive lacks one or more Linux binaries.'
  [[ -x "$BUNDLE/scripts/install-server.sh" && -x "$BUNDLE/scripts/site-to-site-selective.sh" ]] || fail 'release archive lacks required installer/network helpers.'
}

check_manager_state() {
  local count=0 path role
  for path in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service /etc/default/pqtunnel-manager; do
    if [[ -e "$path" ]]; then count=$((count + 1)); fi
  done
  if (( count == 0 )); then return 0; fi
  (( count == 3 )) || fail 'partial manager installation detected; refusing to replace existing files.'
  role="$(sed -n 's/^PQTUNNEL_MANAGER_ROLE=//p' /etc/default/pqtunnel-manager | head -n 1)"
  [[ "$role" == gateway ]] || fail "existing manager role is '$role', not 'gateway'. Resolve manually before setup."
}

check_endpoint_absent() {
  local path
  for path in \
    /usr/local/sbin/pqtunneld \
    /etc/systemd/system/pqtunneld.service \
    /etc/pqtunnel/pki/server.crt \
    /etc/pqtunnel/pki/server.key \
    /etc/pqtunnel/pki/ca.crt \
    /etc/default/pqtunneld \
    /etc/pqtunnel/site-to-site.env \
    /usr/local/lib/pqtunnel/site-to-site-selective.sh; do
    [[ ! -e "$path" ]] || fail "existing Gateway endpoint artifact detected at $path; no files overwritten."
  done
}

check_network_guard() {
  local check_tun="$1" rules
  command -v ip >/dev/null && command -v nft >/dev/null && command -v sysctl >/dev/null || fail 'iproute2, nftables and procps/sysctl must already be installed.'
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    fail 'UFW is active. This automated network helper cannot safely integrate with it.'
  fi
  rules="$(nft list ruleset 2>/dev/null || true)"
  if grep -Eq '^[[:space:]]*table[[:space:]]' <<< "$rules"; then
    fail 'existing nftables tables/rules were detected. No rules were changed; use a separately reviewed integration plan.'
  fi
  if command -v iptables-save >/dev/null 2>&1 && iptables-save 2>/dev/null | grep -qE '^-A[[:space:]]'; then
    fail 'existing iptables rules were detected. No rules were changed.'
  fi
  [[ "$(sysctl -n net.ipv4.ip_forward)" == 0 ]] || fail 'IPv4 forwarding is already enabled; manual network review required.'
  [[ "$(sysctl -n net.ipv6.conf.all.forwarding)" == 0 ]] || fail 'IPv6 forwarding is already enabled; manual network review required.'
  if ip -4 rule show | grep -Eq '^(10518|10519):' || ip -6 rule show | grep -Eq '^(10518|10519):'; then
    fail 'policy-routing priority 10518/10519 is occupied.'
  fi
  [[ -z "$(ip -4 route show table 518 2>/dev/null)$(ip -6 route show table 518 2>/dev/null)$(ip -4 route show table 519 2>/dev/null)$(ip -6 route show table 519 2>/dev/null)" ]] || fail 'policy-routing table 518 or 519 is already used.'
  if [[ "$check_tun" == yes ]] && ip link show dev pqtun0 >/dev/null 2>&1; then
    fail 'pqtun0 already exists; refusing to take over an unmanaged TUN interface.'
  fi
}

check_listener_port_free() {
  if ss -ltnH 2>/dev/null | awk -v p=":$TLS_PORT" '$4 ~ (p "$") {found=1} END {exit !found}'; then
    fail "TCP port $TLS_PORT is already in use on Gateway."
  fi
}

validate_staged_config() {
  local path cert_hash key_hash
  [[ -s "$STAGE/gateway-app.env" && -s "$STAGE/gateway-network.env" && -s "$STAGE/gateway-manager-token" && -s "$STAGE/speedtest-token" ]] || fail 'Gateway configuration/token staging is incomplete.'
  [[ -d "$STAGE/gateway-pki" ]] || fail 'Gateway PKI staging directory is missing.'
  chmod 0600 "$STAGE/gateway-manager-token" "$STAGE/speedtest-token"
  for path in server.crt server.key ca.crt; do [[ -s "$STAGE/gateway-pki/$path" ]] || fail "Gateway PKI file is missing: $path"; done
  [[ ! -e "$STAGE/gateway-pki/ca.key" ]] || fail 'CA private key must stay offline; it must not be sent to a server.'
  openssl verify -purpose sslserver -CAfile "$STAGE/gateway-pki/ca.crt" "$STAGE/gateway-pki/server.crt" >/dev/null || fail 'Gateway server certificate failed CA validation.'
  cert_hash="$(openssl x509 -in "$STAGE/gateway-pki/server.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')"
  key_hash="$(openssl pkey -in "$STAGE/gateway-pki/server.key" -pubout -outform DER | sha256sum | awk '{print $1}')"
  [[ "$cert_hash" == "$key_hash" ]] || fail 'Gateway certificate/private key mismatch.'
  [[ "$(stat -c '%a' "$STAGE/gateway-pki/server.key")" == 600 ]] || fail 'Gateway private-key staging mode must be 0600.'
  PQTUNNEL_SITE_CONFIG="$STAGE/gateway-network.env" bash "$BUNDLE/scripts/site-to-site-selective.sh" validate >/dev/null
  PQTUNNEL_SITE_CONFIG="$STAGE/gateway-network.env" bash "$BUNDLE/scripts/site-to-site-selective.sh" preview >/dev/null
}

configure_manager() {
  local token speed_token temp line path present=0
  token="$(cat "$STAGE/gateway-manager-token")"
  speed_token="$(cat "$STAGE/speedtest-token")"
  [[ "$token" =~ ^[0-9a-f]{64}$ && "$speed_token" =~ ^[0-9a-f]{64}$ ]] || fail 'manager token validation failed.'
  for path in /usr/local/sbin/pqtunnel-manager /etc/systemd/system/pqtunnel-manager.service /etc/default/pqtunnel-manager; do
    if [[ -e "$path" ]]; then present=$((present + 1)); fi
  done
  if (( present == 0 )); then
    bash "$BUNDLE/scripts/install-manager.sh" --source "$BUNDLE" --role gateway
  elif (( present != 3 )); then
    fail 'partial manager installation detected; refusing to replace files.'
  fi
  temp="$(mktemp)"
  if [[ -f /etc/default/pqtunnel-manager ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      case "$line" in
        PQTUNNEL_MANAGER_ROLE=*|PQTUNNEL_MANAGER_LISTEN=*|PQTUNNEL_MANAGER_TOKEN=*|PQTUNNEL_MANAGER_PUBLIC_HOST=*|PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP=*|PQTUNNEL_MANAGER_TLS_CERT=*|PQTUNNEL_MANAGER_TLS_KEY=*|PQTUNNEL_MANAGER_SPEEDTEST_LISTEN=*|PQTUNNEL_MANAGER_SPEEDTEST_PEER=*|PQTUNNEL_MANAGER_SPEEDTEST_TOKEN=*) ;;
        *) printf '%s\n' "$line" ;;
      esac
    done < /etc/default/pqtunnel-manager > "$temp"
  fi
  {
    printf 'PQTUNNEL_MANAGER_ROLE=gateway\n'
    printf 'PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091\n'
    printf 'PQTUNNEL_MANAGER_TOKEN=%s\n' "$token"
    printf 'PQTUNNEL_MANAGER_SPEEDTEST_LISTEN=10.66.0.1:9109\n'
    printf 'PQTUNNEL_MANAGER_SPEEDTEST_PEER=10.66.0.2:9109\n'
    printf 'PQTUNNEL_MANAGER_SPEEDTEST_TOKEN=%s\n' "$speed_token"
  } >> "$temp"
  install -o root -g root -m 0600 "$temp" /etc/default/pqtunnel-manager
  rm -f "$temp"
  unset token speed_token
}

verify_bundle
validate_staged_config

case "$ACTION" in
  preflight)
    bash "$BUNDLE/scripts/site-to-site-preflight.sh" --role gateway
    check_network_guard yes
    check_endpoint_absent
    check_manager_state
    check_listener_port_free
    echo 'PASS: Gateway preflight found no existing endpoint or guarded network state.'
    ;;
  install)
    check_network_guard yes
    check_endpoint_absent
    check_manager_state
    check_listener_port_free
    bash "$BUNDLE/scripts/install-server.sh" --source "$BUNDLE" --pki "$STAGE/gateway-pki"
    install -o root -g root -m 0640 "$STAGE/gateway-app.env" /etc/default/pqtunneld
    install -o root -g root -m 0640 "$STAGE/gateway-network.env" /etc/pqtunnel/site-to-site.env
    install -o root -g root -m 0755 "$BUNDLE/scripts/site-to-site-selective.sh" /usr/local/lib/pqtunnel/site-to-site-selective.sh
    systemctl daemon-reload
    systemd-analyze verify /etc/systemd/system/pqtunneld.service
    configure_manager
    systemd-analyze verify /etc/systemd/system/pqtunnel-manager.service
    systemctl enable --now pqtunneld
    systemctl enable --now pqtunnel-manager
    systemctl restart pqtunnel-manager
    printf 'GATEWAY_MANAGER_TOKEN_APPLIED=1\n' > "$STAGE/manager-token-applied"
    ;;
  apply-network)
    systemctl is-active --quiet pqtunneld || fail 'pqtunneld is not active; refusing to apply Gateway network rules.'
    check_network_guard no
    PQTUNNEL_SITE_CONFIG="$STAGE/gateway-network.env" bash "$BUNDLE/scripts/site-to-site-selective.sh" gateway-up
    ;;
  cleanup)
    rm -rf -- "$STAGE"
    ;;
  *)
    fail 'unknown action; use preflight, install, apply-network, or cleanup.'
    ;;
esac
