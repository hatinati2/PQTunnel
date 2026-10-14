#!/usr/bin/env bash
# Read-only PQTunnel host preflight. Never applies network or service changes.
set -uo pipefail

ROLE=both
ENDPOINT=
usage() {
  cat <<'USAGE'
PQTunnel VPS preflight (READ-ONLY; no network or service changes)
Usage: bash scripts/site-to-site-preflight.sh [--role dialer|gateway|both] [--endpoint IP_OR_HOST]
Checks OS, tools, routes, forwarding, policy table conflicts, firewall presence,
PQTunnel files/service state and certificate expiry. Does not source config files,
print certificate/private-key contents, write reports, or apply changes.
--endpoint optionally checks the existing route to a literal IP or resolved hostname.
USAGE
}
while (($#)); do
  case "$1" in
    --role) [[ $# -ge 2 ]] || { echo "missing --role value" >&2; exit 2; }; ROLE=$2; shift 2 ;;
    --endpoint) [[ $# -ge 2 ]] || { echo "missing --endpoint value" >&2; exit 2; }; ENDPOINT=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "$ROLE" in dialer|gateway|both) ;; *) echo "role must be dialer, gateway or both" >&2; exit 2 ;; esac

PASS=0; WARN=0; FAIL=0
report() {
  level=$1; shift
  printf '[%s] %s\n' "$level" "$*"
  case "$level" in PASS) PASS=$((PASS+1));; WARN) WARN=$((WARN+1));; FAIL) FAIL=$((FAIL+1));; esac
}
have() { command -v "$1" >/dev/null 2>&1; }

printf '%s\n' 'PQTunnel host preflight — READ-ONLY'
printf 'time_utc=%s role=%s\n' "$(date -u +%FT%TZ 2>/dev/null || printf unknown)" "$ROLE"
printf 'host=%s uid=%s\n' "$(hostname 2>/dev/null || printf unknown)" "$(id -u 2>/dev/null || printf unknown)"
printf '%s\n' 'Privacy: config values, IP addresses, certificate contents, and private keys are not printed.'

if [[ -r /etc/os-release ]]; then
  OS_ID=$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2; exit}' /etc/os-release)
  OS_VERSION=$(awk -F= '$1=="VERSION_ID"{gsub(/"/,"",$2); print $2; exit}' /etc/os-release)
  printf 'os=%s version=%s\n' "$OS_ID" "$OS_VERSION"
  if [[ "$OS_ID" == ubuntu && ( "$OS_VERSION" == 24.04 || "$OS_VERSION" == 26.04 ) ]]; then
    report PASS "Ubuntu $OS_VERSION matches the project's CI targets."
  elif [[ "$OS_ID" == ubuntu ]]; then
    report WARN "Ubuntu $OS_VERSION is outside the currently tested 24.04/26.04 matrix."
  else
    report WARN 'OS is not Ubuntu; deployment helpers target Ubuntu/Linux with systemd.'
  fi
else report WARN '/etc/os-release is not readable; OS could not be identified.'; fi

if [[ $(id -u 2>/dev/null || echo 1) -eq 0 ]]; then report PASS 'Running as root; read-only metadata checks can be more complete.'; else report WARN 'Not root; firewall/service checks may be incomplete. This script still changes nothing.'; fi
for cmd in ip nft sysctl systemctl openssl stat awk grep; do
  if have "$cmd"; then report PASS "command available: $cmd"; else report WARN "command unavailable: $cmd"; fi
done

if have ip; then
  DEFAULT4=$(ip -4 route show default 2>/dev/null | awk 'END{print NR+0}')
  DEFAULT6=$(ip -6 route show default 2>/dev/null | awk 'END{print NR+0}')
  WAN_NAMES=$(ip -o route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); break}}' | sort -u | paste -sd, -)
  printf 'default_route_count_v4=%s default_route_count_v6=%s default_route_interfaces=%s\n' "$DEFAULT4" "$DEFAULT6" "${WAN_NAMES:-none}"
  if [[ "$DEFAULT4" -gt 0 ]]; then report PASS 'At least one IPv4 default route exists.'; else report WARN 'No IPv4 default route found.'; fi
  if ip link show dev pqtun0 >/dev/null 2>&1; then report WARN 'pqtun0 already exists; do not assume PQTunnel owns it.'; else report PASS 'pqtun0 is not currently present.'; fi
  if ip -4 rule show 2>/dev/null | grep -Eq '^(10518|10519):'; then report WARN 'Policy-routing priority 10518 or 10519 is occupied.'; else report PASS 'Policy-routing priorities 10518/10519 appear free.'; fi
  for table in 518 519; do
    R4=$(ip -4 route show table "$table" 2>/dev/null | awk 'END{print NR+0}')
    R6=$(ip -6 route show table "$table" 2>/dev/null | awk 'END{print NR+0}')
    if [[ "$R4" == 0 && "$R6" == 0 ]]; then report PASS "Routing table $table is empty."; else report WARN "Routing table $table has entries (v4=$R4 v6=$R6)."; fi
  done
else report FAIL 'iproute2 command "ip" is required for meaningful network preflight.'; fi

read_sysctl() {
  key=$1; label=$2
  if have sysctl && value=$(sysctl -n "$key" 2>/dev/null); then printf '%s=%s\n' "$label" "$value"; report PASS "$label is readable (value=$value)."; else report WARN "$label could not be read."; fi
}
read_sysctl net.ipv4.ip_forward ipv4_forwarding
read_sysctl net.ipv6.conf.all.forwarding ipv6_forwarding
read_sysctl net.ipv4.conf.all.rp_filter ipv4_rp_filter_all
read_sysctl net.ipv4.conf.default.rp_filter ipv4_rp_filter_default

if have nft; then
  NFT_TABLES=$(nft list tables 2>/dev/null || true)
  if [[ -n "$NFT_TABLES" ]]; then
    NFT_COUNT=$(printf '%s\n' "$NFT_TABLES" | grep -c '^table ' || true)
    report WARN "Existing nftables tables detected (count=$NFT_COUNT); review before any apply."
    if printf '%s\n' "$NFT_TABLES" | grep -Eq '^table inet (pqtunnel_selective|pqtunnel_gateway)$'; then report WARN 'A PQTunnel-named nftables table already exists.'; fi
  else report PASS 'No nftables tables were reported (permission errors may appear empty).'; fi
else report WARN 'nft unavailable; nftables state was not checked.'; fi

if have ufw; then
  UFW_STATUS=$(ufw status 2>/dev/null | awk 'NR==1{print $2}')
  if [[ "$UFW_STATUS" == active ]]; then report WARN 'UFW is active; current network helper deliberately refuses this host.'; else report PASS 'UFW is not reported active.'; fi
else report WARN 'ufw unavailable; UFW status could not be checked.'; fi
if have iptables-save; then
  if iptables-save 2>/dev/null | grep -qE '^-A[[:space:]]'; then report WARN 'Existing iptables rules detected; review before any apply.'; else report PASS 'No iptables -A rules were reported.'; fi
else report WARN 'iptables-save unavailable; legacy iptables rules were not checked.'; fi

check_file() {
  path=$1; label=$2; private=0
  if [[ $# -ge 3 ]]; then private=$3; fi
  if [[ ! -e "$path" ]]; then report WARN "$label not found: $path"; return; fi
  if [[ ! -f "$path" ]]; then report WARN "$label is not a regular file: $path"; return; fi
  if have stat; then
    owner=$(stat -c '%u' "$path" 2>/dev/null || printf '?')
    mode=$(stat -c '%a' "$path" 2>/dev/null || printf '?')
    printf 'file=%s exists=yes owner_uid=%s mode=%s\n' "$path" "$owner" "$mode"
    if [[ "$private" == 1 && "$mode" =~ ^[0-7]+$ ]]; then
      perm=$((8#$mode))
      if (( (perm & 0077) == 0 )); then report PASS "$label permissions restrict access to owner."; else report WARN "$label permissions are broader than 0600."; fi
    fi
    if [[ "$owner" != 0 ]]; then report WARN "$label is not owned by root."; fi
  fi
}

if [[ "$ROLE" == gateway || "$ROLE" == both ]]; then
  printf '%s\n' '--- gateway/listener checks ---'
  check_file /usr/local/sbin/pqtunneld 'pqtunneld binary'
  check_file /etc/default/pqtunneld 'pqtunneld environment file'
  check_file /etc/pqtunnel/pki/server.crt 'server certificate'
  check_file /etc/pqtunnel/pki/server.key 'server private key' 1
  check_file /etc/pqtunnel/pki/ca.crt 'peer CA certificate'
  if have systemctl; then
    if systemctl is-active --quiet pqtunneld 2>/dev/null; then report WARN 'pqtunneld service is active.'; else report PASS 'pqtunneld service is not active.'; fi
    if systemctl is-enabled --quiet pqtunneld 2>/dev/null; then report WARN 'pqtunneld is enabled at boot.'; else report PASS 'pqtunneld is not enabled at boot.'; fi
  fi
  if have openssl && [[ -s /etc/pqtunnel/pki/server.crt ]]; then
    END_DATE=$(openssl x509 -in /etc/pqtunnel/pki/server.crt -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    if [[ -n "$END_DATE" ]]; then
      printf 'server_certificate_not_after=%s\n' "$END_DATE"
      if openssl x509 -in /etc/pqtunnel/pki/server.crt -checkend 0 -noout >/dev/null 2>&1; then report PASS 'Server certificate is not expired.'; else report FAIL 'Server certificate has expired or could not be validated.'; fi
    fi
  fi
fi

if [[ "$ROLE" == dialer || "$ROLE" == both ]]; then
  printf '%s\n' '--- dialer/client checks ---'
  check_file /usr/local/bin/pqtunnel-client 'pqtunnel-client binary'
  check_file /etc/pqtunnel/site-to-site.env 'selective network config'
  check_file /etc/pqtunnel/pki/client.crt 'client/peer certificate'
  check_file /etc/pqtunnel/pki/client.key 'client/peer private key' 1
  check_file /etc/pqtunnel/pki/ca.crt 'server CA certificate'
  if have pgrep; then
    CLIENT_COUNT=$(pgrep -x pqtunnel-client 2>/dev/null | awk 'END{print NR+0}')
    printf 'pqtunnel_client_process_count=%s\n' "$CLIENT_COUNT"
    if [[ "$CLIENT_COUNT" -gt 0 ]]; then report WARN 'pqtunnel-client process is running.'; else report PASS 'No pqtunnel-client process is running.'; fi
  fi
  if have systemctl; then
    if systemctl is-active --quiet pqtunnel-client 2>/dev/null; then report WARN 'pqtunnel-client systemd unit is active.'; else report PASS 'pqtunnel-client systemd unit is not active.'; fi
  fi
fi

if [[ -n "$ENDPOINT" ]]; then
  printf '%s\n' '--- optional endpoint route check ---'
  candidate=
  if [[ "$ENDPOINT" =~ ^[0-9.]+$ || "$ENDPOINT" =~ ^[0-9a-fA-F:]+$ ]]; then
    candidate=$ENDPOINT
  elif have getent; then
    candidate=$(getent ahosts "$ENDPOINT" 2>/dev/null | awk 'NR==1{print $1}')
  fi
  if [[ -z "$candidate" ]]; then report WARN 'Endpoint did not resolve to an IP; route check skipped.'; elif ip route get "$candidate" >/dev/null 2>&1 || ip -6 route get "$candidate" >/dev/null 2>&1; then report PASS 'An existing route to an endpoint address is present.'; else report WARN 'No route could be confirmed to the endpoint.'; fi
fi

printf '\nSUMMARY pass=%s warn=%s fail=%s\n' "$PASS" "$WARN" "$FAIL"
printf '%s\n' 'READ-ONLY GUARANTEE: no files were created/deleted; no routes, sysctls, firewall state, or services were changed.'
printf '%s\n' 'Warnings are not permission to apply the network helper. Review all findings and retain console/out-of-band recovery.'
exit $(( FAIL > 0 ? 1 : 0 ))
