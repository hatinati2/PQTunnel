#!/usr/bin/env bash
# Experimental Linux-only helper for selective site-to-site policy routing.
# It intentionally refuses hosts with existing firewall/forwarding policies.
set -Eeuo pipefail

CONFIG="${PQTUNNEL_SITE_CONFIG:-/etc/pqtunnel/site-to-site.env}"
STATE_DIR="${PQTUNNEL_STATE_DIR:-/var/lib/pqtunnel}"
DIALER_STATE="$STATE_DIR/site-selective-dialer.state"
GATEWAY_STATE="$STATE_DIR/site-selective-gateway.state"
GATEWAY_TUN_OWNER_MARKER="/var/lib/pqtunnel-manager/gateway-tun-owned"
TUN_DEFAULT="pqtun0"
TUN_V4_DIALER="10.66.0.2/24"
TUN_V4_GATEWAY="10.66.0.1/24"
TUN_V4_HOST="10.66.0.2"
TUN_V6_DIALER="fd42:7061:7475::2/64"
TUN_V6_GATEWAY="fd42:7061:7475::1/64"
TUN_V6_HOST="fd42:7061:7475::2"
MARK_SOCKET=20560
MARK_EGRESS=20561
MARK_FORWARD=20562
TABLE_EGRESS=518
TABLE_FORWARD=519
PRIO_EGRESS=10518
PRIO_FORWARD=10519
NFT_DIALER="pqtunnel_selective"
NFT_GATEWAY="pqtunnel_gateway"

fail() { echo "pqtunnel-selective: $*" >&2; exit 1; }
need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || fail 'this action requires root on a dedicated test host'; }
valid_ifname() { [[ "$1" =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]]; }
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

usage() {
  cat <<'USAGE'
PQTunnel selective site-to-site network helper (EXPERIMENTAL)

Read-only actions:
  bash scripts/site-to-site-selective.sh validate
  bash scripts/site-to-site-selective.sh preview
  sudo bash scripts/site-to-site-selective.sh status

Network-changing actions (do NOT run on a live/production host until reviewed):
  sudo bash scripts/site-to-site-selective.sh dialer-up
  sudo bash scripts/site-to-site-selective.sh dialer-down
  sudo bash scripts/site-to-site-selective.sh gateway-up
  sudo bash scripts/site-to-site-selective.sh gateway-down

Configuration file defaults to /etc/pqtunnel/site-to-site.env; override with
PQTUNNEL_SITE_CONFIG. The up actions intentionally refuse UFW-active hosts,
pre-existing nftables/iptables rules, pre-enabled forwarding, and unmanaged
TUN interfaces. This helper is for an isolated lab host, not a production VPS.

Port format:
  TCP/UDP egress: comma-separated destination ports, e.g. 443,8443
  TCP/UDP forwarding: localPort=targetIPv4:targetPort or localPort=[targetIPv6]:targetPort
  The target of a port-forward mapping must be a literal IP address, not a domain.
USAGE
}

load_config() {
  local require_root_owner="${1:-0}"
  [[ -f "$CONFIG" && -r "$CONFIG" ]] || fail "config not found: $CONFIG (copy scripts/site-to-site.env.example and edit it)"
  local owner mode permissions
  owner="$(stat -c '%u' "$CONFIG")"
  if [[ "$require_root_owner" == 1 ]]; then [[ "$owner" == 0 ]] || fail 'configuration must be owned by root'; fi
  mode="$(stat -c '%a' "$CONFIG")"
  permissions=$((8#$mode))
  (( (permissions & 0022) == 0 )) || fail 'configuration must not be group/world-writable (recommended mode 0600 or 0640)'
  # shellcheck source=/dev/null
  source "$CONFIG"
  PQTUNNEL_ROLE="${PQTUNNEL_ROLE:-dialer}"
  PQTUNNEL_WAN_IF="${PQTUNNEL_WAN_IF:-}"
  PQTUNNEL_TUN="${PQTUNNEL_TUN:-$TUN_DEFAULT}"
  PQTUNNEL_TCP_EGRESS_PORTS="${PQTUNNEL_TCP_EGRESS_PORTS:-}"
  PQTUNNEL_UDP_EGRESS_PORTS="${PQTUNNEL_UDP_EGRESS_PORTS:-}"
  PQTUNNEL_TCP_FORWARD_RULES="${PQTUNNEL_TCP_FORWARD_RULES:-}"
  PQTUNNEL_UDP_FORWARD_RULES="${PQTUNNEL_UDP_FORWARD_RULES:-}"
  [[ "$PQTUNNEL_ROLE" == dialer || "$PQTUNNEL_ROLE" == gateway ]] || fail 'PQTUNNEL_ROLE must be dialer or gateway'
  valid_ifname "$PQTUNNEL_TUN" || fail 'invalid PQTUNNEL_TUN interface name'
  valid_ifname "$PQTUNNEL_WAN_IF" || fail 'set PQTUNNEL_WAN_IF to the physical/WAN interface name'
}

validate_port_list() {
  local label="$1" value="$2" item first last
  [[ -z "$value" ]] && return 0
  [[ "$value" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || fail "$label must be comma-separated numeric ports or ranges, e.g. 443,8000-8010"
  IFS=',' read -r -a _ports <<< "$value"
  for item in "${_ports[@]}"; do
    first="${item%%-*}"
    if [[ "$item" == *-* ]]; then last="${item#*-}"; else last="$first"; fi
    valid_port "$first" || fail "$label contains invalid port: $first"
    valid_port "$last" || fail "$label contains invalid port: $last"
    (( 10#$first <= 10#$last )) || fail "$label contains a reversed port range: $item"
  done
}

# Parses a single mapping and sets LOCAL_PORT, TARGET_IP, TARGET_PORT, TARGET_FAMILY.
parse_forward_entry() {
  local entry="$1" left right host port
  [[ "$entry" == *=* ]] || fail "bad port-forward mapping '$entry'; use localPort=targetIP:targetPort"
  left="${entry%%=*}"; right="${entry#*=}"
  valid_port "$left" || fail "bad local port in mapping '$entry'"
  if [[ "$right" =~ ^\[([0-9a-fA-F:.]+)\]:([0-9]{1,5})$ ]]; then
    host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    [[ "$host" == *:* ]] || fail "bracketed target must be IPv6 in mapping '$entry'"
    TARGET_FAMILY=ipv6
  elif [[ "$right" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})$ ]]; then
    host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[3]}"
    valid_ipv4 "$host" || fail "invalid target IPv4 address in mapping '$entry'"
    TARGET_FAMILY=ipv4
  else
    fail "bad target in mapping '$entry'; use IPv4:port or [IPv6]:port (domain targets are not supported for DNAT)"
  fi
  valid_port "$port" || fail "bad target port in mapping '$entry'"
  LOCAL_PORT="$left"; TARGET_IP="$host"; TARGET_PORT="$port"
}

valid_ipv4() {
  local value="$1" a b c d octet
  [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r a b c d <<< "$value"
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}

validate_forward_list() {
  local label="$1" value="$2" entry
  [[ -z "$value" ]] && return 0
  IFS=',' read -r -a _maps <<< "$value"
  local seen=","
  for entry in "${_maps[@]}"; do
    parse_forward_entry "$entry"
    [[ "$seen" != *",$LOCAL_PORT,"* ]] || fail "$label repeats local port $LOCAL_PORT; use a unique local port per protocol"
    seen+="$LOCAL_PORT,"
  done
}

validate_config() {
  if [[ "$PQTUNNEL_ROLE" == dialer ]]; then
    [[ -n "$PQTUNNEL_TCP_EGRESS_PORTS$PQTUNNEL_UDP_EGRESS_PORTS$PQTUNNEL_TCP_FORWARD_RULES$PQTUNNEL_UDP_FORWARD_RULES" ]] || fail 'configure at least one egress port or port-forward mapping for the dialer role'
    validate_port_list PQTUNNEL_TCP_EGRESS_PORTS "$PQTUNNEL_TCP_EGRESS_PORTS"
    validate_port_list PQTUNNEL_UDP_EGRESS_PORTS "$PQTUNNEL_UDP_EGRESS_PORTS"
    validate_forward_list PQTUNNEL_TCP_FORWARD_RULES "$PQTUNNEL_TCP_FORWARD_RULES"
    validate_forward_list PQTUNNEL_UDP_FORWARD_RULES "$PQTUNNEL_UDP_FORWARD_RULES"
  fi
}

check_no_existing_firewall() {
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    fail 'UFW is active. No changes made; integrate rules with the existing firewall manually in a reviewed lab setup.'
  fi
  local rules
  rules="$(nft list ruleset 2>/dev/null || true)"
  if grep -Eq '^[[:space:]]*table[[:space:]]' <<< "$rules"; then
    fail 'an existing nftables table/ruleset was detected. No changes made; this helper requires a dedicated host with no existing firewall rules.'
  fi
  if command -v iptables-save >/dev/null 2>&1 && iptables-save 2>/dev/null | grep -qE '^-A[[:space:]]'; then
    fail 'existing iptables rules were detected. No changes made.'
  fi
}

check_rule_tables_free() {
  if ip -4 rule show | grep -Eq "^(${PRIO_EGRESS}|${PRIO_FORWARD}):" || ip -6 rule show | grep -Eq "^(${PRIO_EGRESS}|${PRIO_FORWARD}):"; then
    fail 'policy-routing priorities 10518/10519 are already in use; no changes made'
  fi
  [[ -z "$(ip -4 route show table "$TABLE_EGRESS" 2>/dev/null)$(ip -6 route show table "$TABLE_EGRESS" 2>/dev/null)" ]] || fail 'route table 518 is not empty; no changes made'
  [[ -z "$(ip -4 route show table "$TABLE_FORWARD" 2>/dev/null)$(ip -6 route show table "$TABLE_FORWARD" 2>/dev/null)" ]] || fail 'route table 519 is not empty; no changes made'
}

nft_port_set() {
  local value="$1"
  [[ -n "$value" ]] || return 0
  printf '{ %s }' "${value//,/ , }"
}

emit_mapping_marks() {
  local proto="$1" list="$2" entry
  [[ -n "$list" ]] || return 0
  IFS=',' read -r -a _maps <<< "$list"
  for entry in "${_maps[@]}"; do
    parse_forward_entry "$entry"
    if [[ "$TARGET_FAMILY" == ipv4 ]]; then
      printf '    iifname "%s" meta nfproto ipv4 %s dport %s meta mark set %s\n' "$PQTUNNEL_WAN_IF" "$proto" "$LOCAL_PORT" "$MARK_FORWARD"
    else
      printf '    iifname "%s" meta nfproto ipv6 %s dport %s meta mark set %s\n' "$PQTUNNEL_WAN_IF" "$proto" "$LOCAL_PORT" "$MARK_FORWARD"
    fi
  done
}

make_dialer_nft() {
  local out="$1" tcp_set udp_set
  tcp_set="$(nft_port_set "$PQTUNNEL_TCP_EGRESS_PORTS")"
  udp_set="$(nft_port_set "$PQTUNNEL_UDP_EGRESS_PORTS")"
  {
    printf 'table inet %s {\n' "$NFT_DIALER"
    printf '  chain output_route { type route hook output priority mangle; policy accept;\n'
    printf '    socket mark %s return\n' "$MARK_SOCKET"
    [[ -z "$tcp_set" ]] || printf '    meta l4proto tcp tcp dport %s meta mark set %s\n' "$tcp_set" "$MARK_EGRESS"
    [[ -z "$udp_set" ]] || printf '    meta l4proto udp udp dport %s meta mark set %s\n' "$udp_set" "$MARK_EGRESS"
    printf '  }\n'
    if [[ -n "$PQTUNNEL_TCP_FORWARD_RULES$PQTUNNEL_UDP_FORWARD_RULES" ]]; then
      printf '  chain mark_prerouting { type filter hook prerouting priority mangle; policy accept;\n'
      emit_mapping_marks tcp "$PQTUNNEL_TCP_FORWARD_RULES"
      emit_mapping_marks udp "$PQTUNNEL_UDP_FORWARD_RULES"
      printf '  }\n'
      printf '  chain dstnat_prerouting { type nat hook prerouting priority dstnat; policy accept;\n'
      # Re-render only DNAT lines; remove mark rules emitted by helper with a small direct loop.
      local proto list entry
      for proto in tcp udp; do
        if [[ "$proto" == tcp ]]; then list="$PQTUNNEL_TCP_FORWARD_RULES"; else list="$PQTUNNEL_UDP_FORWARD_RULES"; fi
        [[ -n "$list" ]] || continue
        IFS=',' read -r -a _maps <<< "$list"
        for entry in "${_maps[@]}"; do
          parse_forward_entry "$entry"
          if [[ "$TARGET_FAMILY" == ipv4 ]]; then
            printf '    iifname "%s" meta nfproto ipv4 %s dport %s dnat ip to %s:%s\n' "$PQTUNNEL_WAN_IF" "$proto" "$LOCAL_PORT" "$TARGET_IP" "$TARGET_PORT"
          else
            printf '    iifname "%s" meta nfproto ipv6 %s dport %s dnat ip6 to [%s]:%s\n' "$PQTUNNEL_WAN_IF" "$proto" "$LOCAL_PORT" "$TARGET_IP" "$TARGET_PORT"
          fi
        done
      done
      printf '  }\n'
      printf '  chain forward_filter { type filter hook forward priority filter; policy drop;\n'
      printf '    iifname "%s" oifname "%s" meta mark %s ct state { new, established, related } accept\n' "$PQTUNNEL_WAN_IF" "$PQTUNNEL_TUN" "$MARK_FORWARD"
      printf '    iifname "%s" oifname "%s" ct state { established, related } accept\n' "$PQTUNNEL_TUN" "$PQTUNNEL_WAN_IF"
      printf '  }\n'
    fi
    printf '  chain postrouting_snat { type nat hook postrouting priority srcnat; policy accept;\n'
    printf '    oifname "%s" meta mark %s ip saddr != %s snat ip to %s\n' "$PQTUNNEL_TUN" "$MARK_EGRESS" "$TUN_V4_HOST" "$TUN_V4_HOST"
    printf '    oifname "%s" meta mark %s ip6 saddr != %s snat ip6 to %s\n' "$PQTUNNEL_TUN" "$MARK_EGRESS" "$TUN_V6_HOST" "$TUN_V6_HOST"
    if [[ -n "$PQTUNNEL_TCP_FORWARD_RULES$PQTUNNEL_UDP_FORWARD_RULES" ]]; then
      printf '    oifname "%s" meta mark %s ip saddr != %s snat ip to %s\n' "$PQTUNNEL_TUN" "$MARK_FORWARD" "$TUN_V4_HOST" "$TUN_V4_HOST"
      printf '    oifname "%s" meta mark %s ip6 saddr != %s snat ip6 to %s\n' "$PQTUNNEL_TUN" "$MARK_FORWARD" "$TUN_V6_HOST" "$TUN_V6_HOST"
    fi
    printf '  }\n'
    printf '}\n'
  } > "$out"
}

write_state() {
  local role="$1" path="$2" created_tun="$3" old4="$4" old6="$5" changed4="$6" changed6="$7" added_v6="$8"
  if [[ -d "$STATE_DIR" ]]; then
    [[ "$(stat -c '%u' "$STATE_DIR")" == 0 ]] || fail "state directory is not owned by root: $STATE_DIR"
    local dirmode dirperm
    dirmode="$(stat -c '%a' "$STATE_DIR")"; dirperm=$((8#$dirmode))
    (( (dirperm & 0022) == 0 )) || fail "state directory is group/world-writable: $STATE_DIR"
  else
    install -d -o root -g root -m 0700 "$STATE_DIR"
  fi
  {
    printf 'ROLE=%q\n' "$role"
    printf 'PQTUNNEL_TUN=%q\n' "$PQTUNNEL_TUN"
    printf 'PQTUNNEL_WAN_IF=%q\n' "$PQTUNNEL_WAN_IF"
    printf 'CREATED_TUN=%q\n' "$created_tun"
    printf 'OLD_IP_FORWARD=%q\n' "$old4"
    printf 'OLD_IP6_FORWARD=%q\n' "$old6"
    printf 'CHANGED_IP_FORWARD=%q\n' "$changed4"
    printf 'CHANGED_IP6_FORWARD=%q\n' "$changed6"
    printf 'ADDED_GATEWAY_V6=%q\n' "$added_v6"
    printf 'ENABLE_EGRESS=%q\n' "$([[ -n "$PQTUNNEL_TCP_EGRESS_PORTS$PQTUNNEL_UDP_EGRESS_PORTS" ]] && echo 1 || echo 0)"
    printf 'ENABLE_FORWARD=%q\n' "$([[ -n "$PQTUNNEL_TCP_FORWARD_RULES$PQTUNNEL_UDP_FORWARD_RULES" ]] && echo 1 || echo 0)"
  } > "$path"
  chown root:root "$path"; chmod 0600 "$path"
}

remove_rules_routes() {
  local role="$1"
  if [[ "$role" == dialer ]]; then
    nft list table inet "$NFT_DIALER" >/dev/null 2>&1 && nft delete table inet "$NFT_DIALER" || true
    ip -4 rule del priority "$PRIO_EGRESS" fwmark "$MARK_EGRESS" table "$TABLE_EGRESS" 2>/dev/null || true
    ip -6 rule del priority "$PRIO_EGRESS" fwmark "$MARK_EGRESS" table "$TABLE_EGRESS" 2>/dev/null || true
    ip -4 rule del priority "$PRIO_FORWARD" fwmark "$MARK_FORWARD" table "$TABLE_FORWARD" 2>/dev/null || true
    ip -6 rule del priority "$PRIO_FORWARD" fwmark "$MARK_FORWARD" table "$TABLE_FORWARD" 2>/dev/null || true
    ip -4 route del default dev "${PQTUNNEL_TUN:-$TUN_DEFAULT}" table "$TABLE_EGRESS" 2>/dev/null || true
    ip -6 route del default dev "${PQTUNNEL_TUN:-$TUN_DEFAULT}" table "$TABLE_EGRESS" 2>/dev/null || true
    ip -4 route del default dev "${PQTUNNEL_TUN:-$TUN_DEFAULT}" table "$TABLE_FORWARD" 2>/dev/null || true
    ip -6 route del default dev "${PQTUNNEL_TUN:-$TUN_DEFAULT}" table "$TABLE_FORWARD" 2>/dev/null || true
  else
    nft list table inet "$NFT_GATEWAY" >/dev/null 2>&1 && nft delete table inet "$NFT_GATEWAY" || true
  fi
}

rollback_failed() {
  local role="$1" path="$2" old4="$3" old6="$4" changed4="$5" changed6="$6" created_tun="$7" added_v6="$8"
  remove_rules_routes "$role"
  if [[ "$added_v6" == 1 ]]; then ip -6 addr del "$TUN_V6_GATEWAY" dev "${PQTUNNEL_TUN:-$TUN_DEFAULT}" >/dev/null 2>&1 || true; fi
  if [[ "$changed4" == 1 && -n "$old4" ]]; then sysctl -w "net.ipv4.ip_forward=$old4" >/dev/null 2>&1 || true; fi
  if [[ "$changed6" == 1 && -n "$old6" ]]; then sysctl -w "net.ipv6.conf.all.forwarding=$old6" >/dev/null 2>&1 || true; fi
  if [[ "$role" == dialer && "$created_tun" == 1 ]]; then
    ip link set dev "${PQTUNNEL_TUN:-$TUN_DEFAULT}" down >/dev/null 2>&1 || true
    ip tuntap del dev "${PQTUNNEL_TUN:-$TUN_DEFAULT}" mode tun >/dev/null 2>&1 || true
  fi
  rm -f "$path"
}

apply_dialer() {
  need_root
  load_config 1; validate_config
  [[ "$PQTUNNEL_ROLE" == dialer ]] || fail 'set PQTUNNEL_ROLE=dialer in the config for dialer-up'
  command -v ip >/dev/null && command -v nft >/dev/null && command -v sysctl >/dev/null || fail 'iproute2, nftables and procps/sysctl are required'
  [[ ! -e "$DIALER_STATE" ]] || fail "state exists at $DIALER_STATE; inspect it and use dialer-down before retrying"
  if pgrep -x pqtunnel-client >/dev/null 2>&1; then fail 'pqtunnel-client is already running; stop it before changing TUN policy'; fi
  check_no_existing_firewall
  check_rule_tables_free
  ip link show dev "$PQTUNNEL_WAN_IF" >/dev/null 2>&1 || fail 'WAN interface was not found'
  if ip link show dev "$PQTUNNEL_TUN" >/dev/null 2>&1; then fail "TUN $PQTUNNEL_TUN already exists without PQTunnel state; refusing to take it over"; fi
  local needForward=0 created=1 old4 old6 changed4=0 changed6=0 tmp
  [[ -z "$PQTUNNEL_TCP_FORWARD_RULES$PQTUNNEL_UDP_FORWARD_RULES" ]] || needForward=1
  old4="$(cat /proc/sys/net/ipv4/ip_forward)"
  old6="$(cat /proc/sys/net/ipv6/conf/all/forwarding)"
  if (( needForward )); then
    [[ "$old4" == 0 && "$old6" == 0 ]] || fail 'IPv4 or IPv6 forwarding is already enabled; refusing a host that may already route traffic'
    changed4=1; changed6=1
  fi
  tmp="$(mktemp)"
  make_dialer_nft "$tmp"
  nft -c -f "$tmp" || { rm -f "$tmp"; fail 'nftables validation failed; no changes made'; }
  write_state dialer "$DIALER_STATE" "$created" "$old4" "$old6" "$changed4" "$changed6" 0
  trap 'rc=$?; trap - ERR; rollback_failed dialer "$DIALER_STATE" "$old4" "$old6" "$changed4" "$changed6" "$created" 0; rm -f "$tmp"; exit "$rc"' ERR
  ip tuntap add dev "$PQTUNNEL_TUN" mode tun
  ip addr add "$TUN_V4_DIALER" dev "$PQTUNNEL_TUN"
  ip -6 addr add "$TUN_V6_DIALER" dev "$PQTUNNEL_TUN"
  ip link set dev "$PQTUNNEL_TUN" up
  if [[ -n "$PQTUNNEL_TCP_EGRESS_PORTS$PQTUNNEL_UDP_EGRESS_PORTS" ]]; then
    ip -4 route add default dev "$PQTUNNEL_TUN" table "$TABLE_EGRESS"
    ip -6 route add default dev "$PQTUNNEL_TUN" table "$TABLE_EGRESS"
    ip -4 rule add priority "$PRIO_EGRESS" fwmark "$MARK_EGRESS" table "$TABLE_EGRESS"
    ip -6 rule add priority "$PRIO_EGRESS" fwmark "$MARK_EGRESS" table "$TABLE_EGRESS"
  fi
  if [[ -n "$PQTUNNEL_TCP_FORWARD_RULES$PQTUNNEL_UDP_FORWARD_RULES" ]]; then
    ip -4 route add default dev "$PQTUNNEL_TUN" table "$TABLE_FORWARD"
    ip -6 route add default dev "$PQTUNNEL_TUN" table "$TABLE_FORWARD"
    ip -4 rule add priority "$PRIO_FORWARD" fwmark "$MARK_FORWARD" table "$TABLE_FORWARD"
    ip -6 rule add priority "$PRIO_FORWARD" fwmark "$MARK_FORWARD" table "$TABLE_FORWARD"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
  fi
  nft -f "$tmp"
  rm -f "$tmp"
  trap - ERR
  echo 'Experimental selective policy is set on the dialer. Do not start the tunnel until certificate, prefixes and port allowlists are reviewed.'
  echo "Run pqtunnel-client with --socket-mark $MARK_SOCKET so the TLS transport bypasses destination-port marking."
}

make_gateway_nft() {
  local out="$1"
  {
    printf 'table inet %s {\n' "$NFT_GATEWAY"
    printf '  chain forward_filter { type filter hook forward priority filter; policy drop;\n'
    printf '    iifname "%s" oifname "%s" ip saddr %s ct state { new, established, related } accept\n' "$PQTUNNEL_TUN" "$PQTUNNEL_WAN_IF" "$TUN_V4_HOST/32"
    printf '    iifname "%s" oifname "%s" ip daddr %s ct state { established, related } accept\n' "$PQTUNNEL_WAN_IF" "$PQTUNNEL_TUN" "$TUN_V4_HOST/32"
    printf '    iifname "%s" oifname "%s" ip6 saddr %s ct state { new, established, related } accept\n' "$PQTUNNEL_TUN" "$PQTUNNEL_WAN_IF" "$TUN_V6_HOST/128"
    printf '    iifname "%s" oifname "%s" ip6 daddr %s ct state { established, related } accept\n' "$PQTUNNEL_WAN_IF" "$PQTUNNEL_TUN" "$TUN_V6_HOST/128"
    printf '  }\n'
    printf '  chain postrouting_snat { type nat hook postrouting priority srcnat; policy accept;\n'
    printf '    oifname "%s" ip saddr %s masquerade\n' "$PQTUNNEL_WAN_IF" "$TUN_V4_HOST/32"
    printf '    oifname "%s" ip6 saddr %s masquerade\n' "$PQTUNNEL_WAN_IF" "$TUN_V6_HOST/128"
    printf '  }\n'
    printf '}\n'
  } > "$out"
}

gateway_preflight() {
  need_root
  load_config 1; validate_config
  [[ "$PQTUNNEL_ROLE" == gateway ]] || fail 'set PQTUNNEL_ROLE=gateway in the config for gateway-preflight'
  command -v ip >/dev/null && command -v nft >/dev/null && command -v sysctl >/dev/null || fail 'iproute2, nftables and procps/sysctl are required'
  [[ ! -e "$GATEWAY_STATE" ]] || fail "state exists at $GATEWAY_STATE; inspect it before retrying"
  check_no_existing_firewall
  check_rule_tables_free
  ip link show dev "$PQTUNNEL_WAN_IF" >/dev/null 2>&1 || fail 'WAN interface was not found'
  [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == 0 && "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" == 0 ]] || fail 'IP forwarding is already enabled; refusing a host that may already route traffic'
  if ip link show dev "$PQTUNNEL_TUN" >/dev/null 2>&1; then
    fail "TUN interface $PQTUNNEL_TUN already exists; refusing to claim an unmanaged interface"
  fi
  echo 'PASS: Gateway network preflight passed; no service, route, interface, forwarding, or firewall state was changed.'
}

gateway_prepare() {
  need_root
  gateway_preflight
  [[ -d /var/lib/pqtunnel-manager && ! -L /var/lib/pqtunnel-manager ]] || fail 'manager state directory is missing or unsafe'
  [[ "$(stat -c '%u' /var/lib/pqtunnel-manager)" == 0 ]] || fail 'manager state directory is not owned by root'
  [[ "$(stat -c '%a' /var/lib/pqtunnel-manager)" == 700 || "$(stat -c '%a' /var/lib/pqtunnel-manager)" == 750 ]] || fail 'manager state directory permissions are unsafe'
  [[ ! -e "$GATEWAY_TUN_OWNER_MARKER" && ! -L "$GATEWAY_TUN_OWNER_MARKER" ]] || fail 'Gateway TUN ownership marker already exists; inspect the previous service run'
  (umask 077; : > "$GATEWAY_TUN_OWNER_MARKER")
  chown root:root "$GATEWAY_TUN_OWNER_MARKER"
  chmod 0600 "$GATEWAY_TUN_OWNER_MARKER"
  echo 'Gateway preflight passed; the upcoming pqtunneld service start owns the newly created TUN interface.'
}

gateway_cleanup() {
  need_root
  if systemctl is-active --quiet pqtunneld; then
    fail 'stop pqtunneld before Gateway network cleanup'
  fi
  if [[ -f "$GATEWAY_STATE" ]]; then
    bring_down gateway "$GATEWAY_STATE"
  fi
  if [[ -e "$GATEWAY_TUN_OWNER_MARKER" || -L "$GATEWAY_TUN_OWNER_MARKER" ]]; then
    [[ -f "$GATEWAY_TUN_OWNER_MARKER" && ! -L "$GATEWAY_TUN_OWNER_MARKER" ]] || fail 'Gateway TUN ownership marker is unsafe; refusing cleanup'
    [[ "$(stat -c '%u' "$GATEWAY_TUN_OWNER_MARKER")" == 0 ]] || fail 'Gateway TUN ownership marker is not root-owned'
    if ip link show dev "$TUN_DEFAULT" >/dev/null 2>&1; then
      ip link set dev "$TUN_DEFAULT" down 2>/dev/null || true
      ip tuntap del dev "$TUN_DEFAULT" mode tun || fail 'could not remove the TUN interface owned by the Gateway service'
    fi
    rm -f -- "$GATEWAY_TUN_OWNER_MARKER"
    echo 'Gateway-owned TUN interface and network state cleaned up.'
  fi
}

apply_gateway() {
  need_root
  load_config 1; validate_config
  [[ "$PQTUNNEL_ROLE" == gateway ]] || fail 'set PQTUNNEL_ROLE=gateway in the config for gateway-up'
  command -v ip >/dev/null && command -v nft >/dev/null && command -v sysctl >/dev/null || fail 'iproute2, nftables and procps/sysctl are required'
  [[ ! -e "$GATEWAY_STATE" ]] || fail "state exists at $GATEWAY_STATE; inspect it and use gateway-down before retrying"
  if systemctl is-active --quiet pqtunneld; then
    : # The TUN listener may be active; its device/IPv4 address are required below.
  fi
  check_no_existing_firewall
  ip link show dev "$PQTUNNEL_WAN_IF" >/dev/null 2>&1 || fail 'WAN interface was not found'
  ip link show dev "$PQTUNNEL_TUN" >/dev/null 2>&1 || fail "TUN $PQTUNNEL_TUN was not found; prepare the listener interface first"
  ip -4 addr show dev "$PQTUNNEL_TUN" | grep -q '10\.66\.0\.1/24' || fail 'listener TUN does not have 10.66.0.1/24; review the pqtunneld service first'
  if ip -6 addr show dev "$PQTUNNEL_TUN" | grep -qF "$TUN_V6_GATEWAY"; then fail "TUN already has $TUN_V6_GATEWAY without PQTunnel network state"; fi
  local old4 old6 tmp
  old4="$(cat /proc/sys/net/ipv4/ip_forward)"; old6="$(cat /proc/sys/net/ipv6/conf/all/forwarding)"
  [[ "$old4" == 0 && "$old6" == 0 ]] || fail 'IPv4 or IPv6 forwarding is already enabled; refusing a host that may already route traffic'
  tmp="$(mktemp)"
  make_gateway_nft "$tmp"
  nft -c -f "$tmp" || { rm -f "$tmp"; fail 'nftables validation failed; no changes made'; }
  write_state gateway "$GATEWAY_STATE" 0 "$old4" "$old6" 1 1 1
  trap 'rc=$?; trap - ERR; rollback_failed gateway "$GATEWAY_STATE" "$old4" "$old6" 1 1 0 1; rm -f "$tmp"; exit "$rc"' ERR
  ip -6 addr add "$TUN_V6_GATEWAY" dev "$PQTUNNEL_TUN"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
  nft -f "$tmp"
  rm -f "$tmp"
  trap - ERR
  echo 'Experimental dual-stack egress NAT is configured on the gateway. The forward chain policy is DROP and only the configured tunnel overlay is allowed.'
}

bring_down() {
  local role="$1" path="$2"
  need_root
  [[ -f "$path" && -r "$path" ]] || fail "no saved $role state ($path); nothing was changed"
  local owner mode perm
  owner="$(stat -c '%u' "$path")"; mode="$(stat -c '%a' "$path")"; perm=$((8#$mode))
  [[ "$owner" == 0 && $((perm & 0022)) -eq 0 ]] || fail 'state file ownership/permissions are unsafe; refusing rollback'
  # shellcheck source=/dev/null
  source "$path"
  if [[ "$ROLE" == dialer ]] && pgrep -x pqtunnel-client >/dev/null 2>&1; then fail 'stop pqtunnel-client before dialer-down; no changes made'; fi
  if [[ "$ROLE" == gateway ]] && systemctl is-active --quiet pqtunneld; then fail 'pqtunneld is active; stop it through your reviewed maintenance procedure before gateway-down; no changes made'; fi
  remove_rules_routes "$role"
  if [[ "${ADDED_GATEWAY_V6:-0}" == 1 ]]; then ip -6 addr del "$TUN_V6_GATEWAY" dev "$PQTUNNEL_TUN" 2>/dev/null || true; fi
  if [[ "${CHANGED_IP_FORWARD:-0}" == 1 && "${OLD_IP_FORWARD:-}" == 0 && "$(cat /proc/sys/net/ipv4/ip_forward)" == 1 ]]; then sysctl -w net.ipv4.ip_forward=0 >/dev/null; fi
  if [[ "${CHANGED_IP6_FORWARD:-0}" == 1 && "${OLD_IP6_FORWARD:-}" == 0 && "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" == 1 ]]; then sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null; fi
  if [[ "$role" == dialer && "${CREATED_TUN:-0}" == 1 ]]; then
    ip link set dev "$PQTUNNEL_TUN" down 2>/dev/null || true
    ip tuntap del dev "$PQTUNNEL_TUN" mode tun 2>/dev/null || true
  fi
  rm -f "$path"
  echo "$role selective rules removed; captured forwarding values restored when unchanged. Routes/DNS are not globally replaced by this helper."
}

MODE="${1:---help}"
case "$MODE" in
  --help|-h) usage ;;
  validate)
    load_config 0; validate_config
    echo "Config parsed successfully: role=$PQTUNNEL_ROLE wan=$PQTUNNEL_WAN_IF tun=$PQTUNNEL_TUN"
    echo "TCP egress ports: ${PQTUNNEL_TCP_EGRESS_PORTS:-none}; UDP egress ports: ${PQTUNNEL_UDP_EGRESS_PORTS:-none}"
    echo "TCP port forwards: ${PQTUNNEL_TCP_FORWARD_RULES:-none}; UDP port forwards: ${PQTUNNEL_UDP_FORWARD_RULES:-none}"
    echo 'Read-only validation only; no routes, firewall rules or services were changed.'
    ;;
  preview)
    load_config 0; validate_config
    preview_file="$(mktemp)"
    if [[ "$PQTUNNEL_ROLE" == dialer ]]; then make_dialer_nft "$preview_file"; else make_gateway_nft "$preview_file"; fi
    cat "$preview_file"
    rm -f "$preview_file"
    echo '# Preview only: no routes, firewall rules, addresses, services or sysctls were changed.'
    ;;
  status)
    ip -brief link show "$TUN_DEFAULT" 2>/dev/null || true
    ip -4 rule show; ip -6 rule show
    ip -4 route show table "$TABLE_EGRESS" 2>/dev/null || true
    ip -6 route show table "$TABLE_EGRESS" 2>/dev/null || true
    ip -4 route show table "$TABLE_FORWARD" 2>/dev/null || true
    ip -6 route show table "$TABLE_FORWARD" 2>/dev/null || true
    nft list table inet "$NFT_DIALER" 2>/dev/null || true
    nft list table inet "$NFT_GATEWAY" 2>/dev/null || true
    ;;
  dialer-up) apply_dialer ;;
  gateway-preflight) gateway_preflight ;;
  gateway-prepare) gateway_prepare ;;
  gateway-cleanup) gateway_cleanup ;;
  gateway-up) apply_gateway ;;
  dialer-down) bring_down dialer "$DIALER_STATE" ;;
  gateway-down) bring_down gateway "$GATEWAY_STATE" ;;
  *) usage >&2; fail "unknown action: $MODE" ;;
esac
