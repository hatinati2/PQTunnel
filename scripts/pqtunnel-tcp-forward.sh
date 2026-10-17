#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

CLIENT_ENV="${PQTUNNEL_TCP_FORWARD_CLIENT_ENV:-/etc/default/pqtunnel-client}"
UNIT_DIR="${PQTUNNEL_TCP_FORWARD_UNIT_DIR:-/etc/systemd/system}"
MODE="${1:-}"
[[ -n "$MODE" ]] || { echo "missing command" >&2; exit 2; }
shift

usage() {
  cat <<'USAGE'
PQTunnel optional user-space TCP forward (IPv4 only)

  sudo bash scripts/pqtunnel-tcp-forward.sh install \
    --name xray --listen-address 213.176.7.211 --listen-port 10488 \
    --target-address 10.66.0.1 --target-port 10488 [--start]

  bash scripts/pqtunnel-tcp-forward.sh install ... --dry-run
  sudo bash scripts/pqtunnel-tcp-forward.sh remove --name xray

The relay changes no routes, firewall rules, NAT, or forwarding settings.
USAGE
}
fail() { printf 'pqtunnel-tcp-forward: ERROR: %s\n' "$*" >&2; exit 1; }
need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || fail 'run install/remove as root (or use sudo).'; }

validate_policy() {
  python3 - "$CLIENT_ENV" "$1" "$2" <<'PY'
import ipaddress
import re
import sys
from pathlib import Path

path, target_text, port_text = sys.argv[1:4]
try:
    target = ipaddress.IPv4Address(target_text)
    port = int(port_text)
    text = Path(path).read_text(encoding="utf-8")
except (OSError, ValueError) as exc:
    print(f"pqtunnel-tcp-forward: ERROR: cannot validate Dialer policy: {exc}", file=sys.stderr)
    raise SystemExit(1)

values = {}
for raw in text.splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    key, value = key.strip(), value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    if key in ("PQTUNNEL_REMOTE_PREFIXES", "PQTUNNEL_ALLOWED_DST_PORTS"):
        if key in values:
            print(f"pqtunnel-tcp-forward: ERROR: duplicate {key} entries in {path}", file=sys.stderr)
            raise SystemExit(1)
        values[key] = value

remote_text = values.get("PQTUNNEL_REMOTE_PREFIXES", "")
if not remote_text:
    print("pqtunnel-tcp-forward: ERROR: PQTUNNEL_REMOTE_PREFIXES is empty; target is not guaranteed to use the tunnel", file=sys.stderr)
    raise SystemExit(1)
try:
    networks = [ipaddress.ip_network(item.strip(), strict=False) for item in remote_text.split(",")]
except ValueError as exc:
    print(f"pqtunnel-tcp-forward: ERROR: invalid CIDR in PQTUNNEL_REMOTE_PREFIXES: {exc}", file=sys.stderr)
    raise SystemExit(1)
if not any(target in network for network in networks if network.version == 4):
    print(f"pqtunnel-tcp-forward: ERROR: target {target} is outside PQTUNNEL_REMOTE_PREFIXES", file=sys.stderr)
    raise SystemExit(1)

allow_text = values.get("PQTUNNEL_ALLOWED_DST_PORTS", "")
if not allow_text:
    print("pqtunnel-tcp-forward: WARNING: PQTUNNEL_ALLOWED_DST_PORTS is empty; the client-side port filter is disabled.", file=sys.stderr)
    raise SystemExit(0)

matched = False
for raw in allow_text.split(","):
    item = raw.strip()
    parts = item.split(":", 1)
    if len(parts) != 2:
        print(f"pqtunnel-tcp-forward: ERROR: malformed PQTUNNEL_ALLOWED_DST_PORTS item: {item}", file=sys.stderr)
        raise SystemExit(1)
    proto, spec = parts[0].strip().lower(), parts[1].strip()
    if proto != "tcp":
        continue
    bounds = spec.split("-", 1)
    if not all(re.fullmatch(r"[0-9]{1,5}", bound) for bound in bounds):
        print(f"pqtunnel-tcp-forward: ERROR: malformed TCP port rule: {item}", file=sys.stderr)
        raise SystemExit(1)
    nums = [int(bound) for bound in bounds]
    if any(n < 1 or n > 65535 for n in nums) or nums[0] > nums[-1]:
        print(f"pqtunnel-tcp-forward: ERROR: invalid TCP port range: {item}", file=sys.stderr)
        raise SystemExit(1)
    if nums[0] <= port <= nums[-1]:
        matched = True
if not matched:
    print(f"pqtunnel-tcp-forward: ERROR: TCP/{port} is not allowed by the Dialer PQTUNNEL_ALLOWED_DST_PORTS; allow it on both endpoints", file=sys.stderr)
    raise SystemExit(1)
PY
}

valid_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

managed_unit_marker() {
  [[ -f "$1" ]] && grep -Fqx '# Managed by scripts/pqtunnel-tcp-forward.sh' "$1"
}

install_forward() {
  local name="" listen_address="" listen_port="" target_address="" target_port=""
  local start=0 dry_run=0 arg tunnel_unit="" socat_bin="" unit_name="" unit_file=""
  while (($#)); do
    arg="$1"; shift
    case "$arg" in
      --name) (($#)) || fail '--name requires a value'; name="$1"; shift ;;
      --listen-address) (($#)) || fail '--listen-address requires a value'; listen_address="$1"; shift ;;
      --listen-port) (($#)) || fail '--listen-port requires a value'; listen_port="$1"; shift ;;
      --target-address) (($#)) || fail '--target-address requires a value'; target_address="$1"; shift ;;
      --target-port) (($#)) || fail '--target-port requires a value'; target_port="$1"; shift ;;
      --start) start=1 ;;
      --dry-run) dry_run=1 ;;
      --help|-h) usage; return 0 ;;
      *) fail "unknown install option: $arg" ;;
    esac
  done

  [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || fail 'name must be lowercase letters, digits, and hyphens (max 32 chars)'
  [[ -n "$listen_address" && -n "$target_address" ]] || fail 'listen and target IPv4 addresses are required'
  valid_port "$listen_port" || fail 'listen port must be an integer from 1 to 65535'
  valid_port "$target_port" || fail 'target port must be an integer from 1 to 65535'
  python3 - "$listen_address" "$target_address" <<'PY'
import ipaddress
import sys
for value in sys.argv[1:]:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        print(f"pqtunnel-tcp-forward: ERROR: IPv4 literal required: {value}", file=sys.stderr)
        raise SystemExit(1)
PY
  local cmd
  for cmd in python3 ip ss systemctl; do command -v "$cmd" >/dev/null 2>&1 || fail "required command not found: $cmd"; done
  socat_bin="$(command -v socat || true)"
  [[ -n "$socat_bin" && "$socat_bin" == /* ]] || fail 'socat is not installed; install the OS socat package first'
  [[ -r "$CLIENT_ENV" ]] || fail "Dialer config not readable: $CLIENT_ENV"
  validate_policy "$target_address" "$target_port"

  if ! ip -o -4 addr show | awk '{for (i=1; i<NF; i++) if ($i=="inet") {split($(i+1), a, "/"); print a[1]}}' | grep -Fxq "$listen_address"; then
    fail "listen address $listen_address is not assigned to a local interface; use the guest/local interface address, not an unassigned provider NAT address"
  fi
  if ss -H -ltn "( sport = :$listen_port )" 2>/dev/null | grep -q .; then
    fail "TCP/$listen_port already has a listener; nothing was changed"
  fi

  local active_units=() installed_units=() unit
  for unit in pqtunnel-client-transport.service pqtunnel-client.service; do
    if systemctl is-active --quiet "$unit"; then active_units+=("$unit"); fi
    if systemctl cat "$unit" >/dev/null 2>&1; then installed_units+=("$unit"); fi
  done
  if ((${#active_units[@]} > 1)); then
    fail 'multiple PQTunnel client services are active; resolve this before adding a forward'
  elif ((${#active_units[@]} == 1)); then
    tunnel_unit="${active_units[0]}"
  elif ((${#installed_units[@]} == 1)); then
    tunnel_unit="${installed_units[0]}"
  elif ((${#installed_units[@]} > 1)); then
    tunnel_unit="pqtunnel-client-transport.service"
  else
    fail 'no supported PQTunnel Dialer unit found (expected pqtunnel-client-transport.service or pqtunnel-client.service)'
  fi

  unit_name="pqtunnel-tcp-forward-${name}.service"
  unit_file="$UNIT_DIR/$unit_name"
  if (( ! dry_run )); then
    need_root
    [[ ! -e "$unit_file" ]] || fail "$unit_file already exists; refusing to overwrite"
    command -v systemd-analyze >/dev/null 2>&1 || fail 'systemd-analyze is required'
    if (( start )) && ! systemctl is-active --quiet "$tunnel_unit"; then
      fail "$tunnel_unit is not active; start and verify the tunnel first. No files were written"
    fi
  fi

  local unit_text
  unit_text="$(cat <<EOF
# Managed by scripts/pqtunnel-tcp-forward.sh
[Unit]
Description=PQTunnel managed TCP forward ${name} (${listen_port} -> ${target_address}:${target_port})
Documentation=https://github.com/hatinati2/PQTunnel
Requires=${tunnel_unit}
After=network-online.target ${tunnel_unit}
PartOf=${tunnel_unit}

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=${socat_bin} TCP-LISTEN:${listen_port},bind=${listen_address},reuseaddr,fork TCP:${target_address}:${target_port}
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
)"

  if (( dry_run )); then
    printf '%s\n' "$unit_text"
    printf '\nDry run only: no unit file or systemd state was changed.\n'
    return 0
  fi

  install -d -o root -g root -m 0755 "$UNIT_DIR"
  local tmp
  tmp="$(mktemp "$UNIT_DIR/.${unit_name}.XXXXXX")"
  printf '%s\n' "$unit_text" > "$tmp"
  chown root:root "$tmp"
  chmod 0644 "$tmp"
  mv "$tmp" "$unit_file"
  if ! systemctl daemon-reload || ! systemd-analyze verify "$unit_file"; then
    rm -f "$unit_file"
    systemctl daemon-reload || true
    fail 'generated systemd unit failed validation; the generated unit was removed'
  fi

  if (( start )); then
    if ! systemctl enable --now "$unit_name"; then
      printf 'The unit was created but did not start; inspect: systemctl status %s\n' "$unit_name" >&2
      exit 1
    fi
    printf 'Enabled and started %s\n' "$unit_name"
  else
    printf 'Created %s but did not start it.\n' "$unit_name"
    printf 'After reviewing the exposure, start it with: sudo systemctl enable --now %s\n' "$unit_name"
  fi
  printf 'Check with: sudo systemctl --no-pager --full status %s\n' "$unit_name"
}

remove_forward() {
  local name="" arg unit_name unit_file
  while (($#)); do
    arg="$1"; shift
    case "$arg" in
      --name) (($#)) || fail '--name requires a value'; name="$1"; shift ;;
      --help|-h) usage; return 0 ;;
      *) fail "unknown remove option: $arg" ;;
    esac
  done
  [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || fail 'valid --name is required'
  need_root
  unit_name="pqtunnel-tcp-forward-${name}.service"
  unit_file="$UNIT_DIR/$unit_name"
  managed_unit_marker "$unit_file" || fail "$unit_file is missing or was not created by this helper; refusing to remove it"
  systemctl disable --now "$unit_name" >/dev/null 2>&1 || true
  systemctl stop "$unit_name" >/dev/null 2>&1 || true
  rm -f "$unit_file"
  systemctl daemon-reload
  systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
  printf 'Removed managed unit %s. Firewall rules and tunnel configuration were not changed.\n' "$unit_name"
}

case "$MODE" in
  install) install_forward "$@" ;;
  remove) remove_forward "$@" ;;
  --help|-h|help) usage ;;
  *) usage >&2; fail "unknown command: $MODE" ;;
esac
