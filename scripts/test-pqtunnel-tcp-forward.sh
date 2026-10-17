#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/bin"
SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pqtunnel-tcp-forward.sh"

cat > "$ROOT/bin/ip" <<'EOF'
#!/usr/bin/env bash
printf '2: ens192 inet 192.0.2.20/32 scope global ens192\n'
EOF
cat > "$ROOT/bin/ss" <<'EOF'
#!/usr/bin/env bash
if [[ "${FAKE_SS_BUSY:-0}" == 1 ]]; then
  printf 'LISTEN 0 128 192.0.2.10:10488 0.0.0.0:*\n'
fi
EOF
cat > "$ROOT/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  is-active)
    [[ "${3:-}" == pqtunnel-client-transport.service && "${FAKE_TUNNEL_ACTIVE:-1}" == 1 ]]
    ;;
  cat)
    [[ "${2:-}" == pqtunnel-client-transport.service ]]
    ;;
  *) exit 0 ;;
esac
EOF
cat > "$ROOT/bin/socat" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$ROOT/bin/"*
cat > "$ROOT/client.env" <<'EOF'
PQTUNNEL_REMOTE_PREFIXES=10.66.0.1/32,fd42:7061:7475::1/128
PQTUNNEL_ALLOWED_DST_PORTS=tcp:10488
EOF

export PATH="$ROOT/bin:$PATH"
export PQTUNNEL_TCP_FORWARD_CLIENT_ENV="$ROOT/client.env"
ARGS=(install --name xray --listen-address 192.0.2.10 --listen-port 10488 --target-address 10.66.0.1 --target-port 10488 --dry-run)

bash "$SCRIPT" "${ARGS[@]}" > "$ROOT/valid.out"
grep -Fq 'Requires=pqtunnel-client-transport.service' "$ROOT/valid.out"
grep -Fq 'TCP-LISTEN:10488,bind=192.0.2.10,reuseaddr,fork TCP:10.66.0.1:10488' "$ROOT/valid.out"
grep -Fq 'Dry run only: no unit file or systemd state was changed.' "$ROOT/valid.out"

cat > "$ROOT/client.env" <<'EOF'
PQTUNNEL_REMOTE_PREFIXES=10.66.0.1/32
PQTUNNEL_ALLOWED_DST_PORTS=tcp:443
EOF
if bash "$SCRIPT" "${ARGS[@]}" > /dev/null 2> "$ROOT/port.err"; then
  echo "test failure: disallowed destination port was accepted" >&2
  exit 1
fi
grep -Fq 'TCP/10488 is not allowed' "$ROOT/port.err"

cat > "$ROOT/client.env" <<'EOF'
PQTUNNEL_REMOTE_PREFIXES=10.66.0.99/32
PQTUNNEL_ALLOWED_DST_PORTS=tcp:10488
EOF
if bash "$SCRIPT" "${ARGS[@]}" > /dev/null 2> "$ROOT/prefix.err"; then
  echo "test failure: target outside remote prefixes was accepted" >&2
  exit 1
fi
grep -Fq 'outside PQTUNNEL_REMOTE_PREFIXES' "$ROOT/prefix.err"

cat > "$ROOT/client.env" <<'EOF'
PQTUNNEL_REMOTE_PREFIXES=10.66.0.1/32
PQTUNNEL_ALLOWED_DST_PORTS=
EOF
if bash "$SCRIPT" "${ARGS[@]}" > /dev/null 2> "$ROOT/empty-allow.err"; then
  echo "test failure: empty destination allowlist was accepted" >&2
  exit 1
fi
grep -Fq 'must explicitly allow the target TCP port' "$ROOT/empty-allow.err"

cat > "$ROOT/client.env" <<'EOF'
PQTUNNEL_REMOTE_PREFIXES=10.66.0.1/32
PQTUNNEL_ALLOWED_DST_PORTS=tcp:10488
EOF
if FAKE_SS_BUSY=1 bash "$SCRIPT" "${ARGS[@]}" > /dev/null 2> "$ROOT/busy.err"; then
  echo "test failure: busy listener port was accepted" >&2
  exit 1
fi
grep -Fq 'already has a listener' "$ROOT/busy.err"

echo "PQTunnel TCP-forward validation/dry-run tests passed."
