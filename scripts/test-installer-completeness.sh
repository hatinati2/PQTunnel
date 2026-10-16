#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SERVICE=deploy/systemd/pqtunnel-client.service
BOOTSTRAP=scripts/pqtunnel-bootstrap.sh
STOP_HELPER=scripts/stop-pqtunnel-client-network.sh
RUN_HELPER=scripts/run-pqtunnel-client.sh
NETWORK_HELPER=scripts/site-to-site-selective.sh

[[ -s "$SERVICE" ]] || { echo "Missing client systemd unit" >&2; exit 1; }
[[ -s "$BOOTSTRAP" ]] || { echo "Missing bootstrap installer" >&2; exit 1; }
[[ -s "$STOP_HELPER" ]] || { echo "Missing client stop helper source" >&2; exit 1; }
[[ -s "$RUN_HELPER" ]] || { echo "Missing client run helper source" >&2; exit 1; }
[[ -s "$NETWORK_HELPER" ]] || { echo "Missing client network helper source" >&2; exit 1; }

grep -Fxq 'ExecStartPre=/usr/local/lib/pqtunnel/site-to-site-selective.sh dialer-up' "$SERVICE"
grep -Fxq 'ExecStart=/usr/local/lib/pqtunnel/run-client.sh' "$SERVICE"
grep -Fxq 'ExecStopPost=/usr/local/lib/pqtunnel/stop-client-network.sh' "$SERVICE"

grep -Fq 'scripts/site-to-site-selective.sh' "$BOOTSTRAP"
grep -Fq 'scripts/run-pqtunnel-client.sh' "$BOOTSTRAP"
grep -Fq 'scripts/stop-pqtunnel-client-network.sh' "$BOOTSTRAP"
grep -Fq ' /usr/local/lib/pqtunnel/stop-client-network.sh' "$BOOTSTRAP"

echo "PASS: client installer stages every helper referenced by its systemd unit."
