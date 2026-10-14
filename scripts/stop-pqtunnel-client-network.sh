#!/usr/bin/env bash
set -Eeuo pipefail
HELPER=/usr/local/lib/pqtunnel/site-to-site-selective.sh
STATE=/var/lib/pqtunnel/site-selective-dialer.state
if [[ -f "$STATE" ]]; then
  exec "$HELPER" dialer-down
fi
exit 0
