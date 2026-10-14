#!/usr/bin/env bash
set -Eeuo pipefail
: "${PQTUNNEL_SERVER:?PQTUNNEL_SERVER must be configured in /etc/default/pqtunnel-client}"
: "${PQTUNNEL_SERVER_NAME:?PQTUNNEL_SERVER_NAME must be configured in /etc/default/pqtunnel-client}"
: "${PQTUNNEL_LOCAL_PREFIXES:?PQTUNNEL_LOCAL_PREFIXES must be configured in /etc/default/pqtunnel-client}"
: "${PQTUNNEL_REMOTE_PREFIXES:?PQTUNNEL_REMOTE_PREFIXES must be configured in /etc/default/pqtunnel-client}"
: "${PQTUNNEL_ALLOWED_DST_PORTS:?PQTUNNEL_ALLOWED_DST_PORTS must be configured in /etc/default/pqtunnel-client}"
exec /usr/local/bin/pqtunnel-client \
  --server "$PQTUNNEL_SERVER" \
  --server-name "$PQTUNNEL_SERVER_NAME" \
  --ca /etc/pqtunnel/pki/ca.crt \
  --cert /etc/pqtunnel/pki/client.crt \
  --key /etc/pqtunnel/pki/client.key \
  --local-prefixes "$PQTUNNEL_LOCAL_PREFIXES" \
  --remote-prefixes "$PQTUNNEL_REMOTE_PREFIXES" \
  --allowed-dst-ports "$PQTUNNEL_ALLOWED_DST_PORTS" \
  --socket-mark 20560
