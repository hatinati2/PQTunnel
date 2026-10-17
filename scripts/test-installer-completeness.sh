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



# The module's Go directive is the minimum build toolchain. Every source-building
# installer must reject older local toolchains before invoking go build.
GO_DIRECTIVE="$(sed -n 's/^go //p' go.mod | head -n1)"
if [[ "$GO_DIRECTIVE" =~ ^1\.([0-9]+)\.[0-9]+$ ]]; then
  MIN_GO_MINOR="${BASH_REMATCH[1]}"
else
  echo "Unexpected Go directive in go.mod: $GO_DIRECTIVE" >&2
  exit 1
fi
for installer in scripts/install-server.sh scripts/install-manager.sh scripts/pqtunnel-bootstrap.sh; do
  grep -Fq "Go 1.${MIN_GO_MINOR}+ is required" "$installer" || {
    echo "Toolchain error message is out of sync with go.mod: $installer" >&2
    exit 1
  }
  grep -Fq "a[2]+0)>=${MIN_GO_MINOR}" "$installer" || {
    echo "Toolchain version guard is out of sync with go.mod: $installer" >&2
    exit 1
  }
done

# Keep the standalone setup helper's fallback release aligned with the one-line installer.
# The installer passes this version explicitly; the fallback matters for direct invocation.
INSTALLER_VERSION="$(sed -n 's/^VERSION="\\([^"]*\\)"$/\\1/p' install.sh | head -n1)"
SETUP_DEFAULT_VERSION="$(sed -n 's/^VERSION="${PQTUNNEL_SETUP_VERSION:-\\([^}]*\\)}"$/\\1/p' scripts/pqtunnel-site-to-site-setup.sh | head -n1)"
if [[ -z "$INSTALLER_VERSION" || "$SETUP_DEFAULT_VERSION" != "$INSTALLER_VERSION" ]]; then
  echo "Setup helper default version is out of sync with install.sh" >&2
  exit 1
fi

echo "PASS: client installer stages every helper referenced by its systemd unit."
