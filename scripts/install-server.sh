#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Install PQTunnel server files on Ubuntu from either a source checkout or a matching Linux release bundle.
The installer does not change firewall rules, IPv4 forwarding, NAT, or routes.

Usage:
  sudo ./scripts/install-server.sh --source /path/to/extracted/PQTunnel --pki /path/to/server-pki [--enable]

--source may be a source checkout (contains go.mod and cmd/pqtunneld) or a release bundle
(containing pqtunneld, scripts/, deploy/, and docs/). For release bundles, use the asset
that matches the server architecture (Linux amd64 or Linux arm64).

The PKI directory must contain server.crt, server.key, and ca.crt. Do NOT place ca.key
on the server. --enable starts and enables the systemd unit; without it, the service
is installed but remains stopped/disabled.

This installer refuses to overwrite a detected existing installation. It is not an upgrader.
USAGE
}
fail() { echo "pqtunnel installer: $*" >&2; exit 1; }

SOURCE=""
PKI=""
ENABLE=0
while (($#)); do
  case "$1" in
    --source) SOURCE="${2:?missing source path}"; shift 2 ;;
    --pki) PKI="${2:?missing PKI path}"; shift 2 ;;
    --enable) ENABLE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || fail 'run this installer with sudo on the Ubuntu server.'
[[ -n "$SOURCE" && -d "$SOURCE" ]] || fail '--source must point to an extracted source tree or Linux release bundle.'
[[ -n "$PKI" && -d "$PKI" ]] || fail '--pki must point to a private directory containing server certificates.'
[[ -f "$SOURCE/deploy/systemd/pqtunneld.service" ]] || fail 'deploy/systemd/pqtunneld.service is missing under --source.'
for f in server.crt server.key ca.crt; do
  [[ -s "$PKI/$f" ]] || fail "missing or empty PKI file: $PKI/$f"
done
[[ ! -e "$PKI/ca.key" ]] || fail 'ca.key is present in the server PKI directory. Keep the CA private key offline and remove it from this directory.'
command -v openssl >/dev/null || fail 'openssl is required to validate the server certificate and key; no files were installed.'
command -v systemctl >/dev/null || fail 'systemd is required by this installer.'
command -v ip >/dev/null || fail 'iproute2 is required by the systemd unit.'
[[ -c /dev/net/tun ]] || fail '/dev/net/tun is unavailable; no files were installed.'

# Validate that the certificate chains to the provided CA and matches the private key.
openssl x509 -in "$PKI/server.crt" -noout >/dev/null || fail 'server.crt is not a valid PEM certificate.'
openssl pkey -in "$PKI/server.key" -noout >/dev/null || fail 'server.key is not a valid PEM private key.'
openssl verify -purpose sslserver -CAfile "$PKI/ca.crt" "$PKI/server.crt" >/dev/null || fail 'server.crt does not validate against ca.crt for TLS server use.'
CERT_PUB="$(openssl x509 -in "$PKI/server.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print $1}')"
KEY_PUB="$(openssl pkey -in "$PKI/server.key" -pubout -outform DER | sha256sum | awk '{print $1}')"
[[ "$CERT_PUB" == "$KEY_PUB" ]] || fail 'server.key does not match server.crt.'

# Do not silently replace a previous install or its certificates/unit.
for path in /usr/local/sbin/pqtunneld /etc/systemd/system/pqtunneld.service /etc/pqtunnel/pki/server.key; do
  [[ ! -e "$path" ]] || fail "existing installation artifact detected at $path; refusing to overwrite it. Review/update manually with a backup."
done

BIN_SOURCE=""
TMPBIN=""
if [[ -f "$SOURCE/go.mod" ]]; then
  command -v go >/dev/null || fail 'Go 1.24+ is required to build from source. Use a matching Linux release bundle if Go is not installed.'
  GV="$(go env GOVERSION | sed 's/^go//')"
  if ! awk -v v="$GV" 'BEGIN { split(v,a,"."); exit !((a[1]+0)>1 || ((a[1]+0)==1 && (a[2]+0)>=24)) }'; then
    fail "Go 1.24+ is required; found $GV. No automatic toolchain installation is performed."
  fi
  [[ -f "$SOURCE/cmd/pqtunneld/main.go" ]] || fail 'cmd/pqtunneld/main.go is missing from source tree.'
  TMPBIN="$(mktemp)"
  trap '[[ -z "$TMPBIN" ]] || rm -f "$TMPBIN"' EXIT
  (
    cd "$SOURCE"
    GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$TMPBIN" ./cmd/pqtunneld
  )
  BIN_SOURCE="$TMPBIN"
elif [[ -f "$SOURCE/pqtunneld" ]]; then
  # Release packages are named ...-linux-amd64 or ...-linux-arm64. Verify the target before install.
  HOST_ARCH="$(uname -m)"
  case "$HOST_ARCH" in
    x86_64) HOST_ARCH="amd64" ;;
    aarch64|arm64) HOST_ARCH="arm64" ;;
    *) fail "unsupported Linux host architecture: $HOST_ARCH" ;;
  esac
  PACKAGE_NAME="$(basename "$SOURCE")"
  if [[ "$PACKAGE_NAME" =~ -linux-(amd64|arm64)$ ]]; then
    PACKAGE_ARCH="${BASH_REMATCH[1]}"
  elif command -v file >/dev/null; then
    DESCRIPTION="$(file -b "$SOURCE/pqtunneld")"
    case "$DESCRIPTION" in
      *"x86-64"*) PACKAGE_ARCH="amd64" ;;
      *"ARM aarch64"*) PACKAGE_ARCH="arm64" ;;
      *) fail "cannot verify release binary architecture ($DESCRIPTION); use the original ...-linux-amd64 or ...-linux-arm64 directory name." ;;
    esac
  else
    fail 'cannot verify the prebuilt binary architecture. Keep the original ...-linux-amd64 or ...-linux-arm64 directory name.'
  fi
  [[ "$PACKAGE_ARCH" == "$HOST_ARCH" ]] || fail "release package architecture is $PACKAGE_ARCH but this host is $HOST_ARCH. Download the matching Linux asset."
  BIN_SOURCE="$SOURCE/pqtunneld"
else
  fail '--source must contain go.mod (source checkout) or pqtunneld (Linux release bundle).'
fi

install -d -o root -g root -m 0750 /etc/pqtunnel /etc/pqtunnel/pki /var/lib/pqtunnel
install -o root -g root -m 0755 "$BIN_SOURCE" /usr/local/sbin/pqtunneld
install -o root -g root -m 0644 "$PKI/server.crt" /etc/pqtunnel/pki/server.crt
install -o root -g root -m 0600 "$PKI/server.key" /etc/pqtunnel/pki/server.key
install -o root -g root -m 0644 "$PKI/ca.crt" /etc/pqtunnel/pki/ca.crt
install -o root -g root -m 0644 "$SOURCE/deploy/systemd/pqtunneld.service" /etc/systemd/system/pqtunneld.service

if [[ ! -e /etc/default/pqtunneld ]]; then
  cat > /etc/default/pqtunneld <<'ENV'
# PQTunnel server settings. Review before enabling the service.
PQTUNNEL_LISTEN=0.0.0.0:8443
PQTUNNEL_TLS_CERT=/etc/pqtunnel/pki/server.crt
PQTUNNEL_TLS_KEY=/etc/pqtunnel/pki/server.key
PQTUNNEL_CLIENT_CA=/etc/pqtunnel/pki/ca.crt
PQTUNNEL_MAX_CLIENTS=128
# For a single site-to-site peer, set both values and set MAX_CLIENTS=1.
PQTUNNEL_PEER_PREFIXES=
PQTUNNEL_LOCAL_PREFIXES=
PQTUNNEL_PEER_NAME=
ENV
  chown root:root /etc/default/pqtunneld
  chmod 0640 /etc/default/pqtunneld
fi
systemctl daemon-reload

# The temporary build has served its purpose; leave no generated binary behind.
if [[ -n "$TMPBIN" ]]; then rm -f "$TMPBIN"; TMPBIN=""; fi

echo 'PQTunnel server binary, validated PKI files and systemd unit installed.'
echo 'No firewall, NAT, IP-forwarding, or route settings were changed.'
if (( ENABLE )); then
  systemctl enable --now pqtunneld
  echo 'pqtunneld is enabled and started. Network forwarding/NAT remains a separate, reviewed step.'
else
  echo 'Service was NOT started. Review /etc/default/pqtunneld before deciding whether to start it.'
  echo 'This installer does not configure the provider firewall or open TCP port 8443.'
fi
