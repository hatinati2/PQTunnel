#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "Usage: bash scripts/build-release-bundles.sh VERSION OUTPUT_DIR" >&2
}

fail() {
  echo "release bundle validation failed: $*" >&2
  exit 1
}

[[ $# -eq 2 ]] || { usage; exit 2; }
VERSION="$1"
DIST_INPUT="$2"
[[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail "invalid bundle version string"
[[ -n "$DIST_INPUT" ]] || { usage; exit 2; }

ROOT="$(cd -- "$(dirname -- "$BASH_SOURCE")/.." && pwd -P)"
cd "$ROOT"
[[ -f go.mod && -d cmd && -d scripts && -d deploy && -d docs ]] || fail "run from a complete repository checkout"
command -v go >/dev/null 2>&1 || fail "Go is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
command -v grep >/dev/null 2>&1 || fail "grep is required"

mkdir -p -- "$DIST_INPUT"
DIST_DIR="$(cd -- "$DIST_INPUT" && pwd -P)"
[[ "$DIST_DIR" != "/" && "$DIST_DIR" != "$ROOT" ]] || fail "refusing unsafe output directory: $DIST_DIR"

# Clear only artifacts for this requested version. This also prevents a stale
# Windows archive from surviving a re-run in an existing output directory.
rm -f -- "$DIST_DIR"/"PQTunnel-${VERSION}-"*.tar.gz "$DIST_DIR/SHA256SUMS"

declare -A PKG_BY_ARCH
for goarch in amd64 arm64; do
  pkg="PQTunnel-${VERSION}-linux-${goarch}"
  PKG_BY_ARCH["$goarch"]="$pkg"
  staging="$DIST_DIR/$pkg"
  rm -rf -- "$staging"
  mkdir -p -- "$staging"

  for cmd in pqtunneld pqtunnel-client pqtunnel-pki pqtunnel-proxy; do
    GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
      go build -trimpath -ldflags='-s -w' -o "$staging/$cmd" "./cmd/$cmd"
  done
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
    go build -trimpath -ldflags='-s -w' -o "$staging/pqtunnel-manager" ./cmd/pqtunnel-manager

  cp README.md README.fa.md SECURITY.md LICENSE CHANGELOG.md "$staging/"
  cp -R scripts deploy docs "$staging/"
  archive="$DIST_DIR/${pkg}.tar.gz"
  tar -C "$DIST_DIR" -czf "$archive" "$pkg"
  rm -rf -- "$staging"
done

PKG_AMD64="${PKG_BY_ARCH[amd64]}"
PKG_ARM64="${PKG_BY_ARCH[arm64]}"
(
  cd "$DIST_DIR"
  sha256sum "./${PKG_AMD64}.tar.gz" "./${PKG_ARM64}.tar.gz" > SHA256SUMS
  sha256sum --check SHA256SUMS
)

shopt -s nullglob
release_archives=("$DIST_DIR"/"PQTunnel-${VERSION}-"*.tar.gz)
[[ ${#release_archives[@]} -eq 2 ]] || fail "expected exactly two Linux release archives, found ${#release_archives[@]}"
[[ ! -e "$DIST_DIR/PQTunnel-${VERSION}-windows-amd64.tar.gz" ]] || fail "unsupported Windows release archive was created"

validate_archive() {
  local arch="$1" pkg="$2" archive="$DIST_DIR/${pkg}.tar.gz" archive_list relative
  [[ -s "$archive" ]] || fail "missing or empty archive: $archive"
  archive_list="$(tar -tzf "$archive")" || fail "cannot inspect archive: $archive"
  for relative in \
    pqtunneld pqtunnel-client pqtunnel-pki pqtunnel-proxy pqtunnel-manager \
    README.md README.fa.md SECURITY.md LICENSE CHANGELOG.md \
    scripts/site-to-site-preflight.sh scripts/site-to-site-selective.sh \
    deploy/systemd/pqtunnel-manager.service docs/LINUX-MVP-RELEASE-GATE.md; do
    grep -Fxq "${pkg}/${relative}" <<<"$archive_list" || fail "$arch bundle is missing ${relative}"
  done
  if grep -Fq "${pkg}/PQTunnel/" <<<"$archive_list"; then
    fail "$arch bundle contains the stale nested PQTunnel/ tree"
  fi
  if grep -Eq '\\.exe$' <<<"$archive_list"; then
    fail "$arch bundle unexpectedly contains Windows executables"
  fi
  echo "PASS: ${arch} release archive contains required Linux binaries and documentation."
}

validate_archive "linux/amd64" "$PKG_AMD64"
validate_archive "linux/arm64" "$PKG_ARM64"

SMOKE_TMP="$(mktemp -d -t pqtunnel-release-smoke.XXXXXX)"
trap 'rm -rf -- "$SMOKE_TMP"' EXIT
tar -xzf "$DIST_DIR/${PKG_AMD64}.tar.gz" -C "$SMOKE_TMP"
BIN_DIR="$SMOKE_TMP/$PKG_AMD64"
for binary in pqtunneld pqtunnel-client pqtunnel-pki pqtunnel-proxy pqtunnel-manager; do
  [[ -x "$BIN_DIR/$binary" ]] || fail "amd64 bundle binary is not executable: $binary"
done

"$BIN_DIR/pqtunneld" -h >/dev/null 2>&1
"$BIN_DIR/pqtunnel-client" -h >/dev/null 2>&1
"$BIN_DIR/pqtunnel-proxy" -h >/dev/null 2>&1
if "$BIN_DIR/pqtunnel-pki" >"$SMOKE_TMP/pki.log" 2>&1; then
  fail "pqtunnel-pki unexpectedly succeeded without a subcommand"
fi
grep -Fq "usage:" "$SMOKE_TMP/pki.log" || fail "pqtunnel-pki did not report its usage"
if env -i PATH="$PATH" "$BIN_DIR/pqtunnel-manager" >"$SMOKE_TMP/manager.log" 2>&1; then
  fail "pqtunnel-manager unexpectedly ran without its required role"
fi
grep -Fq "PQTUNNEL_MANAGER_ROLE must be gateway or dialer" "$SMOKE_TMP/manager.log" || fail "pqtunnel-manager did not reject missing role configuration"

echo "PASS: Linux amd64 bundle binaries start with the expected CLI/configuration behavior."
echo "PASS: release bundles verified for VERSION=$VERSION."
