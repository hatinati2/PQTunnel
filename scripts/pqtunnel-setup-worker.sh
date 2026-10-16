#!/usr/bin/env bash
# Privileged worker for the authenticated, loopback-only graphical setup wizard.
# It runs exactly the repository's fixed site-to-site setup script with validated
# line-oriented input, never a browser-provided command.
set -Eeuo pipefail
umask 077

STATE_DIR=/var/lib/pqtunnel-manager
SCRIPT=/usr/local/lib/pqtunnel/pqtunnel-site-to-site-setup.sh
ENV_FILE=/var/lib/pqtunnel-manager/setup.env
RAW_LOG=/var/lib/pqtunnel-manager/setup-raw.log
SAFE_LOG=/var/lib/pqtunnel-manager/setup.log
STATE_FILE=/var/lib/pqtunnel-manager/setup-state
TOKEN_FILE=/var/lib/pqtunnel-manager/setup-tokens
INPUT_FILE=

write_state() {
  local state="$1" tmp
  tmp="$(mktemp "$STATE_DIR/.setup-state.XXXXXX")"
  printf '%s\n' "$state" > "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$STATE_FILE"
}
extract_tokens() {
  local dialer gateway speed
  dialer="$(sed -nE 's/^Iran\/Dialer manager token: ([0-9a-f]{64})$/\1/p' "$RAW_LOG" | tail -n1)"
  gateway="$(sed -nE 's/^Germany\/Gateway manager token: ([0-9a-f]{64})$/\1/p' "$RAW_LOG" | tail -n1)"
  speed="$(sed -nE 's/^Shared speed-test token: ([0-9a-f]{64})$/\1/p' "$RAW_LOG" | tail -n1)"
  if [[ -n "$dialer$gateway$speed" ]]; then
    local tmp
    tmp="$(mktemp "$STATE_DIR/.setup-tokens.XXXXXX")"
    [[ -z "$dialer" ]] || printf 'DIALER_TOKEN=%s\n' "$dialer" >> "$tmp"
    [[ -z "$gateway" ]] || printf 'GATEWAY_TOKEN=%s\n' "$gateway" >> "$tmp"
    [[ -z "$speed" ]] || printf 'SPEEDTEST_TOKEN=%s\n' "$speed" >> "$tmp"
    chmod 0600 "$tmp"
    mv -f "$tmp" "$TOKEN_FILE"
  fi
  unset dialer gateway speed
}
sanitize_log() {
  local tmp
  tmp="$(mktemp "$STATE_DIR/.setup-log.XXXXXX")"
  sed -E \
    -e '/^(Iran\/Dialer manager token|Germany\/Gateway manager token|Shared speed-test token): /s/: .*/: [REDACTED]/' \
    -e '/PQTUNNEL_MANAGER_TOKEN=/s/=.*/=[REDACTED]/' \
    -e '/PRIVATE KEY|-----BEGIN/s/.*/[redacted sensitive setup output]/' \
    "$RAW_LOG" > "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$SAFE_LOG"
  rm -f "$RAW_LOG"
}
finalize() {
  local status="$1"
  if [[ -f "$RAW_LOG" ]]; then
    extract_tokens || true
    sanitize_log || true
  fi
  write_state "$status" || true
  [[ -z "$INPUT_FILE" ]] || rm -f "$INPUT_FILE"
  rm -f "$ENV_FILE"
}

trap 'rc=$?; if [[ "$rc" -ne 0 ]]; then finalize failed; fi' EXIT
mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"
write_state running
rm -f "$TOKEN_FILE" "$SAFE_LOG" "$RAW_LOG"

[[ -x "$SCRIPT" ]] || { echo 'Pinned setup script is missing; upgrade PQTunnel manager.' > "$SAFE_LOG"; write_state failed; exit 1; }
[[ "${PQTUNNEL_SETUP_INPUT_B64:-}" =~ ^[A-Za-z0-9+/=]+$ ]] || { echo 'Setup input was missing or invalid.' > "$SAFE_LOG"; write_state failed; exit 1; }

INPUT_FILE="$(mktemp /run/pqtunnel-setup-inputs.XXXXXX)"
chmod 0600 "$INPUT_FILE"
printf '%s' "$PQTUNNEL_SETUP_INPUT_B64" | base64 --decode > "$INPUT_FILE"
[[ -s "$INPUT_FILE" ]] || { echo 'Setup input was empty.' > "$SAFE_LOG"; write_state failed; exit 1; }
unset PQTUNNEL_SETUP_INPUT_B64

set +e
PQTUNNEL_SETUP_INPUT_FILE="$INPUT_FILE" bash "$SCRIPT" > "$RAW_LOG" 2>&1
rc=$?
set -e
extract_tokens || true
sanitize_log
if (( rc == 0 )); then
  write_state succeeded
  echo 'PQTunnel graphical setup finished. Consult the authenticated setup page for status.' >&2
else
  write_state failed
  echo "PQTunnel graphical setup stopped with exit status $rc; logs were redacted." >&2
fi
rm -f "$INPUT_FILE" "$ENV_FILE"
INPUT_FILE=
exit "$rc"
