#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SSH_CONFIG="${SSH_CONFIG:-/dev/null}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_PORT="${SSH_PORT:-22010}"
SSH_USER="${SSH_USER:-master}"
SSH_HOST="${SSH_HOST:-62.183.4.208}"

REMOTE_STREAM_HOST="${REMOTE_STREAM_HOST:-127.0.0.1}"
REMOTE_STREAM_PORT="${REMOTE_STREAM_PORT:-13000}"
TUNNEL_LOCAL_PORT="${TUNNEL_LOCAL_PORT:-13001}"

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-13000}"
CAPTURE_DURATION="${CAPTURE_DURATION:-8}"
ACCEPT_TIMEOUT="${ACCEPT_TIMEOUT:-120}"
MAX_FRAMES="${MAX_FRAMES:-120}"

DEVICE_LABEL="${DEVICE_LABEL:-Integrated Camera}"
SOURCE_WIDTH="${SOURCE_WIDTH:-}"
SOURCE_HEIGHT="${SOURCE_HEIGHT:-}"
VIDEO_FPS="${VIDEO_FPS:-15}"
SIGNATURE_TRUSTED_KEY="${SIGNATURE_TRUSTED_KEY:-}"

if [[ -n "${PYTHON_BIN:-}" ]]; then
  PYTHON="$PYTHON_BIN"
elif [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
  PYTHON="$REPO_ROOT/.venv/bin/python"
else
  PYTHON="python"
fi

SSH_CMD=(
  ssh
  -F "$SSH_CONFIG"
  -i "$SSH_KEY"
  -p "$SSH_PORT"
  -o ExitOnForwardFailure=yes
  -N
  -L "$TUNNEL_LOCAL_PORT:$REMOTE_STREAM_HOST:$REMOTE_STREAM_PORT"
  "$SSH_USER@$SSH_HOST"
)

PROXY_CMD=(
  "$PYTHON"
  -m deepfake_virtualcam_check.cli
  gateway-tcp-proxy
  --listen-host "$PROXY_HOST"
  --listen-port "$PROXY_PORT"
  --upstream-host 127.0.0.1
  --upstream-port "$TUNNEL_LOCAL_PORT"
  --duration "$CAPTURE_DURATION"
  --accept-timeout "$ACCEPT_TIMEOUT"
  --max-frames "$MAX_FRAMES"
  --device-label "$DEVICE_LABEL"
  --fps "$VIDEO_FPS"
  --pretty
)

if [[ -n "$SOURCE_WIDTH" ]]; then
  PROXY_CMD+=(--width "$SOURCE_WIDTH")
fi

if [[ -n "$SOURCE_HEIGHT" ]]; then
  PROXY_CMD+=(--height "$SOURCE_HEIGHT")
fi

if [[ -n "$SIGNATURE_TRUSTED_KEY" ]]; then
  PROXY_CMD+=(--signature-trusted-key "$SIGNATURE_TRUSTED_KEY")
fi

if [[ "${DRYRUN:-0}" == "1" ]]; then
  printf 'PYTHONPATH=%q ' "$REPO_ROOT/src"
  printf '%q ' "${PROXY_CMD[@]}"
  printf '\n\n'
  printf '%q ' "${SSH_CMD[@]}"
  printf '\n'
  exit 0
fi

cleanup() {
  if [[ -n "${TUNNEL_PID:-}" ]] && kill -0 "$TUNNEL_PID" 2>/dev/null; then
    kill "$TUNNEL_PID" 2>/dev/null || true
    wait "$TUNNEL_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "Opening SSH tunnel localhost:$TUNNEL_LOCAL_PORT -> $SSH_HOST:$REMOTE_STREAM_PORT"
"${SSH_CMD[@]}" &
TUNNEL_PID=$!
sleep 1

if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
  wait "$TUNNEL_PID"
fi

echo "Proxy listening on $PROXY_HOST:$PROXY_PORT"
echo "Now start the stream client against 127.0.0.1:$PROXY_PORT."
echo "Waiting up to ${ACCEPT_TIMEOUT}s for the client; capture starts after it connects."
echo

PYTHONPATH="$REPO_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" "${PROXY_CMD[@]}"
