#!/usr/bin/env bash
set -euo pipefail

SSH_CONFIG="${SSH_CONFIG:-/dev/null}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_PORT="${SSH_PORT:-22010}"
SSH_USER="${SSH_USER:-master}"
SSH_HOST="${SSH_HOST:-62.183.4.208}"

REMOTE_DIR="${REMOTE_DIR:-/home/master/work/deepfake-audio-video-inference}"
REMOTE_STREAM_HOST="${REMOTE_STREAM_HOST:-127.0.0.1}"
REMOTE_STREAM_PORT="${REMOTE_STREAM_PORT:-13000}"

if [[ "${DRYRUN:-0}" == "1" ]]; then
  printf '%q ' ssh -F "$SSH_CONFIG" -i "$SSH_KEY" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST"
  printf 'REMOTE_DIR=%q REMOTE_STREAM_HOST=%q REMOTE_STREAM_PORT=%q bash -s\n' \
    "$REMOTE_DIR" "$REMOTE_STREAM_HOST" "$REMOTE_STREAM_PORT"
  exit 0
fi

ssh -F "$SSH_CONFIG" -i "$SSH_KEY" -p "$SSH_PORT" "$SSH_USER@$SSH_HOST" \
  REMOTE_DIR="$REMOTE_DIR" \
  REMOTE_STREAM_HOST="$REMOTE_STREAM_HOST" \
  REMOTE_STREAM_PORT="$REMOTE_STREAM_PORT" \
  bash -s <<'REMOTE'
set -euo pipefail

cd "$REMOTE_DIR"

if ss -ltn "sport = :$REMOTE_STREAM_PORT" | grep -q LISTEN; then
  echo "stream_server is already listening on $REMOTE_STREAM_HOST:$REMOTE_STREAM_PORT"
  exit 0
fi

VIDEO_DLC_ROOT="${VIDEO_DLC_ROOT:-/home/master/workspace_w9line/deep_face/extracted/Deep-Live-Cam}"
VIDEO_SOURCE_FACE="${VIDEO_SOURCE_FACE:-$VIDEO_DLC_ROOT/классный_чел_пнг.jpg}"
VIDEO_PYTHON_PATH="${VIDEO_PYTHON_PATH:-$VIDEO_DLC_ROOT/.venv_dlc/bin/python}"
VIDEO_CUDA_LIB_ROOT="${VIDEO_CUDA_LIB_ROOT:-$PWD/.venv/lib/python3.10/site-packages}"

echo "Starting stream_server on $REMOTE_STREAM_HOST:$REMOTE_STREAM_PORT"

PYTHONPATH="$PWD" TORCH_FORCE_NO_WEIGHTS_ONLY_LOAD=1 .venv/bin/python \
  -m backend.media_gateway.stream_server \
  --host "$REMOTE_STREAM_HOST" \
  --port "$REMOTE_STREAM_PORT" \
  --audio-model-path assets/weights/voice_model.pth \
  --audio-index-path assets/indices/voice_model.index \
  --audio-index-rate 0.3 \
  --audio-sample-rate 48000 \
  --audio-block-time 0.25 \
  --audio-f0method fcpe \
  --video-dlc-root "$VIDEO_DLC_ROOT" \
  --video-source-face "$VIDEO_SOURCE_FACE" \
  --video-python-path "$VIDEO_PYTHON_PATH" \
  --video-cuda-lib-root "$VIDEO_CUDA_LIB_ROOT" \
  --video-execution-provider cuda \
  --video-camera-fps 15.0
REMOTE
