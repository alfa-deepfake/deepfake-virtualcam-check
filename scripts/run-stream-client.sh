#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ALFA_ROOT="$(cd "$REPO_ROOT/.." && pwd)"

VOICE_REPO="${VOICE_REPO:-$ALFA_ROOT/deepfake-voice-inference}"
GATEWAY_HOST="${GATEWAY_HOST:-127.0.0.1}"
GATEWAY_PORT="${GATEWAY_PORT:-13000}"

VIDEO_DEVICE="${VIDEO_DEVICE:-0}"
VIDEO_WIDTH="${VIDEO_WIDTH:-512}"
VIDEO_HEIGHT="${VIDEO_HEIGHT:-288}"
VIDEO_FPS="${VIDEO_FPS:-15}"
JPEG_QUALITY="${JPEG_QUALITY:-65}"

AUDIO_SAMPLE_RATE="${AUDIO_SAMPLE_RATE:-48000}"
AUDIO_BLOCK_SAMPLES="${AUDIO_BLOCK_SAMPLES:-12000}"
AUDIO_DEVICE="${AUDIO_DEVICE:-}"
SOURCE_WAV="${SOURCE_WAV:-}"

SIGNATURE_KEY="${SIGNATURE_KEY:-}"
SIGNATURE_KEY_ID="${SIGNATURE_KEY_ID:-deepfake-client-test}"

if [[ ! -f "$VOICE_REPO/backend/media_gateway/stream_client.py" ]]; then
  echo "stream_client.py not found in VOICE_REPO=$VOICE_REPO" >&2
  echo "Set VOICE_REPO=/path/to/deepfake-voice-inference and retry." >&2
  exit 1
fi

if [[ -n "${PYTHON_BIN:-}" ]]; then
  PYTHON="$PYTHON_BIN"
elif [[ -x "$VOICE_REPO/.venv/bin/python" ]]; then
  PYTHON="$VOICE_REPO/.venv/bin/python"
else
  PYTHON="python"
fi

CMD=(
  "$PYTHON"
  -m backend.media_gateway.stream_client
  --gateway-host "$GATEWAY_HOST"
  --gateway-port "$GATEWAY_PORT"
  --video-device "$VIDEO_DEVICE"
  --video-width "$VIDEO_WIDTH"
  --video-height "$VIDEO_HEIGHT"
  --video-fps "$VIDEO_FPS"
  --jpeg-quality "$JPEG_QUALITY"
  --audio-sample-rate "$AUDIO_SAMPLE_RATE"
  --audio-block-samples "$AUDIO_BLOCK_SAMPLES"
)

if [[ -n "$AUDIO_DEVICE" ]]; then
  CMD+=(--audio-device "$AUDIO_DEVICE")
fi

if [[ -n "$SOURCE_WAV" ]]; then
  CMD+=(--source-wav "$SOURCE_WAV")
fi

if [[ -n "$SIGNATURE_KEY" ]]; then
  CMD+=(--signature-key "$SIGNATURE_KEY" --signature-key-id "$SIGNATURE_KEY_ID")
fi

if [[ "${DRYRUN:-0}" == "1" ]]; then
  printf 'cd %q\n' "$VOICE_REPO"
  printf 'PYTHONPATH=%q ' "$VOICE_REPO"
  printf '%q ' "${CMD[@]}"
  printf '\n'
  exit 0
fi

cd "$VOICE_REPO"
echo "Connecting stream_client to $GATEWAY_HOST:$GATEWAY_PORT"
PYTHONPATH="$VOICE_REPO${PYTHONPATH:+:$PYTHONPATH}" "${CMD[@]}"
