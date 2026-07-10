# deepfake-virtualcam-check

Explainable CLI/library module for realtime video-stream risk scoring. It does
not run an ML detector and does not try to make a final deepfake decision from
one frame. Instead it aggregates passive stream signals that are useful against
virtual cameras, replayed streams, broken signatures, and failed active
liveness checks.

## Position in the system

Recommended server-side order:

1. Verify stream signature with `deepfake-stream-signature`.
2. Collect source metadata and frame observations from the
   `deepfake-audio-video-inference` media gateway / UDP capture path.
3. Optionally attach `face-flashing` active challenge output.
4. Run `deepfake-virtualcam-check`.
5. Let the caller decide where to send/store the returned score object.

The current module is intentionally lightweight and CPU-only. GPU ML scoring is
out of scope for this package and can be aggregated by another service later.

## What it checks

- Known virtual camera labels: OBS, ManyCam, Snap Camera, v4l2loopback, etc.
- Screen/window capture metadata when available from the client/gateway.
- Signature status: trusted, absent, untrusted key, tampered, replay, chain
  mismatch.
- Timestamp cadence: repeated timestamps, sequence gaps, cadence that is too
  exact for a natural webcam transport.
- Replay/freeze patterns: exact frame hashes, consecutive duplicates, near
  duplicate perceptual hashes with flat brightness.
- Encoding consistency: codec, encoded frame sizes, decoded MJPEG dimensions,
  and declared-vs-decoded resolution mismatch.
- Face/content stability: missing face, overly static face bounding box, low
  texture detail.
- Active liveness output from the `face-flashing` module.

## Input JSON

```json
{
  "uid": "user-1",
  "check_id": "check-123",
  "session_id": "media-session-1",
  "signature_status": "trusted",
  "source": {
    "device_label": "Integrated Camera",
    "width": 1280,
    "height": 720,
    "fps": 30,
    "capture_surface": null,
    "settings": {}
  },
  "frames": [
    {
      "sequence_number": 1,
      "timestamp_us": 33000,
      "received_at_us": 101000,
      "codec": "mjpeg",
      "encoded_size": 24831,
      "width": 512,
      "height": 288,
      "content_hash": "sha256-or-gateway-id",
      "perceptual_hash": "0011223344556677",
      "face_bbox": [0.39, 0.25, 0.21, 0.28],
      "brightness": 96.2,
      "laplacian_var": 44.0
    }
  ],
  "active_challenge": {
    "live_probability": 0.91,
    "verdict": "live",
    "response_score": 0.35,
    "mean_latency_ms": 120
  }
}
```

Frame image decoding can happen outside the core package, but the CLI also has a
`deepfake-audio-video-inference` media gateway adapter. With OpenCV installed it can
extract brightness, blur, dHash, and Haar face-box metrics from MJPEG packets.
Without OpenCV/Pillow it still extracts packet timing and payload hashes. If the
gateway payload contains a `deepfake-stream-signature` envelope, the adapter can
strip it for frame metrics and can verify it when trusted keys are supplied.

## Run

```bash
PYTHONPATH=src python -m deepfake_virtualcam_check.cli score input.json --pretty
```

For backward-compatible local use, this is equivalent:

```bash
PYTHONPATH=src python -m deepfake_virtualcam_check.cli input.json --pretty
```

## Media Gateway Input

The module understands the packet format from the shared
`deepfake-media-transport` package (`deepfake_media_transport.protocol`):

- magic/version header `DF` / `1`;
- stream type `2` for video;
- codec `2` for MJPEG;
- 16-byte session id;
- sequence number and timestamp in microseconds;
- fragmentation fields.

JSONL mode accepts one packet per line. Each line can be a base64 string or an
object:

```json
{"packet_b64": "...", "received_at_us": 123456789, "signature_status": "trusted"}
```

Run:

```bash
PYTHONPATH=src python -m deepfake_virtualcam_check.cli gateway-jsonl packets.jsonl \
  --device-label "Integrated Camera" \
  --width 512 \
  --height 288 \
  --fps 15 \
  --signature-status trusted \
  --signature-trusted-key deepfake-client-test=secret \
  --pretty
```

Stream mode accepts a binary file containing TCP stream-mode frames, where each
packet is prefixed by the same 4-byte big-endian length used by
`backend.media_gateway.stream_client` and `stream_server`:

```bash
PYTHONPATH=src python -m deepfake_virtualcam_check.cli gateway-stream stream-capture.bin \
  --source-json source.json \
  --max-frames 120 \
  --pretty
```

`source.json` uses the same fields as the `source` object in normalized input.
CLI flags such as `--device-label`, `--width`, `--height`, and `--fps` override
the file when both are provided.

Live UDP mode listens for raw media gateway datagrams, captures one analysis
window, and prints a score:

```bash
PYTHONPATH=src python -m deepfake_virtualcam_check.cli gateway-udp \
  --host 0.0.0.0 \
  --port 11000 \
  --duration 5 \
  --max-frames 120 \
  --device-label "Integrated Camera" \
  --width 640 \
  --height 360 \
  --fps 20 \
  --signature-trusted-key deepfake-client-test=secret \
  --pretty
```

`--signature-status` can still be passed explicitly when signature verification
is performed by another module before this CLI receives the packet metadata.

## Stream Mode With SSH Tunnel

The current `deepfake-audio-video-inference` preferred path is TCP stream mode:

```text
stream_client on laptop -> local SSH tunnel -> stream_server on cluster
```

To score the same client-to-server media packets without changing the inference
server, put this module in the middle as a short-lived TCP proxy:

1. Ensure the cluster `stream_server` is running.
2. Start the local tunnel + scoring proxy.
3. Start the local `stream_client` against local port `13000`.

If the cluster server is not already listening on `127.0.0.1:13000`, start it
from the laptop:

```bash
./scripts/start-cluster-server.sh
```

Start the local tunnel and scoring proxy:

```bash
./scripts/run-tcp-proxy.sh
```

Then run the stream client:

```bash
./scripts/run-stream-client.sh
```

The proxy exits after the requested capture window and prints one score JSON.
That will also close the test stream, so use it for sampling/calibration rather
than for a long-lived production session.

Common overrides:

```bash
CAPTURE_DURATION=12 MAX_FRAMES=180 ./scripts/run-tcp-proxy.sh
DEVICE_LABEL="OBS Virtual Camera" ./scripts/run-tcp-proxy.sh
SIGNATURE_TRUSTED_KEY="deepfake-client-test=secret" ./scripts/run-tcp-proxy.sh
SOURCE_WIDTH=320 SOURCE_HEIGHT=240 ./scripts/run-tcp-proxy.sh
VIDEO_DEVICE=2 ./scripts/run-stream-client.sh
VOICE_REPO=/path/to/deepfake-audio-video-inference ./scripts/run-stream-client.sh
```

## Output

The CLI prints a score JSON object:

```json
{
  "module": "deepfake-virtualcam-check",
  "version": "0.1.0",
  "verdict": "genuine",
  "risk_score": 0.184,
  "confidence": 0.87,
  "reasons": ["trusted_stream_signature"],
  "metrics": {},
  "components": []
}
```

Verdicts:

- `genuine`: low risk with enough evidence.
- `suspicious`: elevated risk; require step-up, manual review, or stronger
  liveness.
- `fake`: high-risk condition, including critical signature failures or several
  strong virtual/replay signals.
- `uncertain`: insufficient evidence or mid-range risk.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

## Recommendation before production

This module should be treated as a policy/risk aggregator, not as the only
deepfake detector. The active challenge remains important because realtime
virtual camera attacks are often easier to catch through unpredictable liveness
than through passive frame classification alone. ML should remain a separate
service and can be fused with this score by RiskAPI or a later aggregator.
