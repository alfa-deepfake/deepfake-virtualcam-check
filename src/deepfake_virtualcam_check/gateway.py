from __future__ import annotations

import base64
import hashlib
import io
import json
import socket
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping

from deepfake_media_transport import (
    LENGTH_STRUCT,
    Codec,
    MediaPacket,
    PacketReassembler,
    StreamType,
    iter_length_prefixed_packets,
)
from deepfake_stream_signature import (
    StreamPacket,
    StreamPacketHeader,
    StreamSignatureVerifier,
)

from deepfake_virtualcam_check.models import FrameObservation, SourceSignals, StreamCheckInput


@dataclass(frozen=True)
class PacketEnvelope:
    packet: MediaPacket
    received_at_us: int | None = None
    signature_status: str | None = None


def _to_stream_packet(packet: MediaPacket) -> StreamPacket:
    """Adapt a transport MediaPacket to the signature library's StreamPacket."""
    header = packet.header
    return StreamPacket(
        header=StreamPacketHeader(
            stream_type=int(header.stream_type),
            codec=int(header.codec),
            session_id=header.session_id,
            sequence_number=header.sequence_number,
            timestamp_us=header.timestamp_us,
            payload_size=header.payload_size,
            fragment_index=header.fragment_index,
            fragment_count=header.fragment_count,
        ),
        payload=packet.payload,
    )


def stream_input_from_gateway_packets(
    envelopes: Iterable[PacketEnvelope],
    *,
    uid: str | None = None,
    check_id: str | None = None,
    session_id: str | None = None,
    source: SourceSignals | None = None,
    signature_status: str | None = None,
    trusted_signature_keys: Mapping[str, bytes] | None = None,
    max_frames: int | None = None,
) -> StreamCheckInput:
    reassembler = PacketReassembler()
    verifier = StreamSignatureVerifier(trusted_signature_keys)
    frames: list[FrameObservation] = []
    observed_signature_statuses: list[str] = []
    observed_session_id = session_id

    for envelope in envelopes:
        reassembled = reassembler.push(envelope.packet)
        if reassembled is None:
            continue
        status = envelope.signature_status
        if status is None:
            verification = verifier.verify_and_strip(_to_stream_packet(reassembled))
            stripped_payload = verification.packet.payload
            reassembled = replace(
                reassembled,
                header=replace(reassembled.header, payload_size=len(stripped_payload)),
                payload=stripped_payload,
            )
            status = verification.status.value
        if status:
            observed_signature_statuses.append(status)
        if reassembled.header.stream_type != int(StreamType.VIDEO):
            continue
        if observed_session_id is None:
            observed_session_id = reassembled.header.session_id.hex()
        frames.append(frame_observation_from_packet(reassembled, received_at_us=envelope.received_at_us))
        if max_frames is not None and len(frames) >= max_frames:
            break

    return StreamCheckInput(
        uid=uid,
        check_id=check_id,
        session_id=observed_session_id,
        signature_status=signature_status or _dominant_signature_status(observed_signature_statuses),
        source=source or SourceSignals(),
        frames=frames,
    )


def frame_observation_from_packet(packet: MediaPacket, *, received_at_us: int | None = None) -> FrameObservation:
    payload = packet.payload
    image_metrics = _mjpeg_metrics(payload) if packet.header.codec == int(Codec.MJPEG) else {}
    content_hash = hashlib.sha256(payload).hexdigest()

    return FrameObservation(
        sequence_number=packet.header.sequence_number,
        timestamp_us=packet.header.timestamp_us,
        received_at_us=received_at_us,
        codec=_codec_name(packet.header.codec),
        encoded_size=len(payload),
        width=image_metrics.get("width"),
        height=image_metrics.get("height"),
        content_hash=content_hash,
        perceptual_hash=image_metrics.get("perceptual_hash"),
        face_bbox=image_metrics.get("face_bbox"),
        face_detection_available=image_metrics.get("face_detection_available"),
        brightness=image_metrics.get("brightness"),
        laplacian_var=image_metrics.get("laplacian_var"),
    )


def load_jsonl_packet_envelopes(lines: Iterable[str]) -> list[PacketEnvelope]:
    envelopes: list[PacketEnvelope] = []
    for line_no, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        value = json.loads(line)
        if isinstance(value, str):
            packet_b64 = value
            received_at_us = None
            signature_status = None
        elif isinstance(value, dict):
            packet_b64 = str(value.get("packet_b64") or value.get("packet") or "")
            received_at_us = value.get("received_at_us")
            signature_status = value.get("signature_status")
        else:
            raise ValueError(f"line {line_no}: expected JSON string or object")
        if not packet_b64:
            raise ValueError(f"line {line_no}: packet_b64 is required")
        packet = MediaPacket.from_bytes(base64.b64decode(packet_b64))
        envelopes.append(
            PacketEnvelope(
                packet=packet,
                received_at_us=int(received_at_us) if received_at_us is not None else None,
                signature_status=str(signature_status) if signature_status is not None else None,
            )
        )
    return envelopes


def load_length_prefixed_packet_envelopes(data: bytes) -> list[PacketEnvelope]:
    envelopes: list[PacketEnvelope] = []
    for packet_data in iter_length_prefixed_packets(data):
        envelopes.append(
            PacketEnvelope(
                packet=MediaPacket.from_bytes(packet_data),
                received_at_us=time.time_ns() // 1000,
            )
        )
    return envelopes


def collect_tcp_proxy_packet_envelopes(
    *,
    listen_host: str,
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    duration_s: float,
    accept_timeout_s: float = 120.0,
    max_frames: int | None = None,
    max_frame_size: int = 16 * 1024 * 1024,
) -> list[PacketEnvelope]:
    if duration_s <= 0:
        raise ValueError("duration_s must be positive")
    if accept_timeout_s <= 0:
        raise ValueError("accept_timeout_s must be positive")

    envelopes: list[PacketEnvelope] = []
    stop = threading.Event()
    accept_deadline = time.monotonic() + accept_timeout_s
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(1)
    server.settimeout(0.20)
    client: socket.socket | None = None
    upstream: socket.socket | None = None

    try:
        while time.monotonic() < accept_deadline:
            try:
                client, _addr = server.accept()
                break
            except socket.timeout:
                continue
        if client is None:
            return []

        deadline = time.monotonic() + duration_s
        client.settimeout(0.20)
        upstream = socket.create_connection((upstream_host, upstream_port), timeout=5.0)
        upstream.settimeout(0.20)

        upstream_thread = threading.Thread(
            target=_forward_length_prefixed_frames,
            args=(upstream, client, stop, deadline, max_frame_size),
            daemon=True,
        )
        upstream_thread.start()

        video_frames = 0
        while not stop.is_set() and time.monotonic() < deadline:
            frame = _read_length_prefixed_frame_from_socket(client, max_frame_size=max_frame_size)
            if frame is None:
                continue
            upstream.sendall(LENGTH_STRUCT.pack(len(frame)) + frame)
            packet = MediaPacket.from_bytes(frame)
            envelopes.append(PacketEnvelope(packet=packet, received_at_us=time.time_ns() // 1000))
            if packet.header.stream_type == int(StreamType.VIDEO):
                video_frames += 1
                if max_frames is not None and video_frames >= max_frames:
                    break
        stop.set()
        upstream_thread.join(timeout=1.0)
    finally:
        stop.set()
        for sock in (client, upstream, server):
            if sock is not None:
                with suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
                sock.close()
    return envelopes


def _forward_length_prefixed_frames(
    source: socket.socket,
    target: socket.socket,
    stop: threading.Event,
    deadline: float,
    max_frame_size: int,
) -> None:
    while not stop.is_set() and time.monotonic() < deadline:
        frame = _read_length_prefixed_frame_from_socket(source, max_frame_size=max_frame_size)
        if frame is None:
            continue
        target.sendall(LENGTH_STRUCT.pack(len(frame)) + frame)


def _read_length_prefixed_frame_from_socket(sock: socket.socket, *, max_frame_size: int) -> bytes | None:
    try:
        header = _read_exact_from_socket(sock, LENGTH_STRUCT.size)
    except socket.timeout:
        return None
    if not header:
        raise ConnectionError("socket closed")
    frame_size = LENGTH_STRUCT.unpack(header)[0]
    if frame_size > max_frame_size:
        raise ValueError(f"stream frame too large: {frame_size}")
    return _read_exact_from_socket(sock, frame_size)


def _read_exact_from_socket(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _mjpeg_metrics(payload: bytes) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    metrics.update(_image_metrics_with_cv2(payload))
    if not metrics:
        metrics.update(_image_metrics_with_pillow(payload))
    if "perceptual_hash" not in metrics:
        metrics["perceptual_hash"] = _byte_similarity_hash(payload)
    return metrics


def _image_metrics_with_cv2(payload: bytes) -> dict[str, Any]:
    try:
        import cv2  # type: ignore
        import numpy as np  # type: ignore
    except ImportError:
        return {}

    arr = np.frombuffer(payload, dtype=np.uint8)
    frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if frame is None:
        return {}

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    metrics: dict[str, Any] = {
        "width": int(frame.shape[1]),
        "height": int(frame.shape[0]),
        "brightness": float(gray.mean()),
        "laplacian_var": float(cv2.Laplacian(gray, cv2.CV_64F).var()),
        "perceptual_hash": _dhash_from_gray(gray),
    }
    bbox, face_detection_available = _face_bbox_cv2_with_status(frame, gray)
    metrics["face_detection_available"] = face_detection_available
    if bbox is not None:
        metrics["face_bbox"] = bbox
    return metrics


def _image_metrics_with_pillow(payload: bytes) -> dict[str, Any]:
    try:
        from PIL import Image  # type: ignore
    except ImportError:
        return {}

    try:
        image = Image.open(io.BytesIO(payload)).convert("L")
    except Exception:
        return {}

    histogram = image.histogram()
    total = sum(histogram)
    brightness = sum(index * count for index, count in enumerate(histogram)) / total if total else None
    return {
        "width": int(image.width),
        "height": int(image.height),
        "brightness": float(brightness) if brightness is not None else None,
        "perceptual_hash": _dhash_from_pillow(image),
        "face_detection_available": False,
    }


def _face_bbox_cv2_with_status(frame: Any, gray: Any) -> tuple[tuple[float, float, float, float] | None, bool]:
    try:
        import cv2  # type: ignore
    except ImportError:
        return None, False

    if not hasattr(cv2, "CascadeClassifier"):
        return None, False

    cascade_path = getattr(cv2.data, "haarcascades", "") + "haarcascade_frontalface_default.xml"
    cascade = cv2.CascadeClassifier(cascade_path)
    if cascade.empty():
        return None, False
    faces = cascade.detectMultiScale(gray, scaleFactor=1.12, minNeighbors=4, minSize=(45, 45))
    if len(faces) == 0:
        return None, True
    x, y, w, h = max((tuple(face) for face in faces), key=lambda face: face[2] * face[3])
    height, width = frame.shape[:2]
    return (float(x / width), float(y / height), float(w / width), float(h / height)), True


def _dhash_from_gray(gray: Any) -> str:
    import cv2  # type: ignore

    resized = cv2.resize(gray, (9, 8), interpolation=cv2.INTER_AREA)
    bits = resized[:, 1:] > resized[:, :-1]
    value = 0
    for bit in bits.flatten():
        value = (value << 1) | int(bool(bit))
    return f"{value:016x}"


def _dhash_from_pillow(image: Any) -> str:
    resized = image.resize((9, 8))
    pixels = list(resized.getdata())
    value = 0
    for row in range(8):
        for col in range(8):
            value = (value << 1) | int(pixels[row * 9 + col + 1] > pixels[row * 9 + col])
    return f"{value:016x}"


def _byte_similarity_hash(payload: bytes) -> str:
    digest = hashlib.blake2b(payload, digest_size=8).hexdigest()
    return digest


def _dominant_signature_status(statuses: list[str]) -> str | None:
    if not statuses:
        return None
    priority = {
        "tampered": 100,
        "invalid": 95,
        "replay": 90,
        "chain_mismatch": 90,
        "untrusted_key": 80,
        "absent": 30,
        "disabled": 20,
        "trusted": 10,
    }
    return max(statuses, key=lambda status: priority.get(status, 40))


def _codec_name(codec: int) -> str:
    try:
        return Codec(codec).name.lower()
    except ValueError:
        return str(codec)
