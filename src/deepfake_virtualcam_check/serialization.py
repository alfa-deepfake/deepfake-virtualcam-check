from __future__ import annotations

import json
from typing import Any

from deepfake_virtualcam_check.models import (
    ActiveChallengeSignals,
    FrameObservation,
    SourceSignals,
    StreamCheckInput,
)


def load_stream_check(raw: str) -> StreamCheckInput:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Input must be a JSON object")
    return stream_check_from_dict(value)


def stream_check_from_dict(value: dict[str, Any]) -> StreamCheckInput:
    return StreamCheckInput(
        uid=_optional_str(value.get("uid")),
        check_id=_optional_str(value.get("check_id")),
        session_id=_optional_str(value.get("session_id")),
        signature_status=_optional_str(value.get("signature_status")),
        source=_source_from_dict(value.get("source") or {}),
        frames=[_frame_from_dict(item) for item in value.get("frames") or []],
        active_challenge=_challenge_from_dict(value.get("active_challenge")),
    )


def source_from_json_file(path: str) -> SourceSignals:
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    return _source_from_dict(value)


def _source_from_dict(value: dict[str, Any]) -> SourceSignals:
    if not isinstance(value, dict):
        raise ValueError("source must be an object")
    return SourceSignals(
        device_label=_optional_str(value.get("device_label")),
        user_agent=_optional_str(value.get("user_agent")),
        width=_optional_int(value.get("width")),
        height=_optional_int(value.get("height")),
        fps=_optional_float(value.get("fps")),
        capture_surface=_optional_str(value.get("capture_surface")),
        display_surface=_optional_str(value.get("display_surface")),
        settings=_optional_dict(value.get("settings")) or {},
    )


def _frame_from_dict(value: dict[str, Any]) -> FrameObservation:
    if not isinstance(value, dict):
        raise ValueError("each frame must be an object")
    return FrameObservation(
        sequence_number=int(value["sequence_number"]),
        timestamp_us=int(value["timestamp_us"]),
        received_at_us=_optional_int(value.get("received_at_us")),
        codec=_optional_str(value.get("codec")),
        encoded_size=_optional_int(value.get("encoded_size")),
        width=_optional_int(value.get("width")),
        height=_optional_int(value.get("height")),
        content_hash=_optional_str(value.get("content_hash")),
        perceptual_hash=_optional_str(value.get("perceptual_hash")),
        face_bbox=_bbox(value.get("face_bbox")),
        face_detection_available=_optional_bool(value.get("face_detection_available")),
        brightness=_optional_float(value.get("brightness")),
        laplacian_var=_optional_float(value.get("laplacian_var")),
    )


def _challenge_from_dict(value: Any) -> ActiveChallengeSignals | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("active_challenge must be an object")
    return ActiveChallengeSignals(
        live_probability=_optional_float(value.get("live_probability")),
        spoof_probability=_optional_float(value.get("spoof_probability")),
        verdict=_optional_str(value.get("verdict")),
        response_score=_optional_float(value.get("response_score")),
        mean_latency_ms=_optional_float(value.get("mean_latency_ms")),
        reasons=[str(item) for item in value.get("reasons") or []],
        metrics=_optional_dict(value.get("metrics")) or {},
    )


def _bbox(value: Any) -> tuple[float, float, float, float] | None:
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        raise ValueError("face_bbox must be [x, y, width, height]")
    return tuple(float(item) for item in value)  # type: ignore[return-value]


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _optional_float(value: Any) -> float | None:
    return None if value is None else float(value)


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return bool(value)


def _optional_dict(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return dict(value)
