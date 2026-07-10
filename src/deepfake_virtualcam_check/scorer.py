from __future__ import annotations

from collections import Counter
from statistics import mean, pstdev

from deepfake_stream_signature import SignatureStatus

from deepfake_virtualcam_check.models import (
    FrameObservation,
    RiskComponent,
    StreamCheckInput,
    Verdict,
    VirtualCamScore,
)


MODULE_NAME = "deepfake-virtualcam-check"
MODULE_VERSION = "0.1.0"

DIRECT_VIRTUAL_LABELS = (
    "obs virtual camera",
    "obs-camera",
    "manycam",
    "snap camera",
    "xsplit",
    "splitcam",
    "mmhmm",
    "camo",
    "droidcam",
    "iriun",
    "v4l2loopback",
    "akvirtualcamera",
    "webcamoid",
)
CAPTURE_LABELS = ("screen", "window", "tab", "desktop", "display", "capture")
SUSPICIOUS_LABELS = ("virtual", "loopback", "broadcast", "ndi", "blackmagic", "elgato")
# The critical signature failures, sourced from the signature library's enum so
# the vocabulary is defined in exactly one place. untrusted_key is scored
# separately below as a softer signal, so it is excluded here.
BAD_SIGNATURE_STATUSES = {
    SignatureStatus.INVALID.value,
    SignatureStatus.TAMPERED.value,
    SignatureStatus.REPLAY.value,
    SignatureStatus.CHAIN_MISMATCH.value,
}


def score_stream(payload: StreamCheckInput) -> VirtualCamScore:
    frames = sorted(payload.frames, key=lambda frame: (frame.timestamp_us, frame.sequence_number))
    components: list[RiskComponent] = []

    _append_signature_component(components, payload.signature_status)
    _append_source_component(components, payload)
    _append_timing_component(components, frames)
    _append_replay_component(components, frames)
    _append_encoding_component(components, payload, frames)
    _append_face_content_component(components, frames)
    _append_active_challenge_component(components, payload)

    risk_score = _apply_dominance_rules(_weighted_average(components, default=0.5), components)
    confidence = _confidence(components, frames)
    if _has_critical_signature_failure(components):
        confidence = max(confidence, 0.55)
    verdict = _verdict(risk_score, confidence)

    metrics = {
        "frame_count": len(frames),
        "duration_ms": _duration_ms(frames),
        "effective_fps": _effective_fps(frames),
        "signature_status": payload.signature_status,
        "source_device_label": payload.source.device_label,
        "source_resolution": _resolution(payload),
    }
    reasons = _top_reasons(components)

    if len(frames) < 12:
        reasons.append("too_few_frames_for_reliable_stream_analysis")
        confidence = min(confidence, 0.35)
        if risk_score < 0.78:
            verdict = Verdict.UNCERTAIN

    return VirtualCamScore(
        module=MODULE_NAME,
        version=MODULE_VERSION,
        verdict=verdict,
        risk_score=round(_clamp(risk_score), 6),
        confidence=round(_clamp(confidence), 6),
        reasons=reasons,
        metrics=metrics,
        components=components,
    )


def _append_signature_component(components: list[RiskComponent], status: str | None) -> None:
    normalized = (status or "unknown").lower()
    if normalized == "trusted":
        risk, weight, reason = 0.02, 0.16, "trusted_stream_signature"
    elif normalized == "absent":
        risk, weight, reason = 0.22, 0.10, "stream_signature_absent"
    elif normalized == "untrusted_key":
        risk, weight, reason = 0.72, 0.22, "stream_signature_uses_untrusted_key"
    elif normalized in BAD_SIGNATURE_STATUSES:
        risk, weight, reason = 0.98, 0.32, f"stream_signature_{normalized}"
    elif normalized in {"disabled", "unknown", ""}:
        risk, weight, reason = 0.18, 0.06, "stream_signature_not_enforced"
    else:
        risk, weight, reason = 0.42, 0.08, f"unknown_signature_status_{normalized}"

    components.append(RiskComponent("signature", risk, weight, reason, {"status": normalized}))


def _append_source_component(components: list[RiskComponent], payload: StreamCheckInput) -> None:
    source = payload.source
    label = (source.device_label or "").strip().lower()
    capture_surface = (source.capture_surface or source.display_surface or "").strip().lower()

    reason = "source_metadata_not_indicative"
    risk = 0.08
    weight = 0.10

    if _contains_any(label, DIRECT_VIRTUAL_LABELS):
        risk, weight, reason = 0.92, 0.30, "known_virtual_camera_device_label"
    elif _contains_any(label, CAPTURE_LABELS) or _contains_any(capture_surface, CAPTURE_LABELS):
        risk, weight, reason = 0.82, 0.26, "screen_or_window_capture_source"
    elif _contains_any(label, SUSPICIOUS_LABELS):
        risk, weight, reason = 0.58, 0.18, "suspicious_capture_device_label"

    settings = dict(source.settings)
    if source.fps is not None and source.fps > 90:
        risk = max(risk, 0.50)
        reason = "unusual_capture_fps"
    if source.width is not None and source.height is not None:
        settings["width"] = source.width
        settings["height"] = source.height

    components.append(
        RiskComponent(
            "source",
            risk,
            weight,
            reason,
            {
                "device_label": source.device_label,
                "capture_surface": source.capture_surface,
                "display_surface": source.display_surface,
                "fps": source.fps,
                "settings": settings,
            },
        )
    )


def _append_timing_component(components: list[RiskComponent], frames: list[FrameObservation]) -> None:
    if len(frames) < 12:
        components.append(RiskComponent("timing", 0.50, 0.04, "too_few_frames_for_timing", {}))
        return

    timestamp_deltas = _positive_deltas([frame.timestamp_us for frame in frames])
    receive_deltas = _positive_deltas([frame.received_at_us for frame in frames if frame.received_at_us is not None])
    sequence_numbers = [frame.sequence_number for frame in frames]
    repeated_timestamps = 1.0 - len({frame.timestamp_us for frame in frames}) / len(frames)
    sequence_gap_ratio = _sequence_gap_ratio(sequence_numbers)

    cadence_risk = 0.05
    cadence_cv = None
    if len(timestamp_deltas) >= 8:
        avg_delta = mean(timestamp_deltas)
        cadence_cv = pstdev(timestamp_deltas) / avg_delta if avg_delta else None
        if cadence_cv is not None:
            if cadence_cv < 0.006:
                cadence_risk = 0.58
            elif cadence_cv < 0.018:
                cadence_risk = 0.36

    receive_cv = None
    if len(receive_deltas) >= 8:
        avg_receive_delta = mean(receive_deltas)
        receive_cv = pstdev(receive_deltas) / avg_receive_delta if avg_receive_delta else None
        if receive_cv is not None and receive_cv < 0.01:
            cadence_risk = max(cadence_risk, 0.34)

    timestamp_risk = min(1.0, repeated_timestamps * 4.0)
    sequence_risk = min(1.0, sequence_gap_ratio * 3.0)
    risk = max(cadence_risk, timestamp_risk, sequence_risk)

    reason = "natural_timing_variation"
    if repeated_timestamps > 0.02:
        reason = "repeated_stream_timestamps"
    elif sequence_gap_ratio > 0.02:
        reason = "sequence_numbers_have_gaps_or_reorders"
    elif risk >= 0.5:
        reason = "timestamp_cadence_too_exact"

    components.append(
        RiskComponent(
            "timing",
            risk,
            0.16,
            reason,
            {
                "timestamp_delta_cv": cadence_cv,
                "receive_delta_cv": receive_cv,
                "repeated_timestamp_ratio": repeated_timestamps,
                "sequence_gap_ratio": sequence_gap_ratio,
                "effective_fps": _effective_fps(frames),
            },
        )
    )


def _append_replay_component(components: list[RiskComponent], frames: list[FrameObservation]) -> None:
    hashes = [frame.content_hash for frame in frames if frame.content_hash]
    phashes = [frame.perceptual_hash for frame in frames if frame.perceptual_hash]
    brightness_values = [frame.brightness for frame in frames if frame.brightness is not None]

    exact_duplicate_ratio = _duplicate_ratio(hashes)
    frozen_ratio = _adjacent_duplicate_ratio(hashes)
    perceptual_near_duplicate_ratio = _near_duplicate_ratio(phashes)
    brightness_cv = _coefficient_of_variation(brightness_values)

    exact_risk = min(1.0, exact_duplicate_ratio * 2.2)
    frozen_risk = min(1.0, frozen_ratio * 2.8)
    perceptual_risk = 0.0
    if brightness_cv is not None and brightness_cv < 0.015:
        perceptual_risk = min(1.0, perceptual_near_duplicate_ratio * 1.6)
    risk = max(exact_risk, frozen_risk, perceptual_risk)
    reason = "no_replay_pattern_detected"

    if frozen_ratio >= 0.08:
        reason = "consecutive_duplicate_frames"
    elif exact_duplicate_ratio >= 0.10:
        reason = "reused_frame_hashes"
    elif perceptual_near_duplicate_ratio >= 0.45 and brightness_cv is not None and brightness_cv < 0.015:
        risk = max(risk, 0.62)
        reason = "near_duplicate_frames_with_flat_brightness"
    elif not hashes and not phashes:
        risk = 0.20
        reason = "frame_hash_signals_absent"

    components.append(
        RiskComponent(
            "replay",
            risk,
            0.20 if hashes or phashes else 0.06,
            reason,
            {
                "exact_duplicate_ratio": exact_duplicate_ratio,
                "frozen_frame_ratio": frozen_ratio,
                "perceptual_near_duplicate_ratio": perceptual_near_duplicate_ratio,
                "brightness_cv": brightness_cv,
            },
        )
    )


def _append_encoding_component(
    components: list[RiskComponent],
    payload: StreamCheckInput,
    frames: list[FrameObservation],
) -> None:
    if not frames:
        components.append(RiskComponent("encoding", 0.30, 0.02, "video_encoding_signals_absent", {}))
        return

    codecs = sorted({frame.codec for frame in frames if frame.codec})
    encoded_sizes = [frame.encoded_size for frame in frames if frame.encoded_size is not None]
    decoded_frame_count = sum(1 for frame in frames if frame.width and frame.height)
    decoded_sizes = {(frame.width, frame.height) for frame in frames if frame.width and frame.height}
    size_cv = _coefficient_of_variation([float(size) for size in encoded_sizes])

    risk = 0.08
    weight = 0.06
    reason = "video_encoding_not_indicative"

    if codecs and any(codec not in {"mjpeg", "h264"} for codec in codecs):
        risk, reason = 0.40, "unexpected_video_codec"
    if len(decoded_sizes) > 1:
        risk, reason = max(risk, 0.34), "decoded_resolution_changes_within_stream"
    elif decoded_sizes and payload.source.width and payload.source.height:
        decoded_width, decoded_height = next(iter(decoded_sizes))
        if decoded_width != payload.source.width or decoded_height != payload.source.height:
            risk, reason = max(risk, 0.32), "decoded_resolution_mismatch"
    if size_cv is not None and size_cv < 0.01 and len(encoded_sizes) >= 24:
        risk, reason = max(risk, 0.28), "encoded_frame_sizes_too_uniform"

    components.append(
        RiskComponent(
            "encoding",
            risk,
            weight,
            reason,
            {
                "codecs": codecs,
                "encoded_size_cv": size_cv,
                "decoded_frame_ratio": decoded_frame_count / len(frames),
                "decoded_sizes": [f"{width}x{height}" for width, height in sorted(decoded_sizes)],
            },
        )
    )


def _append_face_content_component(components: list[RiskComponent], frames: list[FrameObservation]) -> None:
    face_frames = [frame for frame in frames if frame.face_bbox is not None]
    decoded_frames = [frame for frame in frames if frame.width is not None and frame.height is not None]
    face_detection_frames = [
        frame
        for frame in decoded_frames
        if frame.face_detection_available is True or frame.face_bbox is not None
    ]
    laplacian_values = [frame.laplacian_var for frame in face_frames if frame.laplacian_var is not None]

    if len(frames) < 12:
        components.append(RiskComponent("face_content", 0.42, 0.04, "too_few_frames_for_face_content", {}))
        return

    if not decoded_frames:
        components.append(
            RiskComponent(
                "face_content",
                0.18,
                0.04,
                "frame_image_decode_signals_absent",
                {
                    "decoded_frame_ratio": 0.0,
                    "face_found_ratio": None,
                    "face_area_cv": None,
                    "mean_laplacian_var": None,
                },
            )
        )
        return

    if not face_detection_frames:
        components.append(
            RiskComponent(
                "face_content",
                0.16,
                0.04,
                "face_detection_signals_absent",
                {
                    "decoded_frame_ratio": len(decoded_frames) / len(frames),
                    "face_detection_available_ratio": 0.0,
                    "face_found_ratio": None,
                    "face_area_cv": None,
                    "mean_laplacian_var": None,
                },
            )
        )
        return

    face_ratio = len(face_frames) / len(face_detection_frames)
    area_values = [frame.face_bbox[2] * frame.face_bbox[3] for frame in face_frames if frame.face_bbox]
    area_cv = _coefficient_of_variation(area_values)
    texture_mean = mean(laplacian_values) if laplacian_values else None

    risk = 0.12
    reason = "face_content_not_indicative"
    if face_ratio < 0.35:
        risk, reason = 0.38, "face_missing_in_most_frames"
    elif area_cv is not None and area_cv < 0.012 and len(face_frames) >= 24:
        risk, reason = 0.34, "face_box_motion_too_static"

    if texture_mean is not None and texture_mean < 12.0:
        risk = max(risk, 0.44)
        reason = "low_face_texture_detail"

    components.append(
        RiskComponent(
            "face_content",
            risk,
            0.10,
            reason,
            {
                "face_found_ratio": face_ratio,
                "decoded_frame_ratio": len(decoded_frames) / len(frames),
                "face_detection_available_ratio": len(face_detection_frames) / len(frames),
                "face_area_cv": area_cv,
                "mean_laplacian_var": texture_mean,
            },
        )
    )


def _append_active_challenge_component(components: list[RiskComponent], payload: StreamCheckInput) -> None:
    challenge = payload.active_challenge
    if challenge is None:
        components.append(RiskComponent("active_challenge", 0.30, 0.04, "active_liveness_challenge_absent", {}))
        return

    if challenge.spoof_probability is not None:
        risk = _clamp(challenge.spoof_probability)
    elif challenge.live_probability is not None:
        risk = 1.0 - _clamp(challenge.live_probability)
    elif (challenge.verdict or "").lower() == "spoof":
        risk = 0.90
    elif (challenge.verdict or "").lower() == "live":
        risk = 0.08
    else:
        risk = 0.45

    verdict = (challenge.verdict or "unknown").lower()
    reason = f"active_liveness_{verdict}"
    if challenge.response_score is not None and challenge.response_score < 0.08:
        risk = max(risk, 0.72)
        reason = "weak_active_flash_response"
    if challenge.mean_latency_ms is not None and challenge.mean_latency_ms > 420.0:
        risk = max(risk, 0.68)
        reason = "delayed_active_flash_response"

    metrics = dict(challenge.metrics)
    metrics.update(
        {
            "live_probability": challenge.live_probability,
            "spoof_probability": challenge.spoof_probability,
            "verdict": challenge.verdict,
            "response_score": challenge.response_score,
            "mean_latency_ms": challenge.mean_latency_ms,
            "reasons": challenge.reasons,
        }
    )
    components.append(RiskComponent("active_challenge", risk, 0.28, reason, metrics))


def _weighted_average(components: list[RiskComponent], default: float) -> float:
    total_weight = sum(component.weight for component in components)
    if total_weight <= 0:
        return default
    return sum(component.risk * component.weight for component in components) / total_weight


def _apply_dominance_rules(risk_score: float, components: list[RiskComponent]) -> float:
    if _has_critical_signature_failure(components):
        risk_score = max(risk_score, 0.88)

    strong_components = [
        component
        for component in components
        if component.risk >= 0.75 and component.weight >= 0.16
    ]
    if len(strong_components) >= 2:
        risk_score = max(risk_score, 0.82)

    return risk_score


def _has_critical_signature_failure(components: list[RiskComponent]) -> bool:
    return any(
        component.name == "signature" and component.risk >= 0.95
        for component in components
    )


def _confidence(components: list[RiskComponent], frames: list[FrameObservation]) -> float:
    total_weight = sum(component.weight for component in components)
    confidence = min(1.0, total_weight / 0.82)
    if len(frames) >= 45:
        confidence *= 1.0
    elif len(frames) >= 20:
        confidence *= 0.82
    elif len(frames) >= 12:
        confidence *= 0.62
    else:
        confidence *= 0.36
    return _clamp(confidence)


def _verdict(risk_score: float, confidence: float) -> Verdict:
    if risk_score >= 0.78 and confidence >= 0.35:
        return Verdict.FAKE
    if risk_score >= 0.48 and confidence >= 0.35:
        return Verdict.SUSPICIOUS
    if risk_score <= 0.28 and confidence >= 0.55:
        return Verdict.GENUINE
    return Verdict.UNCERTAIN


def _top_reasons(components: list[RiskComponent]) -> list[str]:
    sorted_components = sorted(components, key=lambda item: item.risk * item.weight, reverse=True)
    return [component.reason for component in sorted_components[:5] if component.reason]


def _positive_deltas(values: list[int]) -> list[int]:
    return [b - a for a, b in zip(values, values[1:]) if b - a > 0]


def _duration_ms(frames: list[FrameObservation]) -> float:
    if len(frames) < 2:
        return 0.0
    return max(0.0, (frames[-1].timestamp_us - frames[0].timestamp_us) / 1000.0)


def _effective_fps(frames: list[FrameObservation]) -> float | None:
    duration = _duration_ms(frames) / 1000.0
    if duration <= 0.0 or len(frames) < 2:
        return None
    return (len(frames) - 1) / duration


def _sequence_gap_ratio(sequence_numbers: list[int]) -> float:
    if len(sequence_numbers) < 2:
        return 0.0
    bad = 0
    for previous, current in zip(sequence_numbers, sequence_numbers[1:]):
        if current != previous + 1:
            bad += 1
    return bad / (len(sequence_numbers) - 1)


def _duplicate_ratio(values: list[str]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    duplicates = sum(count - 1 for count in counts.values() if count > 1)
    return duplicates / len(values)


def _adjacent_duplicate_ratio(values: list[str]) -> float:
    if len(values) < 2:
        return 0.0
    duplicates = sum(1 for left, right in zip(values, values[1:]) if left == right)
    return duplicates / (len(values) - 1)


def _near_duplicate_ratio(values: list[str]) -> float:
    if len(values) < 2:
        return 0.0
    comparable = 0
    near = 0
    for left, right in zip(values, values[1:]):
        distance = _hamming_hex(left, right)
        if distance is None:
            continue
        comparable += 1
        if distance <= 4:
            near += 1
    return near / comparable if comparable else 0.0


def _hamming_hex(left: str, right: str) -> int | None:
    left = left.strip().lower()
    right = right.strip().lower()
    if len(left) != len(right):
        return None
    try:
        return (int(left, 16) ^ int(right, 16)).bit_count()
    except ValueError:
        return None


def _coefficient_of_variation(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    avg = mean(values)
    if abs(avg) < 1e-9:
        return None
    return pstdev(values) / abs(avg)


def _contains_any(value: str, needles: tuple[str, ...]) -> bool:
    return any(needle in value for needle in needles)


def _resolution(payload: StreamCheckInput) -> str | None:
    if payload.source.width is None or payload.source.height is None:
        return None
    return f"{payload.source.width}x{payload.source.height}"


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))
