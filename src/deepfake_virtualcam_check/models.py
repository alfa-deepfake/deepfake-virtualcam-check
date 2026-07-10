from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    GENUINE = "genuine"
    SUSPICIOUS = "suspicious"
    FAKE = "fake"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class SourceSignals:
    device_label: str | None = None
    user_agent: str | None = None
    width: int | None = None
    height: int | None = None
    fps: float | None = None
    capture_surface: str | None = None
    display_surface: str | None = None
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FrameObservation:
    sequence_number: int
    timestamp_us: int
    received_at_us: int | None = None
    codec: str | None = None
    encoded_size: int | None = None
    width: int | None = None
    height: int | None = None
    content_hash: str | None = None
    perceptual_hash: str | None = None
    face_bbox: tuple[float, float, float, float] | None = None
    face_detection_available: bool | None = None
    brightness: float | None = None
    laplacian_var: float | None = None


@dataclass(frozen=True)
class ActiveChallengeSignals:
    live_probability: float | None = None
    spoof_probability: float | None = None
    verdict: str | None = None
    response_score: float | None = None
    mean_latency_ms: float | None = None
    reasons: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StreamCheckInput:
    uid: str | None = None
    check_id: str | None = None
    session_id: str | None = None
    signature_status: str | None = None
    source: SourceSignals = field(default_factory=SourceSignals)
    frames: list[FrameObservation] = field(default_factory=list)
    active_challenge: ActiveChallengeSignals | None = None


@dataclass(frozen=True)
class RiskComponent:
    name: str
    risk: float
    weight: float
    reason: str
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VirtualCamScore:
    module: str
    version: str
    verdict: Verdict
    risk_score: float
    confidence: float
    reasons: list[str]
    metrics: dict[str, Any]
    components: list[RiskComponent]

    def to_riskapi_score(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "version": self.version,
            "verdict": self.verdict.value,
            "risk_score": round(self.risk_score, 6),
            "confidence": round(self.confidence, 6),
            "reasons": self.reasons,
            "metrics": self.metrics,
            "components": [
                {
                    "name": component.name,
                    "risk": round(component.risk, 6),
                    "weight": round(component.weight, 6),
                    "reason": component.reason,
                    "metrics": component.metrics,
                }
                for component in self.components
            ],
        }
