from __future__ import annotations

import hashlib
import json
import sys
import types
import unittest

from deepfake_media_transport import Codec, MediaPacket, PacketHeader, StreamType
from deepfake_stream_signature import SignatureConfig, StreamPacket, StreamPacketHeader, StreamSigner

from deepfake_virtualcam_check import (
    ActiveChallengeSignals,
    FrameObservation,
    SourceSignals,
    StreamCheckInput,
    Verdict,
    score_stream,
)
from deepfake_virtualcam_check.gateway import (
    PacketEnvelope,
    _face_bbox_cv2_with_status,
    frame_observation_from_packet,
    stream_input_from_gateway_packets,
)


class VirtualCamScorerTest(unittest.TestCase):
    def test_scores_clean_trusted_stream_as_genuine(self) -> None:
        payload = StreamCheckInput(
            signature_status="trusted",
            source=SourceSignals(device_label="Integrated Camera", width=1280, height=720, fps=30),
            frames=human_like_frames(),
            active_challenge=ActiveChallengeSignals(
                live_probability=0.91,
                verdict="live",
                response_score=0.35,
                mean_latency_ms=120,
            ),
        )

        result = score_stream(payload)

        self.assertEqual(Verdict.GENUINE, result.verdict)
        self.assertLess(result.risk_score, 0.28)
        self.assertGreater(result.confidence, 0.55)

    def test_flags_known_virtual_camera_with_frozen_frames(self) -> None:
        payload = StreamCheckInput(
            signature_status="absent",
            source=SourceSignals(device_label="OBS Virtual Camera", width=1920, height=1080, fps=30),
            frames=virtual_replay_frames(),
            active_challenge=ActiveChallengeSignals(
                spoof_probability=0.78,
                verdict="spoof",
                response_score=0.02,
                mean_latency_ms=520,
            ),
        )

        result = score_stream(payload)

        self.assertEqual(Verdict.FAKE, result.verdict)
        self.assertGreaterEqual(result.risk_score, 0.78)
        self.assertIn("known_virtual_camera_device_label", result.reasons)

    def test_known_virtual_camera_label_dominates_clean_lit_stream(self) -> None:
        payload = StreamCheckInput(
            signature_status="trusted",
            source=SourceSignals(device_label="OBS Virtual Camera", width=1280, height=720, fps=30),
            frames=human_like_frames(),
            active_challenge=ActiveChallengeSignals(
                live_probability=0.94,
                verdict="live",
                response_score=0.42,
                mean_latency_ms=110,
            ),
        )

        result = score_stream(payload)

        self.assertEqual(Verdict.FAKE, result.verdict)
        self.assertGreaterEqual(result.risk_score, 0.78)
        self.assertIn("known_virtual_camera_device_label", result.reasons)

    def test_tampered_signature_dominates_sparse_stream(self) -> None:
        payload = StreamCheckInput(
            signature_status="tampered",
            source=SourceSignals(device_label="USB Camera"),
            frames=human_like_frames(count=8),
        )

        result = score_stream(payload)

        self.assertEqual(Verdict.FAKE, result.verdict)
        self.assertGreater(result.risk_score, 0.78)

    def test_result_is_json_serializable_for_riskapi(self) -> None:
        result = score_stream(
            StreamCheckInput(
                uid="u1",
                check_id="c1",
                signature_status="trusted",
                source=SourceSignals(device_label="Integrated Camera"),
                frames=human_like_frames(),
            )
        )

        encoded = json.dumps(result.to_riskapi_score(), allow_nan=False)

        self.assertIn("deepfake-virtualcam-check", encoded)

    def test_builds_stream_input_from_gateway_video_packets(self) -> None:
        packet = gateway_packet(sequence_number=1, timestamp_us=33_000, payload=b"\xff\xd8jpeg\xff\xd9")

        payload = stream_input_from_gateway_packets(
            [PacketEnvelope(packet=packet, received_at_us=100_000, signature_status="trusted")],
            signature_status=None,
        )

        self.assertEqual(1, len(payload.frames))
        self.assertEqual("trusted", payload.signature_status)
        self.assertEqual(packet.header.session_id.hex(), payload.session_id)
        self.assertEqual(64, len(payload.frames[0].content_hash or ""))

    def test_frame_observation_uses_gateway_header_timing(self) -> None:
        packet = gateway_packet(sequence_number=7, timestamp_us=231_000, payload=b"not-a-real-jpeg")

        frame = frame_observation_from_packet(packet, received_at_us=250_000)

        self.assertEqual(7, frame.sequence_number)
        self.assertEqual(231_000, frame.timestamp_us)
        self.assertEqual(250_000, frame.received_at_us)
        self.assertIsNotNone(frame.perceptual_hash)

    def test_strips_trusted_signature_envelope_before_frame_metrics(self) -> None:
        raw_payload = b"\xff\xd8jpeg\xff\xd9"
        packet = signed_gateway_packet(
            sequence_number=3,
            timestamp_us=99_000,
            payload=raw_payload,
            key_id="test-key",
            secret=b"test-secret",
        )

        payload = stream_input_from_gateway_packets(
            [PacketEnvelope(packet=packet, received_at_us=120_000)],
            trusted_signature_keys={"test-key": b"test-secret"},
        )

        self.assertEqual("trusted", payload.signature_status)
        self.assertEqual(hashlib.sha256(raw_payload).hexdigest(), payload.frames[0].content_hash)

    def test_absent_image_decode_metrics_do_not_claim_face_is_missing(self) -> None:
        payload = StreamCheckInput(
            signature_status="absent",
            source=SourceSignals(device_label="Integrated Camera", width=512, height=288, fps=15),
            frames=packet_only_frames(),
        )

        result = score_stream(payload)
        face_component = next(component for component in result.components if component.name == "face_content")
        encoding_component = next(component for component in result.components if component.name == "encoding")

        self.assertEqual("frame_image_decode_signals_absent", face_component.reason)
        self.assertNotIn("face_missing_in_most_frames", result.reasons)
        self.assertEqual(0.0, encoding_component.metrics["decoded_frame_ratio"])

    def test_absent_face_detector_does_not_claim_face_is_missing(self) -> None:
        payload = StreamCheckInput(
            signature_status="absent",
            source=SourceSignals(device_label="OBS Virtual Camera", width=512, height=288, fps=15),
            frames=decoded_frames_without_face_detector(),
        )

        result = score_stream(payload)
        face_component = next(component for component in result.components if component.name == "face_content")

        self.assertEqual("face_detection_signals_absent", face_component.reason)
        self.assertNotIn("face_missing_in_most_frames", result.reasons)

    def test_cv2_without_cascade_classifier_does_not_crash_face_detection(self) -> None:
        original_cv2 = sys.modules.get("cv2")
        sys.modules["cv2"] = types.SimpleNamespace(data=types.SimpleNamespace(haarcascades=""))
        try:
            self.assertEqual((None, False), _face_bbox_cv2_with_status(frame=object(), gray=object()))
        finally:
            if original_cv2 is None:
                sys.modules.pop("cv2", None)
            else:
                sys.modules["cv2"] = original_cv2


def human_like_frames(count: int = 60) -> list[FrameObservation]:
    frames = []
    timestamp = 0
    received = 100_000
    for index in range(count):
        timestamp += 33_000 + ((index % 5) - 2) * 700
        received += 33_000 + ((index % 7) - 3) * 1300
        face_w = 0.212 + (index % 6) * 0.0015
        face_h = 0.284 + (index % 5) * 0.0012
        frames.append(
            FrameObservation(
                sequence_number=index,
                timestamp_us=timestamp,
                received_at_us=received,
                content_hash=f"frame-{index}",
                perceptual_hash=f"{0x1000000000000000 + index * 0x10101:016x}",
                face_bbox=(0.39, 0.25, face_w, face_h),
                face_detection_available=True,
                brightness=92.0 + (index % 9) * 1.7,
                laplacian_var=46.0 + (index % 8),
            )
        )
    return frames


def virtual_replay_frames(count: int = 60) -> list[FrameObservation]:
    frames = []
    for index in range(count):
        reused_hash = f"loop-{index // 6}"
        frames.append(
            FrameObservation(
                sequence_number=index,
                timestamp_us=index * 33_333,
                received_at_us=200_000 + index * 33_333,
                content_hash=reused_hash,
                perceptual_hash="ffffffffffffffff",
                face_bbox=(0.40, 0.24, 0.22, 0.30),
                face_detection_available=True,
                brightness=120.0,
                laplacian_var=8.0,
            )
        )
    return frames


def decoded_frames_without_face_detector(count: int = 60) -> list[FrameObservation]:
    frames = []
    timestamp = 0
    received = 100_000
    for index in range(count):
        timestamp += 66_000 + ((index % 4) - 2) * 4000
        received += 66_000 + ((index % 5) - 2) * 4500
        frames.append(
            FrameObservation(
                sequence_number=index,
                timestamp_us=timestamp,
                received_at_us=received,
                codec="mjpeg",
                encoded_size=28_000 + (index % 7) * 700,
                width=512,
                height=288,
                content_hash=f"decoded-{index}",
                perceptual_hash=f"{0x3000000000000000 + index * 0x1010101:016x}",
                face_detection_available=False,
                brightness=95.0 + (index % 7),
                laplacian_var=38.0 + (index % 5),
            )
        )
    return frames


def packet_only_frames(count: int = 60) -> list[FrameObservation]:
    frames = []
    timestamp = 0
    received = 100_000
    for index in range(count):
        timestamp += 66_000 + ((index % 4) - 2) * 4000
        received += 66_000 + ((index % 5) - 2) * 4500
        frames.append(
            FrameObservation(
                sequence_number=index,
                timestamp_us=timestamp,
                received_at_us=received,
                codec="mjpeg",
                encoded_size=28_000 + (index % 7) * 700,
                content_hash=f"packet-{index}",
                perceptual_hash=f"{0x2000000000000000 + index * 0x1010101:016x}",
            )
        )
    return frames


def gateway_packet(sequence_number: int, timestamp_us: int, payload: bytes) -> MediaPacket:
    header = PacketHeader(
        stream_type=StreamType.VIDEO,
        codec=Codec.MJPEG,
        session_id=b"test-session".ljust(16, b"\x00"),
        sequence_number=sequence_number,
        timestamp_us=timestamp_us,
        payload_size=len(payload),
    )
    packet = MediaPacket(header=header, payload=payload)
    # Exercise the shared wire format round-trip end to end.
    assert MediaPacket.from_bytes(packet.to_bytes()) == packet
    return packet


def signed_gateway_packet(
    *,
    sequence_number: int,
    timestamp_us: int,
    payload: bytes,
    key_id: str,
    secret: bytes,
) -> MediaPacket:
    # Mirror the wire: sign via the signature library's StreamPacket, then carry
    # the signed envelope back inside a transport MediaPacket, exactly as a real
    # gateway packet arrives off the socket.
    packet = gateway_packet(sequence_number=sequence_number, timestamp_us=timestamp_us, payload=payload)
    stream_packet = StreamPacket(
        header=_stream_header(packet.header),
        payload=packet.payload,
    )
    signed = StreamSigner(
        SignatureConfig(enabled=True, key_id=key_id, secret=secret, issuer="test")
    ).sign_packet(stream_packet)
    return MediaPacket(
        header=PacketHeader(
            stream_type=packet.header.stream_type,
            codec=packet.header.codec,
            session_id=packet.header.session_id,
            sequence_number=packet.header.sequence_number,
            timestamp_us=packet.header.timestamp_us,
            payload_size=len(signed.payload),
        ),
        payload=signed.payload,
    )


def _stream_header(header: PacketHeader) -> StreamPacketHeader:
    return StreamPacketHeader(
        stream_type=int(header.stream_type),
        codec=int(header.codec),
        session_id=header.session_id,
        sequence_number=header.sequence_number,
        timestamp_us=header.timestamp_us,
        payload_size=header.payload_size,
        fragment_index=header.fragment_index,
        fragment_count=header.fragment_count,
    )


if __name__ == "__main__":
    unittest.main()
