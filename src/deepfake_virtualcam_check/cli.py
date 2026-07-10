from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from deepfake_stream_signature import parse_key_value_pairs

from deepfake_virtualcam_check.gateway import (
    collect_tcp_proxy_packet_envelopes,
    load_jsonl_packet_envelopes,
    load_length_prefixed_packet_envelopes,
    stream_input_from_gateway_packets,
)
from deepfake_virtualcam_check.scorer import score_stream
from deepfake_virtualcam_check.serialization import load_stream_check, source_from_json_file


def main(argv: list[str] | None = None) -> int:
    argv = _normalize_argv(list(sys.argv[1:] if argv is None else argv))
    parser = argparse.ArgumentParser(
        prog="deepfake-virtualcam-check",
        description="Score virtual-camera, replay, signature, and liveness signals for a video stream.",
    )
    subparsers = parser.add_subparsers(dest="command")

    score_parser = subparsers.add_parser("score", help="Score normalized StreamCheckInput JSON.")
    score_parser.add_argument("input", nargs="?", help="Path to JSON input. Reads stdin when omitted or '-'.")
    score_parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")

    jsonl_parser = subparsers.add_parser(
        "gateway-jsonl",
        help="Score media gateway packets from JSONL lines with packet_b64 fields.",
    )
    _add_gateway_args(jsonl_parser)
    jsonl_parser.add_argument("input", nargs="?", help="Path to JSONL input. Reads stdin when omitted or '-'.")

    stream_parser = subparsers.add_parser(
        "gateway-stream",
        help="Score media gateway packets from stream-mode length-prefixed binary frames.",
    )
    _add_gateway_args(stream_parser)
    stream_parser.add_argument("input", help="Path to binary capture file.")

    tcp_proxy_parser = subparsers.add_parser(
        "gateway-tcp-proxy",
        help="Proxy stream-mode TCP traffic, forward it upstream, and score one client-to-server capture window.",
    )
    _add_gateway_args(tcp_proxy_parser)
    tcp_proxy_parser.add_argument("--listen-host", default="127.0.0.1", help="Local TCP proxy bind host.")
    tcp_proxy_parser.add_argument("--listen-port", type=int, default=13000, help="Local TCP proxy bind port.")
    tcp_proxy_parser.add_argument("--upstream-host", default="127.0.0.1", help="Upstream TCP host.")
    tcp_proxy_parser.add_argument("--upstream-port", type=int, default=13001, help="Upstream TCP port.")
    tcp_proxy_parser.add_argument("--duration", type=float, default=5.0, help="Capture duration in seconds.")
    tcp_proxy_parser.add_argument(
        "--accept-timeout",
        type=float,
        default=120.0,
        help="Seconds to wait for stream_client before starting the capture window.",
    )

    args = parser.parse_args(argv)
    command = args.command or "score"

    if command == "score":
        raw = _read_input(args.input)
        payload = load_stream_check(raw)
    elif command == "gateway-jsonl":
        envelopes = load_jsonl_packet_envelopes(_read_input(args.input).splitlines())
        payload = _gateway_payload_from_args(args, envelopes)
    elif command == "gateway-stream":
        envelopes = load_length_prefixed_packet_envelopes(Path(args.input).read_bytes())
        payload = _gateway_payload_from_args(args, envelopes)
    elif command == "gateway-tcp-proxy":
        envelopes = collect_tcp_proxy_packet_envelopes(
            listen_host=args.listen_host,
            listen_port=args.listen_port,
            upstream_host=args.upstream_host,
            upstream_port=args.upstream_port,
            duration_s=args.duration,
            accept_timeout_s=args.accept_timeout,
            max_frames=args.max_frames,
        )
        payload = _gateway_payload_from_args(args, envelopes)
    else:
        parser.error(f"unknown command: {command}")

    score = score_stream(payload).to_riskapi_score()
    json.dump(score, sys.stdout, ensure_ascii=False, indent=2 if args.pretty else None)
    sys.stdout.write("\n")
    return 0


def _read_input(path: str | None) -> str:
    if path is None or path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _normalize_argv(argv: list[str]) -> list[str]:
    commands = {
        "score",
        "gateway-jsonl",
        "gateway-stream",
        "gateway-tcp-proxy",
        "-h",
        "--help",
    }
    if not argv:
        return ["score"]
    if argv[0] in commands:
        return argv
    return ["score", *argv]


def _add_gateway_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--uid")
    parser.add_argument("--check-id")
    parser.add_argument("--session-id")
    parser.add_argument("--signature-status")
    parser.add_argument(
        "--signature-trusted-key",
        action="append",
        default=[],
        help="Trusted stream signature key in key_id=secret format. Can be passed multiple times.",
    )
    parser.add_argument("--source-json", help="Path to source metadata JSON.")
    parser.add_argument("--device-label")
    parser.add_argument("--width", type=int)
    parser.add_argument("--height", type=int)
    parser.add_argument("--fps", type=float)
    parser.add_argument("--max-frames", type=int)
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")


def _gateway_payload_from_args(args: argparse.Namespace, envelopes):
    source = source_from_json_file(args.source_json) if args.source_json else None
    if source is not None:
        source = _override_source(source, args)
    else:
        from deepfake_virtualcam_check.models import SourceSignals

        source = SourceSignals(
            device_label=args.device_label,
            width=args.width,
            height=args.height,
            fps=args.fps,
        )
    return stream_input_from_gateway_packets(
        envelopes,
        uid=args.uid,
        check_id=args.check_id,
        session_id=args.session_id,
        source=source,
        signature_status=args.signature_status,
        trusted_signature_keys=parse_key_value_pairs(args.signature_trusted_key),
        max_frames=args.max_frames,
    )


def _override_source(source, args: argparse.Namespace):
    from deepfake_virtualcam_check.models import SourceSignals

    return SourceSignals(
        device_label=args.device_label if args.device_label is not None else source.device_label,
        user_agent=source.user_agent,
        width=args.width if args.width is not None else source.width,
        height=args.height if args.height is not None else source.height,
        fps=args.fps if args.fps is not None else source.fps,
        capture_surface=source.capture_surface,
        display_surface=source.display_surface,
        settings=source.settings,
    )


if __name__ == "__main__":
    raise SystemExit(main())
