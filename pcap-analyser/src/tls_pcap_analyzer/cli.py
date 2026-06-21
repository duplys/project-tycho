"""
Command-line interface for the TLS PCAP Analyzer.

Usage
-----
    tls-pcap-analyzer capture.pcap
    tls-pcap-analyzer capture.pcap --all
    tls-pcap-analyzer capture.pcap --output result.json
    tls-pcap-analyzer capture.pcap --pretty
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from .parser import parse_pcap


def _to_json_serialisable(obj):
    """Recursively convert dataclasses to plain dicts/lists."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_json_serialisable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_json_serialisable(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _to_json_serialisable(v) for k, v in obj.items()}
    return obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tls-pcap-analyzer",
        description=(
            "Parse a pcap file and extract TLS handshake information "
            "with first-class support for PQC and hybrid algorithms."
        ),
    )
    parser.add_argument(
        "pcap",
        metavar="PCAP_FILE",
        help="Path to the pcap (or pcapng) file to analyse.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest="all_connections",
        help=(
            "Output all TLS connections found in the capture as a JSON array. "
            "By default only the first connection is emitted."
        ),
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write JSON output to FILE instead of stdout.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the JSON output (indent=2).",
    )
    args = parser.parse_args(argv)

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print(f"error: file not found: {pcap_path}", file=sys.stderr)
        return 1

    try:
        records = parse_pcap(pcap_path)
    except Exception as exc:  # noqa: BLE001
        print(f"error: failed to parse pcap: {exc}", file=sys.stderr)
        return 1

    if not records:
        print("warning: no TLS handshakes found in the capture.", file=sys.stderr)
        result = [] if args.all_connections else None
    elif args.all_connections:
        result = [_to_json_serialisable(r) for r in records]
    else:
        result = _to_json_serialisable(records[0])

    indent = 2 if args.pretty else None
    output_text = json.dumps(result, indent=indent)

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Wrote {len(records)} connection(s) → {args.output}", file=sys.stderr)
    else:
        print(output_text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
