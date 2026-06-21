from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

DEFAULT_OBSERVATORY_DATA_FILE = Path("/var/pqc-obs/data/observatory-data.json")


def get_observatory_data_file() -> Path:
    return Path(
        os.getenv(
            "TLS_VISUALIZER_OBSERVATORY_DATA_FILE",
            str(DEFAULT_OBSERVATORY_DATA_FILE),
        )
    ).expanduser()


def _parse_datetime(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def load_observatory_data(storage_file: Path | None = None) -> dict[str, Any]:
    path = storage_file or get_observatory_data_file()
    if not path.exists():
        return {"targets": [], "scans": []}
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid observatory data file: expected object at {path}")
    data.setdefault("targets", [])
    data.setdefault("scans", [])
    return data


def _targets_by_id(data: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {target["id"]: target for target in data["targets"]}


def _iter_scan_handshakes(data: dict[str, Any]):
    targets = _targets_by_id(data)
    for scan in data["scans"]:
        analyzer_output = scan.get("analyzer_output")
        if analyzer_output is None:
            continue
        if isinstance(analyzer_output, list):
            handshakes = analyzer_output
        else:
            handshakes = [analyzer_output]
        for index, handshake in enumerate(handshakes):
            if not isinstance(handshake, dict):
                continue
            target = targets.get(scan["target_id"], {})
            handshake_id = str(scan["id"])
            if len(handshakes) > 1:
                handshake_id = f"{scan['id']}:{index}"
            yield handshake_id, scan, target, handshake


def get_observatory_handshake_summaries() -> list[dict[str, Any]]:
    data = load_observatory_data()
    summaries: list[dict[str, Any]] = []
    for handshake_id, scan, target, handshake in _iter_scan_handshakes(data):
        server_hello = handshake.get("server_hello") or {}
        summary: dict[str, Any] = {
            "id": handshake_id,
            "scan_id": scan["id"],
            "target": {
                "hostname": target.get("hostname"),
                "port": target.get("port"),
                "category": target.get("category"),
            },
            "scanned_at": scan["scanned_at"],
            "probe_group": scan.get("probe_group"),
            "pcap_path": scan.get("pcap_path"),
            "is_pqc": server_hello.get("is_pqc", scan.get("is_pqc")),
            "is_hybrid": server_hello.get("is_hybrid", scan.get("is_hybrid")),
            "selected_group": server_hello.get(
                "selected_group", scan.get("selected_group")
            ),
            "negotiated_cipher_suite": server_hello.get(
                "negotiated_cipher_suite", scan.get("negotiated_cipher_suite")
            ),
        }
        capture_metadata = handshake.get("capture_metadata")
        if capture_metadata is not None:
            summary["capture_metadata"] = capture_metadata
        summaries.append(summary)
    return summaries


def get_observatory_handshake(handshake_id: str) -> dict[str, Any] | None:
    data = load_observatory_data()
    for current_id, _scan, _target, handshake in _iter_scan_handshakes(data):
        if current_id == handshake_id:
            return handshake
    return None


def get_latest_scan_per_target() -> list[dict[str, Any]]:
    data = load_observatory_data()
    latest_scans: dict[int, dict[str, Any]] = {}
    for scan in data["scans"]:
        target_id = scan["target_id"]
        current = latest_scans.get(target_id)
        if current is None or _parse_datetime(scan["scanned_at"]) > _parse_datetime(
            current["scanned_at"]
        ):
            latest_scans[target_id] = scan

    rows: list[dict[str, Any]] = []
    for target in sorted(
        (target for target in data["targets"] if target.get("is_active", True)),
        key=lambda item: item["hostname"],
    ):
        latest = latest_scans.get(target["id"])
        if latest is None:
            continue
        rows.append(
            {
                "hostname": target["hostname"],
                "port": target["port"],
                "category": target["category"],
                "scanned_at": latest["scanned_at"],
                "is_pqc": latest.get("is_pqc"),
                "is_hybrid": latest.get("is_hybrid"),
                "selected_group": latest.get("selected_group"),
                "probe_group": latest.get("probe_group"),
                "negotiated_cipher_suite": latest.get("negotiated_cipher_suite"),
                "error": latest.get("error"),
            }
        )
    return rows


def get_pqc_adoption_over_time(
    since: datetime | None = None,
) -> list[dict[str, Any]]:
    data = load_observatory_data()
    grouped: dict[date, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "pqc_count": 0}
    )

    for scan in data["scans"]:
        if scan.get("error") is not None or scan.get("is_pqc") is None:
            continue
        scanned_at = _parse_datetime(scan["scanned_at"])
        if since and scanned_at < since:
            continue
        scan_date = scanned_at.date()
        grouped[scan_date]["total"] += 1
        if scan.get("is_pqc"):
            grouped[scan_date]["pqc_count"] += 1

    rows = []
    for scan_date in sorted(grouped):
        total = grouped[scan_date]["total"]
        pqc_count = grouped[scan_date]["pqc_count"]
        rows.append(
            {
                "date": scan_date.isoformat(),
                "total": total,
                "pqc_count": pqc_count,
                "pct_pqc": round(100 * pqc_count / total, 2) if total > 0 else 0.0,
            }
        )
    return rows


def get_algorithm_popularity(
    since: datetime | None = None,
) -> list[dict[str, Any]]:
    data = load_observatory_data()
    counts: Counter[str] = Counter()
    for scan in data["scans"]:
        selected_group = scan.get("selected_group")
        if scan.get("error") is not None or selected_group is None:
            continue
        scanned_at = _parse_datetime(scan["scanned_at"])
        if since and scanned_at < since:
            continue
        counts[selected_group] += 1

    return [
        {"selected_group": selected_group, "count": count}
        for selected_group, count in counts.most_common()
    ]
