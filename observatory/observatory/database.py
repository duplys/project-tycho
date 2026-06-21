"""File-backed persistence layer for targets and scan history."""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from datetime import UTC, date, datetime
from pathlib import Path
from threading import RLock
from typing import Any

from observatory.config import settings
from observatory.models import HandshakeData, ScanResult, Target

log = logging.getLogger(__name__)

_STORE_VERSION = 1
_LOCK = RLock()


def _empty_store() -> dict[str, Any]:
    return {
        "version": _STORE_VERSION,
        "next_target_id": 1,
        "next_scan_id": 1,
        "targets": [],
        "scans": [],
    }


def _tmp_path(storage_file: Path) -> Path:
    return storage_file.with_name(f"{storage_file.name}.tmp")


def _parse_datetime(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _ensure_store_file(storage_file: Path | None = None) -> Path:
    path = storage_file or settings.storage_file
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        tmp_path = _tmp_path(path)
        tmp_path.write_text(json.dumps(_empty_store(), indent=2) + "\n", encoding="utf-8")
        tmp_path.replace(path)
        log.info("Created observatory data file at %s", path)
    return path


def _load_store(storage_file: Path | None = None) -> dict[str, Any]:
    path = _ensure_store_file(storage_file)
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid observatory data file: expected object at {path}")
    data.setdefault("version", _STORE_VERSION)
    data.setdefault("next_target_id", 1)
    data.setdefault("next_scan_id", 1)
    data.setdefault("targets", [])
    data.setdefault("scans", [])
    return data


def _write_store(data: dict[str, Any], storage_file: Path | None = None) -> None:
    path = _ensure_store_file(storage_file)
    tmp_path = _tmp_path(path)
    tmp_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp_path.replace(path)


def apply_schema() -> None:
    """Create the observatory data file if it does not already exist."""
    with _LOCK:
        _ensure_store_file()
    log.info("Observatory data file ready.")


def upsert_target(target: Target) -> int:
    """Insert or update a target entry and return its stable integer id."""
    with _LOCK:
        data = _load_store()
        for stored_target in data["targets"]:
            if (
                stored_target["hostname"] == target.hostname
                and stored_target["port"] == target.port
            ):
                stored_target.update(
                    {
                        "category": target.category,
                        "is_active": target.is_active,
                        "notes": target.notes,
                    }
                )
                _write_store(data)
                return stored_target["id"]

        target_id = data["next_target_id"]
        data["next_target_id"] += 1
        data["targets"].append(
            {
                "id": target_id,
                "hostname": target.hostname,
                "port": target.port,
                "category": target.category,
                "is_active": target.is_active,
                "notes": target.notes,
                "added_at": datetime.now(UTC).isoformat(),
            }
        )
        _write_store(data)
        return target_id


def get_active_targets() -> list[dict[str, Any]]:
    """Return all active targets as dictionaries."""
    with _LOCK:
        data = _load_store()
        return [
            target.copy()
            for target in data["targets"]
            if target.get("is_active", True)
        ]


def insert_scan(target_id: int, result: ScanResult) -> int:
    """Persist a scan result and return the new scan id."""
    with _LOCK:
        data = _load_store()
        handshake: HandshakeData | None = result.handshake
        scan_id = data["next_scan_id"]
        data["next_scan_id"] += 1
        data["scans"].append(
            {
                "id": scan_id,
                "target_id": target_id,
                "scanned_at": result.scanned_at.isoformat(),
                "probe_group": result.probe_group,
                "pcap_path": result.pcap_path,
                "analyzer_output": result.analyzer_output,
                "tls_version": handshake.tls_version if handshake else None,
                "negotiated_cipher_suite": (
                    handshake.negotiated_cipher_suite if handshake else None
                ),
                "selected_group": handshake.selected_group if handshake else None,
                "key_share_size_bytes": (
                    handshake.key_share_size_bytes if handshake else None
                ),
                "is_pqc": handshake.is_pqc if handshake else None,
                "is_hybrid": handshake.is_hybrid if handshake else None,
                "pqc_algorithms": (
                    handshake.pqc_algorithms_detected if handshake else None
                ),
                "signature_algorithm": (
                    handshake.signature_algorithm if handshake else None
                ),
                "error": result.error,
                "scan_duration_ms": result.scan_duration_ms,
            }
        )
        _write_store(data)
        return scan_id


def get_pqc_adoption_over_time(
    since: datetime | None = None,
) -> list[dict[str, Any]]:
    """Return daily PQC adoption rates."""
    with _LOCK:
        data = _load_store()

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
        totals = grouped[scan_date]
        total = totals["total"]
        pqc_count = totals["pqc_count"]
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
    """Return counts of each negotiated group across all scans."""
    with _LOCK:
        data = _load_store()

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


def get_latest_scan_per_target() -> list[dict[str, Any]]:
    """Return the latest scan row for every active target."""
    with _LOCK:
        data = _load_store()

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
                "scanned_at": _parse_datetime(latest["scanned_at"]),
                "is_pqc": latest.get("is_pqc"),
                "is_hybrid": latest.get("is_hybrid"),
                "selected_group": latest.get("selected_group"),
                "probe_group": latest.get("probe_group"),
                "negotiated_cipher_suite": latest.get("negotiated_cipher_suite"),
                "error": latest.get("error"),
            }
        )
    return rows
