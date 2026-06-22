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

_STORE_VERSION = 3
_LOCK = RLock()


def _empty_store() -> dict[str, Any]:
    return {
        "version": _STORE_VERSION,
        "next_target_id": 1,
        "next_scan_id": 1,
        "scanner_capabilities": None,
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


def _scan_round_key(scan: dict[str, Any]) -> str:
    """Return a persisted round ID or a stable synthetic ID for legacy rows."""
    return scan.get("scan_round_id") or f"legacy:{scan['id']}"


def _probe_status(scan: dict[str, Any]) -> str:
    if scan.get("error") is not None:
        return "failed"
    if scan.get("selected_group") is not None:
        return "supported"
    return "unknown"


def _group_scans_by_target_round(
    scans: list[dict[str, Any]],
) -> dict[tuple[int, str], list[dict[str, Any]]]:
    grouped: dict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)
    for scan in scans:
        grouped[(scan["target_id"], _scan_round_key(scan))].append(scan)
    return grouped


def _aggregate_target_round(
    target: dict[str, Any], round_id: str, scans: list[dict[str, Any]]
) -> dict[str, Any]:
    ordered = sorted(scans, key=lambda scan: _parse_datetime(scan["scanned_at"]))
    probe_results = []
    supported_groups: list[str] = []
    failed_groups: list[str] = []
    unknown_groups: list[str] = []

    for scan in ordered:
        status = _probe_status(scan)
        group = scan.get("probe_group") or scan.get("selected_group")
        if group:
            destination = {
                "supported": supported_groups,
                "failed": failed_groups,
                "unknown": unknown_groups,
            }[status]
            if group not in destination:
                destination.append(group)
        probe_results.append(
            {
                "scan_id": scan["id"],
                "probe_group": scan.get("probe_group"),
                "scanned_at": _parse_datetime(scan["scanned_at"]),
                "status": status,
                "selected_group": scan.get("selected_group"),
                "is_pqc": scan.get("is_pqc"),
                "is_hybrid": scan.get("is_hybrid"),
                "negotiated_cipher_suite": scan.get("negotiated_cipher_suite"),
                "error": scan.get("error"),
            }
        )

    return {
        "hostname": target["hostname"],
        "port": target["port"],
        "category": target["category"],
        "scan_round_id": round_id,
        "scanned_at": _parse_datetime(ordered[-1]["scanned_at"]),
        "is_pqc": any(
            _probe_status(scan) == "supported" and scan.get("is_pqc") is True
            for scan in ordered
        ),
        "is_hybrid": any(
            _probe_status(scan) == "supported" and scan.get("is_hybrid") is True
            for scan in ordered
        ),
        "supported_groups": supported_groups,
        "failed_groups": failed_groups,
        "unknown_groups": unknown_groups,
        "successful_probe_count": sum(
            _probe_status(scan) == "supported" for scan in ordered
        ),
        "failed_probe_count": sum(_probe_status(scan) == "failed" for scan in ordered),
        "unknown_probe_count": sum(
            _probe_status(scan) == "unknown" for scan in ordered
        ),
        "probe_results": probe_results,
    }


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
    data["version"] = _STORE_VERSION
    data.setdefault("next_target_id", 1)
    data.setdefault("next_scan_id", 1)
    data.setdefault("scanner_capabilities", None)
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
        data = _load_store()
        _write_store(data)
    log.info("Observatory data file ready.")


def update_scanner_capabilities(
    *,
    checked_at: datetime,
    client_version: str,
    configured_groups: list[str],
    supported_groups: list[str],
    unsupported_groups: list[str],
) -> None:
    """Persist scanner capabilities without adding target scan records."""
    with _LOCK:
        data = _load_store()
        data["scanner_capabilities"] = {
            "checked_at": checked_at.isoformat(),
            "client": "openssl",
            "version": client_version,
            "configured_groups": configured_groups,
            "supported_groups": supported_groups,
            "unsupported_groups": unsupported_groups,
        }
        _write_store(data)


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
                "scan_round_id": result.scan_round_id,
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

    for round_scans in _group_scans_by_target_round(data["scans"]).values():
        ordered = sorted(round_scans, key=lambda scan: _parse_datetime(scan["scanned_at"]))
        round_time = _parse_datetime(ordered[0]["scanned_at"])
        if since and round_time < since:
            continue
        statuses = [_probe_status(scan) for scan in ordered]
        if all(status == "unknown" for status in statuses):
            continue
        scan_date = round_time.date()
        grouped[scan_date]["total"] += 1
        if any(
            status == "supported" and scan.get("is_pqc") is True
            for status, scan in zip(statuses, ordered, strict=True)
        ):
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
    """Return an aggregate of the latest scan round for every active target."""
    with _LOCK:
        data = _load_store()

    rounds = _group_scans_by_target_round(data["scans"])
    latest_rounds: dict[int, tuple[str, list[dict[str, Any]]]] = {}
    for (target_id, round_id), scans in rounds.items():
        round_time = max(_parse_datetime(scan["scanned_at"]) for scan in scans)
        current = latest_rounds.get(target_id)
        if current is None or round_time > max(
            _parse_datetime(scan["scanned_at"]) for scan in current[1]
        ):
            latest_rounds[target_id] = (round_id, scans)

    rows: list[dict[str, Any]] = []
    for target in sorted(
        (target for target in data["targets"] if target.get("is_active", True)),
        key=lambda item: item["hostname"],
    ):
        latest = latest_rounds.get(target["id"])
        if latest is None:
            continue
        round_id, scans = latest
        rows.append(_aggregate_target_round(target, round_id, scans))
    return rows
