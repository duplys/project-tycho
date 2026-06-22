from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any


def _parse_datetime(value: str | datetime) -> datetime:
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _scan_round_key(scan: dict[str, Any]) -> str:
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
    groups: dict[str, list[str]] = {
        "supported": [],
        "failed": [],
        "unknown": [],
    }
    probe_results: list[dict[str, Any]] = []
    for scan in ordered:
        status = _probe_status(scan)
        group = scan.get("probe_group") or scan.get("selected_group")
        if group and group not in groups[status]:
            groups[status].append(group)
        probe_results.append(
            {
                "scan_id": scan["id"],
                "probe_group": scan.get("probe_group"),
                "scanned_at": scan["scanned_at"],
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
        "scanned_at": ordered[-1]["scanned_at"],
        "is_pqc": any(
            _probe_status(scan) == "supported" and scan.get("is_pqc") is True
            for scan in ordered
        ),
        "is_hybrid": any(
            _probe_status(scan) == "supported" and scan.get("is_hybrid") is True
            for scan in ordered
        ),
        "supported_groups": groups["supported"],
        "failed_groups": groups["failed"],
        "unknown_groups": groups["unknown"],
        "successful_probe_count": sum(
            _probe_status(scan) == "supported" for scan in ordered
        ),
        "failed_probe_count": sum(_probe_status(scan) == "failed" for scan in ordered),
        "unknown_probe_count": sum(
            _probe_status(scan) == "unknown" for scan in ordered
        ),
        "probe_results": probe_results,
    }


class ObservatoryConnector:
    def __init__(self, data_file: Path) -> None:
        self.data_file = data_file

    def _load_store(self) -> dict[str, Any]:
        if not self.data_file.exists():
            raise FileNotFoundError(
                f"Observatory data file not found: {self.data_file}"
            )
        with self.data_file.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError(
                f"Invalid Observatory data file, expected object: {self.data_file}"
            )
        data.setdefault("targets", [])
        data.setdefault("scans", [])
        return data

    def get_latest_scan_per_target(self) -> list[dict[str, Any]]:
        data = self._load_store()
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

    def get_pqc_adoption_over_time(
        self,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        data = self._load_store()
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
        self,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        data = self._load_store()
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

    def get_recent_scans(
        self,
        limit: int = 20,
        since: datetime | None = None,
        only_with_analyzer_output: bool = True,
    ) -> list[dict[str, Any]]:
        data = self._load_store()
        scans = []
        for scan in data["scans"]:
            scanned_at = _parse_datetime(scan["scanned_at"])
            if since and scanned_at < since:
                continue
            if only_with_analyzer_output and not scan.get("analyzer_output"):
                continue
            scans.append(scan)
        scans.sort(key=lambda item: _parse_datetime(item["scanned_at"]), reverse=True)
        return scans[:limit]

    def build_research_context(self, since: datetime | None = None) -> dict[str, Any]:
        adoption = self.get_pqc_adoption_over_time(since=since)
        algorithms = self.get_algorithm_popularity(since=since)
        latest_status = self.get_latest_scan_per_target()
        recent_scans = self.get_recent_scans(limit=30, since=since)
        total_considered = sum(row["total"] for row in adoption)
        total_pqc = sum(row["pqc_count"] for row in adoption)
        pqc_ratio = (100.0 * total_pqc / total_considered) if total_considered else 0.0

        return {
            "adoption": adoption,
            "algorithms": algorithms[:10],
            "latest_status": latest_status,
            "recent_scans": recent_scans,
            "total_scans_considered": total_considered,
            "total_pqc_scans": total_pqc,
            "pct_pqc_overall": round(pqc_ratio, 2),
        }
