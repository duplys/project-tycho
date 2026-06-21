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
                    "negotiated_cipher_suite": latest.get("negotiated_cipher_suite"),
                    "error": latest.get("error"),
                }
            )
        return rows

    def get_pqc_adoption_over_time(
        self,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        data = self._load_store()
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
