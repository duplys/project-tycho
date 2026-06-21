from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException

from tls_visualizer.observatory_store import (
    get_algorithm_popularity,
    get_observatory_handshake,
    get_observatory_handshake_summaries,
    get_latest_scan_per_target,
    get_pqc_adoption_over_time,
)

router = APIRouter()


def _parse_since(since: str | None) -> datetime | None:
    if since is None:
        return None
    try:
        parsed = datetime.fromisoformat(since)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid date format: {since} (expected YYYY-MM-DD)",
        ) from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


@router.get("/observatory/status")
def observatory_status():
    return get_latest_scan_per_target()


@router.get("/observatory/adoption")
def observatory_adoption(since: str | None = None):
    return get_pqc_adoption_over_time(since=_parse_since(since))


@router.get("/observatory/algorithms")
def observatory_algorithms(since: str | None = None):
    return get_algorithm_popularity(since=_parse_since(since))


@router.get("/observatory/handshakes")
def observatory_handshakes():
    return get_observatory_handshake_summaries()


@router.get("/observatory/handshakes/{handshake_id}")
def observatory_handshake(handshake_id: str):
    record = get_observatory_handshake(handshake_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Observatory handshake not found")
    return record
