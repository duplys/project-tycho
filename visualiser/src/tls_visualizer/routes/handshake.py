import uuid
from typing import Any

from fastapi import APIRouter, HTTPException

from tls_visualizer.models import TLSHandshakeRecord

router = APIRouter()


def _get_store() -> dict[str, TLSHandshakeRecord]:
    from tls_visualizer.app import handshake_store
    return handshake_store


@router.post("/handshakes", status_code=200)
def create_handshake(record: TLSHandshakeRecord) -> dict[str, Any]:
    store = _get_store()
    record_id = str(uuid.uuid4())
    store[record_id] = record
    return {"id": record_id, "data": record.model_dump()}


@router.get("/handshakes")
def list_handshakes() -> list[dict[str, Any]]:
    store = _get_store()
    summaries = []
    for record_id, record in store.items():
        summary: dict[str, Any] = {"id": record_id}
        if record.capture_metadata:
            summary["capture_metadata"] = record.capture_metadata.model_dump()
        is_pqc = None
        if record.server_hello:
            is_pqc = record.server_hello.is_pqc
        summary["is_pqc"] = is_pqc
        summaries.append(summary)
    return summaries


@router.get("/handshakes/{record_id}")
def get_handshake(record_id: str) -> dict[str, Any]:
    store = _get_store()
    record = store.get(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Handshake record not found")
    return {"id": record_id, "data": record.model_dump()}


@router.delete("/handshakes/{record_id}", status_code=200)
def delete_handshake(record_id: str) -> dict[str, str]:
    store = _get_store()
    if record_id not in store:
        raise HTTPException(status_code=404, detail="Handshake record not found")
    del store[record_id]
    return {"status": "deleted", "id": record_id}
