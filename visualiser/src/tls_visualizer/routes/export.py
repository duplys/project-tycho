from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from tls_visualizer.tikz.generator import (
    generate_handshake_flow_tikz,
    generate_key_share_comparison_tikz,
)

router = APIRouter()


def _get_store():
    from tls_visualizer.app import handshake_store
    return handshake_store


@router.get("/handshakes/{record_id}/export/tikz/handshake-flow")
def export_handshake_flow(record_id: str):
    store = _get_store()
    record = store.get(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Handshake record not found")
    tex_source = generate_handshake_flow_tikz(record)
    return PlainTextResponse(
        content=tex_source,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=handshake-flow.tex"},
    )


@router.get("/handshakes/{record_id}/export/tikz/key-share-comparison")
def export_key_share_comparison(record_id: str):
    store = _get_store()
    record = store.get(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Handshake record not found")
    tex_source = generate_key_share_comparison_tikz(record)
    return PlainTextResponse(
        content=tex_source,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=key-share-comparison.tex"},
    )
