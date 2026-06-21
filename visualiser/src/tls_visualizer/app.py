from pathlib import Path
import os
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from tls_visualizer.routes.observatory import router as observatory_router
from tls_visualizer.routes.handshake import router as handshake_router
from tls_visualizer.routes.export import router as export_router
from tls_visualizer.models import TLSHandshakeRecord


logger = logging.getLogger(__name__)

app = FastAPI(
    title="TLS Visualizer",
    description="Visualize TLS handshake data with PQC/hybrid analysis and LaTeX export",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store: {uuid_str: TLSHandshakeRecord}
handshake_store: dict[str, TLSHandshakeRecord] = {}

app.include_router(handshake_router, prefix="/api")
app.include_router(export_router, prefix="/api")
app.include_router(observatory_router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}


def _resolve_frontend_dist() -> Path | None:
    env_dist = os.getenv("TLS_VISUALIZER_FRONTEND_DIST")
    candidates: list[Path] = []
    if env_dist:
        candidates.append(Path(env_dist).expanduser())

    candidates.extend(
        [
            Path("/app/frontend/dist"),
            Path(__file__).parent.parent.parent / "frontend" / "dist",
            Path.cwd() / "frontend" / "dist",
        ]
    )

    for candidate in candidates:
        index_file = candidate / "index.html"
        if candidate.is_dir() and index_file.is_file():
            return candidate
    return None


_frontend_dist = _resolve_frontend_dist()
if _frontend_dist:
    logger.info("Serving frontend assets from %s", _frontend_dist)
    app.mount("/", StaticFiles(directory=str(_frontend_dist), html=True), name="static")
else:
    logger.warning("Frontend dist not found; running API-only mode")


def main():
    import uvicorn
    uvicorn.run("tls_visualizer.app:app", host="0.0.0.0", port=8000, reload=True)
