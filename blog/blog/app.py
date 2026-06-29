from __future__ import annotations

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from blog.config import BlogSettings
from blog.routes.posts import router as posts_router
from blog.routes.build import router as build_router

settings = BlogSettings()

app = FastAPI(
    title="PQC Observatory Blog",
    description="Static blog publishing service for PQC Observatory research",
    version="0.1.0",
)

app.include_router(posts_router, prefix="/api")
app.include_router(build_router, prefix="/api")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


def _mount_static() -> None:
    site_dir = settings.site_dir
    if site_dir.is_dir() and (site_dir / "index.html").is_file():
        app.mount(
            "/",
            StaticFiles(directory=str(site_dir), html=True),
            name="static",
        )


_mount_static()
