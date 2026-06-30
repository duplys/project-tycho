from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from blog.config import BlogSettings
from blog.routes.posts import router as posts_router
from blog.routes.build import router as build_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = BlogSettings()
    settings.site_dir.mkdir(parents=True, exist_ok=True)
    app.mount(
        "/",
        StaticFiles(directory=str(settings.site_dir), html=True),
        name="static",
    )
    yield


app = FastAPI(
    title="PQC Observatory Blog",
    description="Static blog publishing service for PQC Observatory research",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(posts_router, prefix="/api")
app.include_router(build_router, prefix="/api")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
