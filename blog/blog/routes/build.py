from __future__ import annotations

from fastapi import APIRouter

from blog.config import BlogSettings
from blog.generator import SiteGenerator

router = APIRouter(tags=["build"])


@router.post("/rebuild")
def rebuild_site() -> dict:
    settings = BlogSettings()
    generator = SiteGenerator(settings=settings)
    result = generator.build()
    return {"status": "ok", **result}
