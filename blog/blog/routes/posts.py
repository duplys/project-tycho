from __future__ import annotations

import json

from fastapi import APIRouter

from blog.config import BlogSettings
from blog.generator import SiteGenerator
from blog.models import BlogPost

router = APIRouter(tags=["posts"])


@router.get("/posts")
def list_posts() -> list[dict]:
    settings = BlogSettings()
    results: list[dict] = []
    if not settings.posts_dir.exists():
        return results
    for fpath in sorted(settings.posts_dir.glob("*.json")):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                results.append(json.load(f))
        except Exception:
            continue
    return sorted(results, key=lambda p: p.get("date", ""), reverse=True)


@router.post("/posts", status_code=201)
def create_post(post: BlogPost) -> dict:
    settings = BlogSettings()
    payload = post.model_dump()
    settings.posts_dir.mkdir(parents=True, exist_ok=True)
    post_path = settings.posts_dir / f"{post.slug}.json"
    with open(post_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    SiteGenerator(settings=settings).build()
    return {"slug": post.slug, "message": "Post created"}
