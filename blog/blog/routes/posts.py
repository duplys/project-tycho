from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter

from blog.models import BlogPost

router = APIRouter(tags=["posts"])

POSTS_DIR = Path("/var/pqc-obs/blog-posts")


@router.get("/posts")
def list_posts() -> list[dict]:
    results: list[dict] = []
    if not POSTS_DIR.exists():
        return results
    for fpath in sorted(POSTS_DIR.glob("*.json")):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                results.append(json.load(f))
        except Exception:
            continue
    return sorted(results, key=lambda p: p.get("date", ""), reverse=True)


@router.post("/posts", status_code=201)
def create_post(post: BlogPost) -> dict:
    payload = post.model_dump()
    POSTS_DIR.mkdir(parents=True, exist_ok=True)
    post_path = POSTS_DIR / f"{post.slug}.json"
    with open(post_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    return {"slug": post.slug, "message": "Post created"}
