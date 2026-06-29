from __future__ import annotations

import re
from typing import Any

from researcher.models import BlogPostPayload


def _extract_title(markdown: str, fallback: str) -> str:
    match = re.search(r"^#\s+(.+)$", markdown, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return fallback


def _slugify(title: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", title.lower())
    slug = re.sub(r"[-\s]+", "-", slug)
    return slug.strip("-")[:80]


def _extract_summary(markdown: str, max_len: int = 280) -> str:
    paragraphs = re.findall(r"^(?:#{1,6}\s+.*|.*\S.*)$", markdown, re.MULTILINE)
    for para in paragraphs:
        if para.startswith("#"):
            continue
        cleaned = para.strip()
        if len(cleaned) > 20:
            if len(cleaned) > max_len:
                return cleaned[: max_len - 3] + "..."
            return cleaned
    return markdown[:max_len].strip()


def _derive_tags(observatory_context: dict[str, Any]) -> list[str]:
    tags: list[str] = ["PQC", "TLS"]
    for algorithm in observatory_context.get("algorithms", []):
        group = algorithm.get("selected_group", "")
        if group and group not in tags:
            tags.append(group)
    return tags[:8]


def publish_to_blog_node(state: dict[str, Any], deps: Any) -> dict[str, Any]:
    if deps.blog is None:
        return {}

    markdown = state.get("final_markdown", "")
    topic = state.get("topic", "PQC TLS Observatory Update")

    title = _extract_title(markdown, topic)
    slug = _slugify(title)
    summary = _extract_summary(markdown)
    tags = _derive_tags(state.get("observatory_context", {}))
    run_id = state.get("run_id")

    payload = BlogPostPayload(
        title=title,
        slug=slug,
        summary=summary,
        tags=tags,
        markdown_content=markdown,
        run_id=run_id,
    )

    publish_result = deps.blog.publish_post(payload.model_dump())
    rebuild_result = deps.blog.rebuild_site()

    blog_url = f"/posts/{slug}.html"
    return {
        "blog_slug": slug,
        "blog_post_url": blog_url,
        "blog_publish_status": publish_result,
        "blog_rebuild_status": rebuild_result,
    }
