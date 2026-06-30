from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient


POST_PAYLOAD = {
    "title": "ML-KEM dominates this week",
    "slug": "ml-kem-dominates-this-week",
    "summary": "ML-KEM768 is the most widely deployed PQC algorithm.",
    "tags": ["PQC", "TLS"],
    "markdown_content": "## Findings\n\nThis week we observed ML-KEM768 everywhere.",
    "run_id": "abc123",
}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("BLOG_POSTS_DIR", str(tmp_path / "posts"))
    monkeypatch.setenv("BLOG_SITE_DIR", str(tmp_path / "site"))
    from blog.app import app
    with TestClient(app) as c:
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_list_posts_empty(client):
    resp = client.get("/api/posts")
    assert resp.status_code == 200
    assert resp.json() == []


def test_create_post_returns_slug(client):
    resp = client.post("/api/posts", json=POST_PAYLOAD)
    assert resp.status_code == 201
    assert resp.json()["slug"] == "ml-kem-dominates-this-week"


def test_create_post_persists_and_is_listed(client):
    client.post("/api/posts", json=POST_PAYLOAD)

    resp = client.get("/api/posts")
    assert resp.status_code == 200
    posts = resp.json()
    assert len(posts) == 1
    assert posts[0]["title"] == "ML-KEM dominates this week"
    assert posts[0]["slug"] == "ml-kem-dominates-this-week"


def test_create_post_triggers_site_rebuild(client, tmp_path):
    client.post("/api/posts", json=POST_PAYLOAD)

    site_dir = tmp_path / "site"
    assert (site_dir / "index.html").exists(), "index.html missing after create_post"
    assert (site_dir / "posts" / "ml-kem-dominates-this-week.html").exists()


def test_list_posts_sorted_by_date_descending(client):
    for slug, date in [("post-a", "2026-01-01"), ("post-b", "2026-06-30")]:
        payload = {**POST_PAYLOAD, "slug": slug, "date": date, "title": f"Post {slug}"}
        client.post("/api/posts", json=payload)

    resp = client.get("/api/posts")
    dates = [p["date"] for p in resp.json()]
    assert dates == sorted(dates, reverse=True)


def test_rebuild_regenerates_site_from_existing_posts(client, tmp_path):
    posts_dir = tmp_path / "posts"
    posts_dir.mkdir(parents=True, exist_ok=True)
    post_data = {**POST_PAYLOAD, "slug": "manual-post", "date": "2026-06-30"}
    (posts_dir / "manual-post.json").write_text(json.dumps(post_data), encoding="utf-8")

    resp = client.post("/api/rebuild")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["posts_rendered"] == 1
    assert (tmp_path / "site" / "posts" / "manual-post.html").exists()
