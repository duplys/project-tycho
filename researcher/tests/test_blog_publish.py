from __future__ import annotations

import pytest

from researcher.nodes.blog_publish import (
    _derive_tags,
    _extract_summary,
    _extract_title,
    _slugify,
    publish_to_blog_node,
)


# ---------------------------------------------------------------------------
# _extract_title
# ---------------------------------------------------------------------------

def test_extract_title_from_h1():
    md = "Some preamble\n\n# My Great Title\n\nBody text."
    assert _extract_title(md, "fallback") == "My Great Title"


def test_extract_title_uses_fallback_when_no_heading():
    assert _extract_title("No heading here.", "fallback") == "fallback"


def test_extract_title_trims_whitespace():
    assert _extract_title("#   Spaced Title  \nBody.", "fb") == "Spaced Title"


# ---------------------------------------------------------------------------
# _slugify
# ---------------------------------------------------------------------------

def test_slugify_lowercases_and_hyphenates():
    assert _slugify("ML-KEM Takes the Lead") == "ml-kem-takes-the-lead"


def test_slugify_strips_special_chars():
    assert _slugify("Hello, World! & More") == "hello-world-more"


def test_slugify_truncates_at_80_chars():
    long_title = "word " * 30
    result = _slugify(long_title)
    assert len(result) <= 80


def test_slugify_no_leading_or_trailing_hyphens():
    result = _slugify("  ---  padded  ---  ")
    assert not result.startswith("-")
    assert not result.endswith("-")


# ---------------------------------------------------------------------------
# _extract_summary
# ---------------------------------------------------------------------------

def test_extract_summary_returns_first_prose_line():
    md = "# Heading\n\nThis is the first paragraph of prose text that is long enough."
    result = _extract_summary(md)
    assert result == "This is the first paragraph of prose text that is long enough."


def test_extract_summary_skips_headings():
    md = "## Section\n### Sub\nThis is a prose sentence that is long enough."
    assert _extract_summary(md) == "This is a prose sentence that is long enough."


def test_extract_summary_skips_table_rows():
    md = "| col1 | col2 |\n|---|---|\nThis is prose after the table that is long enough."
    assert _extract_summary(md) == "This is prose after the table that is long enough."


def test_extract_summary_skips_unordered_list_items():
    md = "- item one\n- item two\nThis is the prose paragraph that is long enough."
    assert _extract_summary(md) == "This is the prose paragraph that is long enough."


def test_extract_summary_skips_ordered_list_items():
    md = "1. First\n2. Second\nThis is the prose paragraph that is long enough."
    assert _extract_summary(md) == "This is the prose paragraph that is long enough."


def test_extract_summary_skips_code_fences():
    md = "```python\ncode here\n```\nThis is prose after the code block long enough."
    assert _extract_summary(md) == "This is prose after the code block long enough."


def test_extract_summary_skips_blockquotes():
    md = "> quoted text\nThis is the prose paragraph that is long enough to count."
    assert _extract_summary(md) == "This is the prose paragraph that is long enough to count."


def test_extract_summary_truncates_long_lines():
    long_line = "x" * 300
    result = _extract_summary(long_line)
    assert len(result) <= 280
    assert result.endswith("...")


def test_extract_summary_fallback_to_raw_when_no_prose():
    md = "# Only a heading"
    result = _extract_summary(md)
    assert isinstance(result, str)
    assert len(result) > 0


# ---------------------------------------------------------------------------
# _derive_tags
# ---------------------------------------------------------------------------

def test_derive_tags_always_includes_pqc_and_tls():
    tags = _derive_tags({})
    assert "PQC" in tags
    assert "TLS" in tags


def test_derive_tags_extracts_algorithm_groups():
    ctx = {
        "algorithms": [
            {"selected_group": "X25519MLKEM768"},
            {"selected_group": "MLKEM768"},
        ]
    }
    tags = _derive_tags(ctx)
    assert "X25519MLKEM768" in tags
    assert "MLKEM768" in tags


def test_derive_tags_caps_at_8():
    algorithms = [{"selected_group": f"ALG{i}"} for i in range(20)]
    assert len(_derive_tags({"algorithms": algorithms})) <= 8


def test_derive_tags_no_duplicates():
    ctx = {"algorithms": [{"selected_group": "PQC"}, {"selected_group": "TLS"}]}
    tags = _derive_tags(ctx)
    assert tags.count("PQC") == 1
    assert tags.count("TLS") == 1


# ---------------------------------------------------------------------------
# publish_to_blog_node
# ---------------------------------------------------------------------------

class _FakeBlog:
    def __init__(self):
        self.published: list[dict] = []
        self.rebuilt = 0

    def publish_post(self, payload: dict) -> dict:
        self.published.append(payload)
        return {"slug": payload["slug"], "message": "Post created"}

    def rebuild_site(self) -> dict:
        self.rebuilt += 1
        return {"status": "ok", "posts_rendered": len(self.published)}


class _FakeDeps:
    def __init__(self, blog):
        self.blog = blog


def test_publish_node_calls_publish_and_rebuild():
    fake_blog = _FakeBlog()
    state = {
        "final_markdown": "# Week in PQC\n\nML-KEM768 dominates this week's observatory data.",
        "topic": "Week in PQC",
        "observatory_context": {"algorithms": [{"selected_group": "ML-KEM768"}]},
        "run_id": "run-abc",
    }
    result = publish_to_blog_node(state=state, deps=_FakeDeps(blog=fake_blog))

    assert len(fake_blog.published) == 1
    assert fake_blog.rebuilt == 1
    assert fake_blog.published[0]["title"] == "Week in PQC"
    assert fake_blog.published[0]["run_id"] == "run-abc"
    assert result["blog_slug"] == "week-in-pqc"
    assert result["blog_post_url"] == "/posts/week-in-pqc.html"


def test_publish_node_skips_when_blog_is_none():
    result = publish_to_blog_node(state={}, deps=_FakeDeps(blog=None))
    assert result == {}


def test_publish_node_extracts_title_from_markdown():
    fake_blog = _FakeBlog()
    state = {
        "final_markdown": "# Extracted Title\n\nSome body content that is long enough.",
        "topic": "fallback topic",
        "observatory_context": {},
    }
    result = publish_to_blog_node(state=state, deps=_FakeDeps(blog=fake_blog))
    assert fake_blog.published[0]["title"] == "Extracted Title"
    assert result["blog_slug"] == "extracted-title"
