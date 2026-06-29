from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class BlogSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BLOG_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    posts_dir: Path = Path("/var/pqc-obs/blog-posts")
    site_dir: Path = Path("/var/pqc-obs/blog-site")
    host: str = "0.0.0.0"
    port: int = 8001
    blog_title: str = "Project Tycho — PQC Observatory Blog"
    blog_author: str = "Tycho Researcher"
    blog_description: str = (
        "Weekly analysis of post-quantum cryptography adoption in TLS"
    )

