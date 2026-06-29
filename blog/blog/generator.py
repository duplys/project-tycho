from __future__ import annotations

import shutil
from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from blog.config import BlogSettings
from blog.models import BlogPost


class SiteGenerator:
    def __init__(self, settings: BlogSettings) -> None:
        self.settings = settings
        self.templates_dir = Path(__file__).parent / "templates"
        self.static_dir = Path(__file__).parent / "static"
        self.env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(enabled_extensions=("html",)),
        )

    def _load_posts(self) -> list[BlogPost]:
        if not self.settings.posts_dir.exists():
            return []
        posts: list[BlogPost] = []
        pattern = "*.json"
        for fpath in sorted(self.settings.posts_dir.glob(pattern)):
            try:
                post = BlogPost.load_from_file(str(fpath))
                posts.append(post)
            except Exception:
                continue
        return sorted(posts, key=lambda p: p.date, reverse=True)

    def _render_index(self, posts: list[BlogPost]) -> None:
        template = self.env.get_template("index.html.j2")
        html = template.render(
            title=self.settings.blog_title,
            description=self.settings.blog_description,
            author=self.settings.blog_author,
            posts=posts,
            generated_at=date.today().isoformat(),
        )
        self.settings.site_dir.mkdir(parents=True, exist_ok=True)
        (self.settings.site_dir / "index.html").write_text(html, encoding="utf-8")

    def _render_posts(self, posts: list[BlogPost]) -> None:
        template = self.env.get_template("post.html.j2")
        posts_dir = self.settings.site_dir / "posts"
        posts_dir.mkdir(parents=True, exist_ok=True)
        for post in posts:
            html = template.render(
                post=post,
                site_title=self.settings.blog_title,
                author=self.settings.blog_author,
                generated_at=date.today().isoformat(),
            )
            (posts_dir / f"{post.slug}.html").write_text(html, encoding="utf-8")

    def _copy_static(self) -> None:
        if not self.static_dir.exists():
            return
        dest = self.settings.site_dir / "static"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(str(self.static_dir), str(dest))

    def build(self) -> dict[str, int]:
        posts = self._load_posts()
        self._render_index(posts)
        self._render_posts(posts)
        self._copy_static()
        return {"posts_rendered": len(posts)}
