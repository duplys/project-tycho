from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field


class BlogPost(BaseModel):
    title: str
    slug: str
    summary: str
    tags: list[str] = Field(default_factory=list)
    markdown_content: str
    author: str = "Tycho Researcher"
    date: str = Field(default_factory=lambda: date.today().isoformat())
    run_id: str | None = None

    @classmethod
    def load_from_file(cls, path: str) -> BlogPost:
        import json
        with open(path, "r", encoding="utf-8") as f:
            return cls.model_validate(json.load(f))

    def html_content(self) -> str:
        import markdown
        return markdown.markdown(
            self.markdown_content,
            extensions=["fenced_code", "codehilite", "tables", "toc"],
        )

