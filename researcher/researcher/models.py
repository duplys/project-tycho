from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class OutputType(str, Enum):
    RESEARCH_SUMMARY = "research-summary"
    BLOG_POST = "blog-post"
    SHORT_ARTICLE = "short-article"


class ReferenceSnippet(BaseModel):
    source_path: str
    score: int
    excerpt: str


class VisualArtifact(BaseModel):
    kind: str
    filename: str
    relative_path: str
    description: str


class ResearchMetadata(BaseModel):
    run_id: str
    generated_at: str
    topic: str
    output_type: OutputType
    since: str | None = None
    observatory_context: dict[str, Any] = Field(default_factory=dict)
    visualiser_context: dict[str, Any] = Field(default_factory=dict)
    references: list[ReferenceSnippet] = Field(default_factory=list)
    visual_artifacts: list[VisualArtifact] = Field(default_factory=list)
