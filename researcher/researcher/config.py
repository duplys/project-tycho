from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ResearcherSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RESEARCHER_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    observatory_data_file: Path = Path("/var/pqc-obs/data/observatory-data.json")
    reference_dir: Path = Path("/var/pqc-obs/references")
    output_dir: Path = Path("/var/pqc-obs/researcher-output")
    visualiser_base_url: str = "http://127.0.0.1:8000"

    llm_model: str = "gpt-4.1-mini"
    llm_temperature: float = Field(default=0.2, ge=0.0, le=2.0)

    http_timeout_s: float = Field(default=30.0, gt=0.0)
    max_reference_snippets: int = Field(default=6, ge=1, le=20)
    reference_chunk_size: int = Field(default=1800, ge=300, le=8000)
    reference_chunk_overlap: int = Field(default=200, ge=0, le=2000)
    max_visualizations: int = Field(default=3, ge=1, le=10)

    blog_base_url: str = "http://blog:8001"
    blog_system_prompt_file: Path | None = None

    @field_validator(
        "observatory_data_file",
        "reference_dir",
        "output_dir",
        "blog_system_prompt_file",
        mode="before",
    )
    @classmethod
    def _expand_paths(cls, value: str | Path | None) -> Path | None:
        if value is None:
            return None
        return Path(value).expanduser()


settings = ResearcherSettings()
