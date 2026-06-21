from __future__ import annotations

import re
from pathlib import Path

from researcher.models import ReferenceSnippet

_ALLOWED_SUFFIXES = {".tex", ".md", ".txt"}


def _tokenize(text: str) -> list[str]:
    return [token for token in re.findall(r"[a-zA-Z0-9_]+", text.lower()) if len(token) > 2]


class ReferenceRetriever:
    def __init__(
        self,
        reference_dir: Path,
        chunk_size: int = 1800,
        chunk_overlap: int = 200,
    ) -> None:
        self.reference_dir = reference_dir
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def _iter_reference_files(self) -> list[Path]:
        if not self.reference_dir.exists():
            raise FileNotFoundError(
                f"Reference directory does not exist: {self.reference_dir}"
            )
        files: list[Path] = []
        for path in self.reference_dir.rglob("*"):
            if path.is_file() and path.suffix.lower() in _ALLOWED_SUFFIXES:
                files.append(path)
        files.sort()
        return files

    def _split_text(self, text: str) -> list[str]:
        if len(text) <= self.chunk_size:
            return [text]

        chunks: list[str] = []
        start = 0
        step = max(1, self.chunk_size - self.chunk_overlap)
        while start < len(text):
            end = start + self.chunk_size
            chunks.append(text[start:end])
            start += step
        return chunks

    def retrieve(self, query: str, limit: int = 6) -> list[ReferenceSnippet]:
        query_tokens = _tokenize(query)
        files = self._iter_reference_files()
        scored_snippets: list[ReferenceSnippet] = []

        for file_path in files:
            raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
            for chunk in self._split_text(raw_text):
                lowered = chunk.lower()
                score = sum(lowered.count(token) for token in query_tokens)
                if score <= 0:
                    continue
                scored_snippets.append(
                    ReferenceSnippet(
                        source_path=str(file_path),
                        score=score,
                        excerpt=chunk.strip(),
                    )
                )

        scored_snippets.sort(key=lambda snippet: snippet.score, reverse=True)
        return scored_snippets[:limit]
