from __future__ import annotations

from typing import Any

import httpx


class BlogConnector:
    def __init__(self, base_url: str, timeout_s: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base_url, timeout=self.timeout_s)

    def publish_post(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._client() as client:
            response = client.post("/api/posts", json=payload)
            response.raise_for_status()
            return response.json()

    def rebuild_site(self) -> dict[str, Any]:
        with self._client() as client:
            response = client.post("/api/rebuild")
            response.raise_for_status()
            return response.json()
