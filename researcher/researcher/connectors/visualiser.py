from __future__ import annotations

from typing import Any

import httpx


class VisualiserConnector:
    def __init__(self, base_url: str, timeout_s: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base_url, timeout=self.timeout_s)

    def _since_params(self, since: str | None) -> dict[str, str] | None:
        if since is None:
            return None
        return {"since": since}

    def get_status(self) -> list[dict[str, Any]]:
        with self._client() as client:
            response = client.get("/api/observatory/status")
            response.raise_for_status()
            return response.json()

    def get_adoption(self, since: str | None = None) -> list[dict[str, Any]]:
        with self._client() as client:
            response = client.get(
                "/api/observatory/adoption",
                params=self._since_params(since),
            )
            response.raise_for_status()
            return response.json()

    def get_algorithms(self, since: str | None = None) -> list[dict[str, Any]]:
        with self._client() as client:
            response = client.get(
                "/api/observatory/algorithms",
                params=self._since_params(since),
            )
            response.raise_for_status()
            return response.json()

    def export_handshake_assets(self, analyzer_output: dict[str, Any]) -> dict[str, str]:
        with self._client() as client:
            create_response = client.post("/api/handshakes", json=analyzer_output)
            create_response.raise_for_status()
            record_id = create_response.json()["id"]

            flow_response = client.get(
                f"/api/handshakes/{record_id}/export/tikz/handshake-flow"
            )
            flow_response.raise_for_status()

            key_share_response = client.get(
                f"/api/handshakes/{record_id}/export/tikz/key-share-comparison"
            )
            key_share_response.raise_for_status()

            delete_response = client.delete(f"/api/handshakes/{record_id}")
            delete_response.raise_for_status()

        return {
            "handshake-flow": flow_response.text,
            "key-share-comparison": key_share_response.text,
        }
