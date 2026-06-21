"""
Acceptance tests for the Project Tycho system.

These tests validate that the PCAP TLS Parser, Observatory, and Visualiser
work together correctly as a system.

They require:
- The Visualiser service to be running (via docker-compose.yml)
- The tls-pcap-analyzer library installed in the test environment

The easiest way to run them is via the provided helper script::

    cd acceptance-tests
    ./run.sh

Or manually::

    docker compose up -d --build
    uv run pytest test_acceptance.py -v
    docker compose down
"""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

import os

VISUALISER_URL = os.getenv("VISUALISER_URL", "http://localhost:8765")


@pytest.fixture(scope="session")
def base_url() -> str:
    return VISUALISER_URL.rstrip("/")


# ---------------------------------------------------------------------------
# PCAP fixture helpers — re-use builders from pcap-analyser/tests/fixtures
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).parent.parent / "pcap-analyser" / "tests"))

from fixtures import make_classical_tls13_pcap, make_hybrid_mlkem768_pcap  # noqa: E402


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _parse_pcap_to_dict(pcap_path: Path) -> dict:
    """Run the PCAP Analyser on *pcap_path* and return the first record as a dict."""
    from tls_pcap_analyzer import parse_pcap

    records = parse_pcap(pcap_path)
    assert records, f"PCAP Analyser found no TLS records in {pcap_path}"
    return dataclasses.asdict(records[0])


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


class TestHealth:
    """Smoke-test that the Visualiser service started successfully."""

    def test_visualiser_is_healthy(self, base_url: str) -> None:
        resp = requests.get(f"{base_url}/health", timeout=10)
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# PCAP Analyser → Visualiser pipeline
# ---------------------------------------------------------------------------


class TestPcapAnalyserPipeline:
    """
    Validates the end-to-end pipeline:

        synthetic pcap  →  PCAP Analyser (library)  →  POST /api/handshakes
                       →  GET /api/handshakes/{id}  →  TikZ export
    """

    @pytest.fixture(scope="class")
    def hybrid_record_id(self, base_url: str, tmp_path_factory) -> str:
        """Parse a hybrid PCAP file and POST the result to the Visualiser API."""
        pcap = make_hybrid_mlkem768_pcap(
            tmp_path_factory.mktemp("pcap") / "hybrid.pcap"
        )
        record_data = _parse_pcap_to_dict(pcap)
        resp = requests.post(
            f"{base_url}/api/handshakes", json=record_data, timeout=10
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["id"]

    def test_post_hybrid_handshake_is_pqc(self, base_url: str, tmp_path: Path) -> None:
        """PCAP Analyser correctly identifies a hybrid handshake as PQC."""
        pcap = make_hybrid_mlkem768_pcap(tmp_path / "hybrid.pcap")
        record_data = _parse_pcap_to_dict(pcap)

        resp = requests.post(
            f"{base_url}/api/handshakes", json=record_data, timeout=10
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "id" in body
        server_hello = body["data"]["server_hello"]
        assert server_hello["is_pqc"] is True
        assert server_hello["is_hybrid"] is True
        assert server_hello["selected_group"] == "X25519MLKEM768"
        assert server_hello["key_share_size_bytes"] == 1120

    def test_post_classical_handshake_is_not_pqc(
        self, base_url: str, tmp_path: Path
    ) -> None:
        """PCAP Analyser correctly identifies a classical handshake as non-PQC."""
        pcap = make_classical_tls13_pcap(tmp_path / "classical.pcap")
        record_data = _parse_pcap_to_dict(pcap)

        resp = requests.post(
            f"{base_url}/api/handshakes", json=record_data, timeout=10
        )
        assert resp.status_code == 200
        body = resp.json()
        server_hello = body["data"]["server_hello"]
        assert server_hello["is_pqc"] is False
        assert server_hello["is_hybrid"] is False
        assert server_hello["selected_group"] == "x25519"

    def test_get_stored_handshake(
        self, base_url: str, hybrid_record_id: str
    ) -> None:
        """A stored handshake record can be retrieved by its ID."""
        resp = requests.get(
            f"{base_url}/api/handshakes/{hybrid_record_id}", timeout=10
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == hybrid_record_id
        assert body["data"]["server_hello"]["is_pqc"] is True

    def test_list_handshakes_includes_stored(
        self, base_url: str, hybrid_record_id: str
    ) -> None:
        """The list endpoint includes the stored record."""
        resp = requests.get(f"{base_url}/api/handshakes", timeout=10)
        assert resp.status_code == 200
        ids = [item["id"] for item in resp.json()]
        assert hybrid_record_id in ids

    def test_tikz_handshake_flow_export(
        self, base_url: str, hybrid_record_id: str
    ) -> None:
        """The TikZ handshake-flow export is valid for an analyser-sourced record."""
        resp = requests.get(
            f"{base_url}/api/handshakes/{hybrid_record_id}/export/tikz/handshake-flow",
            timeout=10,
        )
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        assert r"\begin{tikzpicture}" in resp.text
        assert r"\end{tikzpicture}" in resp.text
        assert "ClientHello" in resp.text
        assert "ServerHello" in resp.text

    def test_tikz_key_share_comparison_export(
        self, base_url: str, hybrid_record_id: str
    ) -> None:
        """The TikZ key-share-comparison export is valid for an analyser-sourced record."""
        resp = requests.get(
            f"{base_url}/api/handshakes/{hybrid_record_id}/export/tikz/key-share-comparison",
            timeout=10,
        )
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        assert r"\begin{tikzpicture}" in resp.text
        assert "X25519MLKEM768" in resp.text

    def test_delete_removes_handshake(self, base_url: str, tmp_path: Path) -> None:
        """A stored handshake can be deleted; subsequent GETs return 404."""
        pcap = make_classical_tls13_pcap(tmp_path / "classical.pcap")
        record_data = _parse_pcap_to_dict(pcap)
        post_resp = requests.post(
            f"{base_url}/api/handshakes", json=record_data, timeout=10
        )
        record_id = post_resp.json()["id"]

        del_resp = requests.delete(
            f"{base_url}/api/handshakes/{record_id}", timeout=10
        )
        assert del_resp.status_code == 200

        get_resp = requests.get(
            f"{base_url}/api/handshakes/{record_id}", timeout=10
        )
        assert get_resp.status_code == 404


# ---------------------------------------------------------------------------
# Observatory → Visualiser integration
# ---------------------------------------------------------------------------


class TestObservatoryIntegration:
    """
    Validates that the Visualiser correctly reads and exposes the Observatory's
    JSON data store.

    The pre-seeded ``data/observatory-data.json`` contains:
    - cloudflare.com  (PQC / X25519MLKEM768) — scanned 2026-05-21 and 2026-05-22
    - example.com     (classical / x25519)   — scanned 2026-05-21
    """

    def test_status_returns_two_active_targets(self, base_url: str) -> None:
        """/api/observatory/status returns the latest scan for every active target."""
        resp = requests.get(f"{base_url}/api/observatory/status", timeout=10)
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 2
        hostnames = {item["hostname"] for item in items}
        assert hostnames == {"cloudflare.com", "example.com"}

    def test_cloudflare_latest_scan_is_pqc(self, base_url: str) -> None:
        """The latest Observatory scan for cloudflare.com reports a PQC group."""
        resp = requests.get(f"{base_url}/api/observatory/status", timeout=10)
        cloudflare = next(
            item for item in resp.json() if item["hostname"] == "cloudflare.com"
        )
        assert cloudflare["is_pqc"] is True
        assert cloudflare["is_hybrid"] is True
        assert cloudflare["selected_group"] == "X25519MLKEM768"

    def test_example_latest_scan_is_not_pqc(self, base_url: str) -> None:
        """The latest Observatory scan for example.com reports a classical group."""
        resp = requests.get(f"{base_url}/api/observatory/status", timeout=10)
        example = next(
            item for item in resp.json() if item["hostname"] == "example.com"
        )
        assert example["is_pqc"] is False
        assert example["selected_group"] == "x25519"

    def test_adoption_trend_two_days(self, base_url: str) -> None:
        """/api/observatory/adoption returns daily PQC adoption across both scan days."""
        resp = requests.get(f"{base_url}/api/observatory/adoption", timeout=10)
        assert resp.status_code == 200
        items = resp.json()
        by_date = {item["date"]: item for item in items}

        # 2026-05-21: 2 scans total, 1 PQC → 50 %
        assert "2026-05-21" in by_date
        day1 = by_date["2026-05-21"]
        assert day1["total"] == 2
        assert day1["pqc_count"] == 1
        assert day1["pct_pqc"] == 50.0

        # 2026-05-22: 1 scan total, 1 PQC → 100 %
        assert "2026-05-22" in by_date
        day2 = by_date["2026-05-22"]
        assert day2["total"] == 1
        assert day2["pqc_count"] == 1
        assert day2["pct_pqc"] == 100.0

    def test_algorithm_popularity_x25519mlkem768_first(self, base_url: str) -> None:
        """/api/observatory/algorithms ranks X25519MLKEM768 first (2 scans vs 1)."""
        resp = requests.get(f"{base_url}/api/observatory/algorithms", timeout=10)
        assert resp.status_code == 200
        items = resp.json()
        assert items[0]["selected_group"] == "X25519MLKEM768"
        assert items[0]["count"] == 2
        assert items[1]["selected_group"] == "x25519"
        assert items[1]["count"] == 1

    def test_adoption_since_filter(self, base_url: str) -> None:
        """/api/observatory/adoption?since= returns only days on or after the date."""
        resp = requests.get(
            f"{base_url}/api/observatory/adoption?since=2026-05-22", timeout=10
        )
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 1
        assert items[0]["date"] == "2026-05-22"
        assert items[0]["pct_pqc"] == 100.0

    def test_algorithms_since_filter(self, base_url: str) -> None:
        """/api/observatory/algorithms?since= returns only scans on or after the date."""
        resp = requests.get(
            f"{base_url}/api/observatory/algorithms?since=2026-05-22", timeout=10
        )
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 1
        assert items[0]["selected_group"] == "X25519MLKEM768"
        assert items[0]["count"] == 1

    def test_adoption_invalid_since_returns_400(self, base_url: str) -> None:
        """/api/observatory/adoption returns HTTP 400 for a malformed since= value."""
        resp = requests.get(
            f"{base_url}/api/observatory/adoption?since=not-a-date", timeout=10
        )
        assert resp.status_code == 400
