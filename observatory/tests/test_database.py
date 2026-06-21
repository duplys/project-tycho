import json
from datetime import UTC, datetime

import pytest

from observatory.config import settings
from observatory.database import (
    apply_schema,
    get_active_targets,
    get_algorithm_popularity,
    get_latest_scan_per_target,
    get_pqc_adoption_over_time,
    insert_scan,
    upsert_target,
)
from observatory.models import HandshakeData, ScanResult, Target
from observatory.scheduler import sync_targets_to_store


@pytest.fixture
def isolated_storage(tmp_path, monkeypatch):
    storage_file = tmp_path / "observatory-data.json"
    targets_file = tmp_path / "targets.yaml"
    monkeypatch.setattr(settings, "storage_file", storage_file)
    monkeypatch.setattr(settings, "targets_file", targets_file)
    return storage_file, targets_file


def test_apply_schema_creates_json_store(isolated_storage):
    storage_file, _ = isolated_storage

    apply_schema()

    assert storage_file.exists()
    data = json.loads(storage_file.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert data["targets"] == []
    assert data["scans"] == []


def test_file_store_query_helpers(isolated_storage):
    apply_schema()

    cloudflare_id = upsert_target(Target(hostname="cloudflare.com", category="cdn"))
    example_id = upsert_target(Target(hostname="example.com", category="test"))

    insert_scan(
        cloudflare_id,
        ScanResult(
            target_hostname="cloudflare.com",
            target_port=443,
            scanned_at=datetime(2026, 5, 21, 10, 0, tzinfo=UTC),
            probe_group="X25519MLKEM768",
            pcap_path="/tmp/cloudflare-1.pcap",
            analyzer_output={"server_hello": {"selected_group": "X25519MLKEM768"}},
            handshake=HandshakeData(
                selected_group="X25519MLKEM768",
                negotiated_cipher_suite="TLS_AES_128_GCM_SHA256",
                is_pqc=True,
                is_hybrid=True,
            ),
        ),
    )
    insert_scan(
        example_id,
        ScanResult(
            target_hostname="example.com",
            target_port=443,
            scanned_at=datetime(2026, 5, 21, 10, 5, tzinfo=UTC),
            pcap_path="/tmp/example-1.pcap",
            analyzer_output={"server_hello": {"selected_group": "x25519"}},
            handshake=HandshakeData(
                selected_group="x25519",
                negotiated_cipher_suite="TLS_AES_256_GCM_SHA384",
                is_pqc=False,
                is_hybrid=False,
            ),
        ),
    )
    insert_scan(
        cloudflare_id,
        ScanResult(
            target_hostname="cloudflare.com",
            target_port=443,
            scanned_at=datetime(2026, 5, 22, 10, 0, tzinfo=UTC),
            pcap_path="/tmp/cloudflare-2.pcap",
            analyzer_output={"server_hello": {"selected_group": "X25519MLKEM768"}},
            handshake=HandshakeData(
                selected_group="X25519MLKEM768",
                negotiated_cipher_suite="TLS_AES_128_GCM_SHA256",
                is_pqc=True,
                is_hybrid=True,
            ),
        ),
    )

    assert get_pqc_adoption_over_time() == [
        {"date": "2026-05-21", "total": 2, "pqc_count": 1, "pct_pqc": 50.0},
        {"date": "2026-05-22", "total": 1, "pqc_count": 1, "pct_pqc": 100.0},
    ]
    assert get_algorithm_popularity() == [
        {"selected_group": "X25519MLKEM768", "count": 2},
        {"selected_group": "x25519", "count": 1},
    ]

    latest = get_latest_scan_per_target()
    assert latest[0]["hostname"] == "cloudflare.com"
    assert latest[0]["scanned_at"] == datetime(2026, 5, 22, 10, 0, tzinfo=UTC)
    assert latest[0]["probe_group"] is None
    assert latest[1]["hostname"] == "example.com"

    data = json.loads(settings.storage_file.read_text(encoding="utf-8"))
    assert data["scans"][0]["probe_group"] == "X25519MLKEM768"


def test_sync_targets_to_store_deactivates_removed_targets(isolated_storage):
    _, targets_file = isolated_storage

    targets_file.write_text(
        """
targets:
  - hostname: cloudflare.com
    category: cdn
  - hostname: example.com
    category: test
""".strip(),
        encoding="utf-8",
    )
    sync_targets_to_store()
    assert {target["hostname"] for target in get_active_targets()} == {
        "cloudflare.com",
        "example.com",
    }

    targets_file.write_text(
        """
targets:
  - hostname: cloudflare.com
    category: cdn
""".strip(),
        encoding="utf-8",
    )
    sync_targets_to_store()

    assert {target["hostname"] for target in get_active_targets()} == {"cloudflare.com"}
