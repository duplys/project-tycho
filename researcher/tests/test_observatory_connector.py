import json
from datetime import UTC, datetime

from researcher.connectors.observatory import ObservatoryConnector


def _write_store(path):
    payload = {
        "version": 1,
        "targets": [
            {"id": 1, "hostname": "cloudflare.com", "port": 443, "category": "cdn", "is_active": True},
            {"id": 2, "hostname": "example.com", "port": 443, "category": "test", "is_active": True},
        ],
        "scans": [
            {
                "id": 1,
                "target_id": 1,
                "scanned_at": "2026-05-21T10:00:00+00:00",
                "selected_group": "X25519MLKEM768",
                "negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256",
                "is_pqc": True,
                "is_hybrid": True,
                "analyzer_output": {"server_hello": {"selected_group": "X25519MLKEM768"}},
                "error": None,
            },
            {
                "id": 2,
                "target_id": 2,
                "scanned_at": "2026-05-21T10:05:00+00:00",
                "selected_group": "x25519",
                "negotiated_cipher_suite": "TLS_AES_256_GCM_SHA384",
                "is_pqc": False,
                "is_hybrid": False,
                "analyzer_output": {"server_hello": {"selected_group": "x25519"}},
                "error": None,
            },
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_build_research_context(tmp_path):
    data_file = tmp_path / "observatory-data.json"
    _write_store(data_file)
    connector = ObservatoryConnector(data_file=data_file)

    context = connector.build_research_context()

    assert context["total_scans_considered"] == 2
    assert context["total_pqc_scans"] == 1
    assert context["pct_pqc_overall"] == 50.0
    assert context["algorithms"][0]["selected_group"] == "X25519MLKEM768"


def test_get_recent_scans_since_filter(tmp_path):
    data_file = tmp_path / "observatory-data.json"
    _write_store(data_file)
    connector = ObservatoryConnector(data_file=data_file)

    rows = connector.get_recent_scans(
        since=datetime(2026, 5, 21, 10, 1, tzinfo=UTC),
        limit=10,
    )
    assert len(rows) == 1
    assert rows[0]["selected_group"] == "x25519"


def test_round_aware_context_counts_target_once(tmp_path):
    data_file = tmp_path / "observatory-data.json"
    _write_store(data_file)
    payload = json.loads(data_file.read_text(encoding="utf-8"))
    payload["scans"] = [
        {
            "id": 3,
            "target_id": 1,
            "scan_round_id": "weekly-round",
            "scanned_at": "2026-06-21T08:00:00+00:00",
            "probe_group": "X25519MLKEM768",
            "selected_group": "X25519MLKEM768",
            "is_pqc": True,
            "is_hybrid": True,
            "error": None,
        },
        {
            "id": 4,
            "target_id": 1,
            "scan_round_id": "weekly-round",
            "scanned_at": "2026-06-21T08:01:00+00:00",
            "probe_group": "MLKEM768",
            "selected_group": None,
            "is_pqc": None,
            "is_hybrid": None,
            "error": "handshake failed",
        },
    ]
    payload["targets"] = payload["targets"][:1]
    data_file.write_text(json.dumps(payload), encoding="utf-8")
    connector = ObservatoryConnector(data_file=data_file)

    context = connector.build_research_context()

    assert context["total_scans_considered"] == 1
    assert context["total_pqc_scans"] == 1
    assert context["latest_status"][0]["supported_groups"] == ["X25519MLKEM768"]
    assert context["latest_status"][0]["failed_groups"] == ["MLKEM768"]
