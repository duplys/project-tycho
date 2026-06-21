import json


ANALYZER_OUTPUT = {
    "capture_metadata": {
        "filename": "cloudflare-2026-05-21.pcap",
        "captured_at": "2026-05-21T10:00:00+00:00",
        "source_host": "172.19.0.3",
        "destination_host": "104.16.0.1",
    },
    "client_hello": {
        "tls_version": "TLS 1.3",
        "cipher_suites": ["TLS_AES_128_GCM_SHA256"],
        "supported_groups": ["X25519MLKEM768"],
    },
    "server_hello": {
        "negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256",
        "selected_group": "X25519MLKEM768",
        "key_share_size_bytes": 1120,
        "is_pqc": True,
        "is_hybrid": True,
        "pqc_algorithms_detected": ["X25519MLKEM768"],
    },
}


OBSERVATORY_DATA = {
    "version": 1,
    "next_target_id": 3,
    "next_scan_id": 4,
    "targets": [
        {
            "id": 1,
            "hostname": "cloudflare.com",
            "port": 443,
            "category": "cdn",
            "is_active": True,
            "notes": "",
            "added_at": "2026-05-21T00:00:00+00:00",
        },
        {
            "id": 2,
            "hostname": "example.com",
            "port": 443,
            "category": "test",
            "is_active": True,
            "notes": "",
            "added_at": "2026-05-21T00:00:00+00:00",
        },
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
            "pcap_path": "/var/pqc-obs/pcaps/cloudflare-2026-05-21.pcap",
            "analyzer_output": ANALYZER_OUTPUT,
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
            "error": None,
        },
        {
            "id": 3,
            "target_id": 1,
            "scanned_at": "2026-05-22T10:00:00+00:00",
            "selected_group": "X25519MLKEM768",
            "negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256",
            "is_pqc": True,
            "is_hybrid": True,
            "error": None,
        },
    ],
}


def _write_observatory_data(tmp_path, monkeypatch):
    data_file = tmp_path / "observatory-data.json"
    data_file.write_text(json.dumps(OBSERVATORY_DATA), encoding="utf-8")
    monkeypatch.setenv("TLS_VISUALIZER_OBSERVATORY_DATA_FILE", str(data_file))
    return data_file


def test_observatory_status(client, tmp_path, monkeypatch):
    _write_observatory_data(tmp_path, monkeypatch)

    resp = client.get("/api/observatory/status")

    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 2
    assert items[0]["hostname"] == "cloudflare.com"
    assert items[0]["scanned_at"] == "2026-05-22T10:00:00+00:00"


def test_observatory_adoption(client, tmp_path, monkeypatch):
    _write_observatory_data(tmp_path, monkeypatch)

    resp = client.get("/api/observatory/adoption")

    assert resp.status_code == 200
    assert resp.json() == [
        {"date": "2026-05-21", "total": 2, "pqc_count": 1, "pct_pqc": 50.0},
        {"date": "2026-05-22", "total": 1, "pqc_count": 1, "pct_pqc": 100.0},
    ]


def test_observatory_algorithms_since_filter(client, tmp_path, monkeypatch):
    _write_observatory_data(tmp_path, monkeypatch)

    resp = client.get("/api/observatory/algorithms?since=2026-05-22")

    assert resp.status_code == 200
    assert resp.json() == [{"selected_group": "X25519MLKEM768", "count": 1}]


def test_observatory_invalid_since(client):
    resp = client.get("/api/observatory/adoption?since=not-a-date")

    assert resp.status_code == 400
    assert "Invalid date format" in resp.json()["detail"]


def test_observatory_handshake_list(client, tmp_path, monkeypatch):
    _write_observatory_data(tmp_path, monkeypatch)

    resp = client.get("/api/observatory/handshakes")

    assert resp.status_code == 200
    assert resp.json() == [
        {
            "id": "1",
            "scan_id": 1,
            "target": {
                "hostname": "cloudflare.com",
                "port": 443,
                "category": "cdn",
            },
            "scanned_at": "2026-05-21T10:00:00+00:00",
            "probe_group": None,
            "pcap_path": "/var/pqc-obs/pcaps/cloudflare-2026-05-21.pcap",
            "is_pqc": True,
            "is_hybrid": True,
            "selected_group": "X25519MLKEM768",
            "negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256",
            "capture_metadata": ANALYZER_OUTPUT["capture_metadata"],
        }
    ]


def test_observatory_handshake_detail(client, tmp_path, monkeypatch):
    _write_observatory_data(tmp_path, monkeypatch)

    resp = client.get("/api/observatory/handshakes/1")

    assert resp.status_code == 200
    assert resp.json() == ANALYZER_OUTPUT


def test_observatory_handshake_detail_not_found(client, tmp_path, monkeypatch):
    _write_observatory_data(tmp_path, monkeypatch)

    resp = client.get("/api/observatory/handshakes/not-found")

    assert resp.status_code == 404
