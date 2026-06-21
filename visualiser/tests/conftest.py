import pytest
from fastapi.testclient import TestClient

SAMPLE_RECORD = {
    "capture_metadata": {
        "filename": "cloudflare-2026-04-23.pcap",
        "captured_at": "2026-04-23T02:00:01+00:00",
        "source_host": "192.168.1.10",
        "destination_host": "104.16.0.1",
    },
    "client_hello": {
        "tls_version": "TLS 1.3",
        "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
        "supported_groups": ["X25519MLKEM768", "x25519", "secp256r1"],
        "signature_algorithms": ["rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256"],
        "extensions": {
            "server_name": "cloudflare.com",
            "supported_versions": ["0x0304", "0x0303"],
        },
        "key_shares": [
            {
                "group_id": 4587,
                "group_name": "X25519MLKEM768",
                "key_exchange_length": 1216,
            }
        ],
    },
    "server_hello": {
        "negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256",
        "selected_group": "X25519MLKEM768",
        "key_share_size_bytes": 1120,
        "is_pqc": True,
        "is_hybrid": True,
        "pqc_algorithms_detected": ["X25519MLKEM768"],
    },
    "certificate_info": {
        "signature_algorithm": "ecdsa_secp256r1_sha256",
        "is_pqc_signature": False,
    },
    "handshake_timing": {
        "client_hello_timestamp": 1745373601.0,
        "server_hello_timestamp": 1745373601.2,
        "handshake_duration_ms": 200.0,
    },
}


@pytest.fixture
def sample_record():
    return SAMPLE_RECORD


@pytest.fixture
def client():
    # Import after SAMPLE_RECORD is defined so the store starts clean
    from tls_visualizer.app import app, handshake_store
    handshake_store.clear()
    with TestClient(app) as c:
        yield c
    handshake_store.clear()
