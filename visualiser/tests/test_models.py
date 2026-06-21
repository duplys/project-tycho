from tls_visualizer.models import (
    TLSHandshakeRecord,
    CaptureMetadata,
    ClientHelloInfo,
    ServerHelloInfo,
    CertificateInfo,
    HandshakeTiming,
    KeyShareEntry,
)
from tests.conftest import SAMPLE_RECORD


def test_parse_full_record():
    record = TLSHandshakeRecord.model_validate(SAMPLE_RECORD)

    assert record.capture_metadata is not None
    assert record.capture_metadata.filename == "cloudflare-2026-04-23.pcap"
    assert record.capture_metadata.source_host == "192.168.1.10"

    assert record.client_hello is not None
    assert record.client_hello.tls_version == "TLS 1.3"
    assert "TLS_AES_128_GCM_SHA256" in record.client_hello.cipher_suites
    assert "X25519MLKEM768" in record.client_hello.supported_groups
    assert len(record.client_hello.key_shares) == 1
    assert record.client_hello.key_shares[0].group_name == "X25519MLKEM768"
    assert record.client_hello.key_shares[0].key_exchange_length == 1216

    assert record.server_hello is not None
    assert record.server_hello.negotiated_cipher_suite == "TLS_AES_128_GCM_SHA256"
    assert record.server_hello.selected_group == "X25519MLKEM768"
    assert record.server_hello.is_pqc is True
    assert record.server_hello.is_hybrid is True

    assert record.certificate_info is not None
    assert record.certificate_info.signature_algorithm == "ecdsa_secp256r1_sha256"
    assert record.certificate_info.is_pqc_signature is False

    assert record.handshake_timing is not None
    assert record.handshake_timing.handshake_duration_ms == 200.0


def test_optional_fields_empty():
    record = TLSHandshakeRecord()
    assert record.capture_metadata is None
    assert record.client_hello is None
    assert record.server_hello is None
    assert record.certificate_info is None
    assert record.handshake_timing is None


def test_partial_record():
    data = {
        "capture_metadata": {"filename": "test.pcap"},
        "server_hello": {"is_pqc": False},
    }
    record = TLSHandshakeRecord.model_validate(data)
    assert record.capture_metadata.filename == "test.pcap"
    assert record.server_hello.is_pqc is False
    assert record.client_hello is None


def test_key_share_entry():
    ks = KeyShareEntry(group_id=4587, group_name="X25519MLKEM768", key_exchange_length=1216)
    assert ks.group_id == 4587
    assert ks.group_name == "X25519MLKEM768"
    assert ks.key_exchange_length == 1216


def test_key_share_entry_optional():
    ks = KeyShareEntry()
    assert ks.group_id is None
    assert ks.group_name is None
    assert ks.key_exchange_length is None
