"""
Unit tests for the TLS PCAP Analyzer.

Uses synthetic pcap fixtures that are generated in-memory rather than
shipping binary files.  All fixtures produce valid minimal Ethernet/IP/TCP
frames carrying TLS 1.3 Handshake records.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from tls_pcap_analyzer import parse_pcap
from tls_pcap_analyzer.pqc_registry import (
    group_name,
    is_hybrid_group,
    is_pqc_group,
    is_pqc_sig_algo,
    cipher_suite_name,
    sig_algo_name,
)

from tests.fixtures import (
    make_classical_tls13_pcap,
    make_empty_pcap,
    make_hybrid_mlkem768_pcap,
)


# ---------------------------------------------------------------------------
# pqc_registry tests
# ---------------------------------------------------------------------------


class TestPqcRegistry:
    def test_classical_group_not_pqc(self):
        assert not is_pqc_group(0x001D)  # x25519

    def test_mlkem768_is_pqc(self):
        assert is_pqc_group(0x0201)  # MLKEM768

    def test_hybrid_group_is_pqc_and_hybrid(self):
        assert is_pqc_group(0x11EC)   # X25519MLKEM768
        assert is_hybrid_group(0x11EC)

    def test_sm2_mlkem_group_is_pqc_and_hybrid(self):
        assert is_pqc_group(0x11EE)  # curveSM2MLKEM768
        assert is_hybrid_group(0x11EE)

    def test_pure_mlkem_is_not_hybrid(self):
        assert not is_hybrid_group(0x0201)

    def test_group_name_known(self):
        assert group_name(0x001D) == "x25519"
        assert group_name(0x11EB) == "SecP256r1MLKEM768"
        assert group_name(0x11EC) == "X25519MLKEM768"
        assert group_name(0x11EE) == "curveSM2MLKEM768"
        assert group_name(0x0201) == "MLKEM768"

    def test_group_name_unknown(self):
        assert group_name(0xDEAD) == "0xDEAD"

    def test_cipher_suite_name(self):
        assert cipher_suite_name(0x1301) == "TLS_AES_128_GCM_SHA256"
        assert cipher_suite_name(0x1302) == "TLS_AES_256_GCM_SHA384"

    def test_sig_algo_name(self):
        assert sig_algo_name(0x0804) == "rsa_pss_rsae_sha256"
        assert sig_algo_name(0x0904) == "mldsa44"

    def test_pqc_sig_algos(self):
        assert is_pqc_sig_algo(0x0904)  # mldsa44
        assert is_pqc_sig_algo(0x0905)  # mldsa65
        assert is_pqc_sig_algo(0x0B01)  # slhdsa_sha2_128s
        assert not is_pqc_sig_algo(0x0804)  # rsa_pss_rsae_sha256


# ---------------------------------------------------------------------------
# Parser tests — empty pcap
# ---------------------------------------------------------------------------


class TestEmptyPcap:
    def test_no_records_returned(self, tmp_path):
        pcap = make_empty_pcap(tmp_path / "empty.pcap")
        records = parse_pcap(pcap)
        assert records == []


# ---------------------------------------------------------------------------
# Parser tests — classical TLS 1.3
# ---------------------------------------------------------------------------


class TestClassicalTls13:
    @pytest.fixture(scope="class")
    def record(self, tmp_path_factory):
        pcap = make_classical_tls13_pcap(
            tmp_path_factory.mktemp("fixtures") / "classical.pcap"
        )
        records = parse_pcap(pcap)
        assert len(records) >= 1
        return records[0]

    def test_capture_metadata_filename(self, record):
        assert record.capture_metadata.filename == "classical.pcap"

    def test_capture_metadata_hosts_set(self, record):
        assert record.capture_metadata.source_host is not None
        assert record.capture_metadata.destination_host is not None

    def test_client_hello_present(self, record):
        assert record.client_hello is not None

    def test_tls_version_13(self, record):
        assert record.client_hello.tls_version == "TLS 1.3"

    def test_cipher_suites_present(self, record):
        assert "TLS_AES_128_GCM_SHA256" in record.client_hello.cipher_suites

    def test_supported_groups(self, record):
        assert "x25519" in record.client_hello.supported_groups
        assert "secp256r1" in record.client_hello.supported_groups

    def test_sig_algos_present(self, record):
        assert "rsa_pss_rsae_sha256" in record.client_hello.signature_algorithms

    def test_sni_extension(self, record):
        assert record.client_hello.extensions.get("server_name") == "example.com"

    def test_key_share_present(self, record):
        assert len(record.client_hello.key_shares) == 1
        ks = record.client_hello.key_shares[0]
        assert ks.group_name == "x25519"
        assert ks.key_exchange_length == 32

    def test_server_hello_present(self, record):
        assert record.server_hello is not None

    def test_negotiated_cipher_suite(self, record):
        assert record.server_hello.negotiated_cipher_suite == "TLS_AES_128_GCM_SHA256"

    def test_selected_group_x25519(self, record):
        assert record.server_hello.selected_group == "x25519"

    def test_not_pqc(self, record):
        assert not record.server_hello.is_pqc

    def test_not_hybrid(self, record):
        assert not record.server_hello.is_hybrid

    def test_no_pqc_algorithms_detected(self, record):
        assert record.server_hello.pqc_algorithms_detected == []


# ---------------------------------------------------------------------------
# Parser tests — hybrid X25519MLKEM768
# ---------------------------------------------------------------------------


class TestHybridMlkem768:
    @pytest.fixture(scope="class")
    def record(self, tmp_path_factory):
        pcap = make_hybrid_mlkem768_pcap(
            tmp_path_factory.mktemp("fixtures") / "hybrid.pcap"
        )
        records = parse_pcap(pcap)
        assert len(records) >= 1
        return records[0]

    def test_client_hello_present(self, record):
        assert record.client_hello is not None

    def test_hybrid_group_in_supported_groups(self, record):
        assert "X25519MLKEM768" in record.client_hello.supported_groups

    def test_sni_cloudflare(self, record):
        assert record.client_hello.extensions.get("server_name") == "cloudflare.com"

    def test_key_share_hybrid_size(self, record):
        assert len(record.client_hello.key_shares) == 1
        ks = record.client_hello.key_shares[0]
        assert ks.group_name == "X25519MLKEM768"
        assert ks.key_exchange_length == 1216

    def test_server_hello_pqc(self, record):
        assert record.server_hello is not None
        assert record.server_hello.is_pqc

    def test_server_hello_hybrid(self, record):
        assert record.server_hello.is_hybrid

    def test_selected_group_hybrid(self, record):
        assert record.server_hello.selected_group == "X25519MLKEM768"

    def test_key_share_size_bytes(self, record):
        assert record.server_hello.key_share_size_bytes == 1120

    def test_pqc_algorithms_detected(self, record):
        assert "X25519MLKEM768" in record.server_hello.pqc_algorithms_detected


# ---------------------------------------------------------------------------
# JSON serialisation round-trip
# ---------------------------------------------------------------------------


class TestJsonSerialisation:
    def test_classical_serialises_to_json(self, tmp_path):
        pcap = make_classical_tls13_pcap(tmp_path / "c.pcap")
        records = parse_pcap(pcap)
        assert records
        d = dataclasses.asdict(records[0])
        text = json.dumps(d)
        parsed = json.loads(text)
        assert parsed["server_hello"]["is_pqc"] is False

    def test_hybrid_serialises_to_json(self, tmp_path):
        pcap = make_hybrid_mlkem768_pcap(tmp_path / "h.pcap")
        records = parse_pcap(pcap)
        assert records
        d = dataclasses.asdict(records[0])
        text = json.dumps(d)
        parsed = json.loads(text)
        assert parsed["server_hello"]["is_pqc"] is True
        assert parsed["server_hello"]["is_hybrid"] is True


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestCli:
    def test_cli_classical(self, tmp_path, capsys):
        from tls_pcap_analyzer.cli import main

        pcap = make_classical_tls13_pcap(tmp_path / "c.pcap")
        rc = main([str(pcap), "--pretty"])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["server_hello"]["is_pqc"] is False

    def test_cli_hybrid_all(self, tmp_path, capsys):
        from tls_pcap_analyzer.cli import main

        pcap = make_hybrid_mlkem768_pcap(tmp_path / "h.pcap")
        rc = main([str(pcap), "--all", "--pretty"])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert data[0]["server_hello"]["is_hybrid"] is True

    def test_cli_missing_file(self, tmp_path):
        from tls_pcap_analyzer.cli import main

        rc = main([str(tmp_path / "nonexistent.pcap")])
        assert rc == 1

    def test_cli_output_file(self, tmp_path):
        from tls_pcap_analyzer.cli import main

        pcap = make_classical_tls13_pcap(tmp_path / "c.pcap")
        out = tmp_path / "result.json"
        rc = main([str(pcap), "--output", str(out)])
        assert rc == 0
        data = json.loads(out.read_text())
        assert "capture_metadata" in data
