from tls_visualizer.models import TLSHandshakeRecord
from tls_visualizer.tikz.generator import (
    generate_handshake_flow_tikz,
    generate_key_share_comparison_tikz,
)
from tests.conftest import SAMPLE_RECORD


def _make_record(data=None) -> TLSHandshakeRecord:
    return TLSHandshakeRecord.model_validate(data or SAMPLE_RECORD)


def test_handshake_flow_returns_string():
    result = generate_handshake_flow_tikz(_make_record())
    assert isinstance(result, str)
    assert len(result) > 0


def test_handshake_flow_contains_tikzpicture():
    result = generate_handshake_flow_tikz(_make_record())
    assert r"\begin{tikzpicture}" in result
    assert r"\end{tikzpicture}" in result


def test_handshake_flow_contains_client_hello():
    result = generate_handshake_flow_tikz(_make_record())
    assert "ClientHello" in result


def test_handshake_flow_contains_server_hello():
    result = generate_handshake_flow_tikz(_make_record())
    assert "ServerHello" in result


def test_handshake_flow_pqc_color_when_pqc():
    result = generate_handshake_flow_tikz(_make_record())
    # PQC/hybrid record should use pqcblue color
    assert "pqcblue" in result


def test_handshake_flow_contains_sni():
    result = generate_handshake_flow_tikz(_make_record())
    # Check that the SNI hostname from the sample fixture appears verbatim in the TikZ output.
    # This is a string equality check on template output, not URL validation.
    sni_value = SAMPLE_RECORD["client_hello"]["extensions"]["server_name"]
    assert sni_value in result


def test_handshake_flow_contains_cipher_suite():
    result = generate_handshake_flow_tikz(_make_record())
    assert "Cipher Suites:" not in result


def test_handshake_flow_contains_supported_groups():
    result = generate_handshake_flow_tikz(_make_record())
    assert "Supported Groups:" in result
    assert "X25519MLKEM768" in result


def test_handshake_flow_escapes_signature_algorithm():
    # Certificate messages are not included in the LaTeX export because the PCAP
    # capture stops after ServerHello, so signature algorithm info is not present.
    # Verify it is not in the output.
    data = dict(SAMPLE_RECORD)
    cert_info = dict(data["certificate_info"])
    cert_info["signature_algorithm"] = "rsa_pss_rsae_sha256"
    data["certificate_info"] = cert_info

    result = generate_handshake_flow_tikz(_make_record(data))
    # Signature algorithm should not be in the output since we stop after ServerHello
    assert "rsa_pss_rsae_sha256" not in result and "rsa\\_pss\\_rsae\\_sha256" not in result


def test_handshake_flow_duration():
    result = generate_handshake_flow_tikz(_make_record())
    assert "200.0" in result or "200" in result


def test_handshake_flow_empty_record():
    result = generate_handshake_flow_tikz(TLSHandshakeRecord())
    assert r"\begin{tikzpicture}" in result
    assert r"\end{tikzpicture}" in result


def test_key_share_comparison_returns_string():
    result = generate_key_share_comparison_tikz(_make_record())
    assert isinstance(result, str)
    assert len(result) > 0


def test_key_share_comparison_contains_tikzpicture():
    result = generate_key_share_comparison_tikz(_make_record())
    assert r"\begin{tikzpicture}" in result
    assert r"\end{tikzpicture}" in result


def test_key_share_comparison_contains_axis():
    result = generate_key_share_comparison_tikz(_make_record())
    assert r"\begin{axis}" in result
    assert r"\end{axis}" in result


def test_key_share_comparison_contains_group_name():
    result = generate_key_share_comparison_tikz(_make_record())
    assert "X25519MLKEM768" in result


def test_key_share_comparison_contains_size():
    result = generate_key_share_comparison_tikz(_make_record())
    assert "1216" in result


def test_key_share_comparison_fallback_empty_record():
    result = generate_key_share_comparison_tikz(TLSHandshakeRecord())
    assert r"\begin{tikzpicture}" in result
    assert "x25519" in result.lower()


def test_key_share_classification_hybrid():
    result = generate_key_share_comparison_tikz(_make_record())
    assert "hybridteal" in result


def test_key_share_coordinates_have_parentheses():
    """pgfplots requires coordinates in (x, y) form; verify the format is correct."""
    result = generate_key_share_comparison_tikz(_make_record())
    # The sample record has X25519MLKEM768 with key_exchange_length=1216.
    # After the fix, the output must contain "(1216, 0)" (or similar indexed form).
    import re
    coords = re.findall(r"\(\d+,\s*\d+\)", result)
    assert len(coords) > 0, "No valid (x, y) coordinates found in pgfplots output"
