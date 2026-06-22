import subprocess

import pytest

from observatory import scanner


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (
            "MLKEM512:MLKEM768:X25519MLKEM768",
            {"MLKEM512", "MLKEM768", "X25519MLKEM768"},
        ),
        (
            "MLKEM512\nMLKEM768\ncurveSM2MLKEM768\n",
            {"MLKEM512", "MLKEM768", "curveSM2MLKEM768"},
        ),
    ],
)
def test_parse_openssl_tls_groups(output, expected):
    assert scanner.parse_openssl_tls_groups(output) == expected


def test_discover_openssl_capabilities(monkeypatch):
    outputs = iter(
        [
            "OpenSSL 4.0.1 9 Jun 2026",
            "MLKEM512:MLKEM768:curveSM2MLKEM768",
        ]
    )
    monkeypatch.setattr(scanner, "_run_openssl_query", lambda *args: next(outputs))

    capabilities = scanner.discover_openssl_capabilities()

    assert capabilities.version == "OpenSSL 4.0.1 9 Jun 2026"
    assert capabilities.implemented_groups == {
        "MLKEM512",
        "MLKEM768",
        "curveSM2MLKEM768",
    }


def test_openssl_query_rejects_missing_binary(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda command: None)

    with pytest.raises(RuntimeError, match="not found on PATH"):
        scanner.discover_openssl_capabilities()


def test_openssl_query_rejects_failed_command(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda command: "/opt/openssl/bin/openssl")
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], returncode=1, stdout="", stderr="provider failed"
        ),
    )

    with pytest.raises(RuntimeError, match="provider failed"):
        scanner.discover_openssl_capabilities()
