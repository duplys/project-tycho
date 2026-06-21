"""
Data models for TLS handshake analysis output.

The output schema mirrors the specification in PQC-TLS-observatory-spec.md §4.4.
All models are plain dataclasses that serialise to JSON-compatible dicts via
``dataclasses.asdict``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CaptureMetadata:
    filename: str
    captured_at: str | None
    source_host: str | None
    destination_host: str | None


@dataclass
class KeyShareEntry:
    group_id: int
    group_name: str
    key_exchange_length: int


@dataclass
class ClientHelloInfo:
    tls_version: str
    cipher_suites: list[str]
    supported_groups: list[str]
    signature_algorithms: list[str]
    extensions: dict[str, object]
    key_shares: list[KeyShareEntry]


@dataclass
class ServerHelloInfo:
    negotiated_cipher_suite: str
    selected_group: str | None
    key_share_size_bytes: int
    is_pqc: bool
    is_hybrid: bool
    pqc_algorithms_detected: list[str]


@dataclass
class CertificateInfo:
    signature_algorithm: str | None
    is_pqc_signature: bool


@dataclass
class HandshakeTiming:
    client_hello_timestamp: float | None
    server_hello_timestamp: float | None
    handshake_duration_ms: float | None


@dataclass
class TLSHandshakeRecord:
    capture_metadata: CaptureMetadata
    client_hello: ClientHelloInfo | None
    server_hello: ServerHelloInfo | None
    certificate_info: CertificateInfo | None
    handshake_timing: HandshakeTiming = field(
        default_factory=lambda: HandshakeTiming(None, None, None)
    )
