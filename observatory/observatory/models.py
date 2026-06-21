"""Data models for targets and scan results."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Target(BaseModel):
    """A host that the observatory will periodically scan."""

    hostname: str
    port: int = 443
    # Descriptive category for segmentation (cdn, hyperscaler, tech, finance,
    # government, education, …).
    category: str = "unknown"
    is_active: bool = True
    notes: str = ""

    @field_validator("hostname")
    @classmethod
    def _strip_scheme(cls, v: str) -> str:
        # Allow users to paste bare URLs like "https://example.com".
        for prefix in ("https://", "http://"):
            if v.startswith(prefix):
                v = v[len(prefix):]
        # Strip trailing slashes and paths, then normalize the hostname.
        return v.split("/")[0].strip().rstrip(".").lower()

    @field_validator("port")
    @classmethod
    def _valid_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"Invalid port number: {v}")
        return v


class HandshakeData(BaseModel):
    """Subset of analyzer JSON that the observatory indexes for trend queries."""

    tls_version: str | None = None
    negotiated_cipher_suite: str | None = None
    selected_group: str | None = None
    key_share_size_bytes: int | None = None
    is_pqc: bool = False
    is_hybrid: bool = False
    pqc_algorithms_detected: list[str] = Field(default_factory=list)
    signature_algorithm: str | None = None

    @classmethod
    def from_analyzer_output(cls, data: dict[str, Any]) -> "HandshakeData":
        """Extract handshake fields from the Tool 1 JSON output schema."""
        server = data.get("server_hello", {})
        cert = data.get("certificate_info") or {}
        client = data.get("client_hello", {})
        return cls(
            tls_version=client.get("tls_version"),
            negotiated_cipher_suite=server.get("negotiated_cipher_suite"),
            selected_group=server.get("selected_group"),
            key_share_size_bytes=server.get("key_share_size_bytes"),
            is_pqc=bool(server.get("is_pqc", False)),
            is_hybrid=bool(server.get("is_hybrid", False)),
            pqc_algorithms_detected=server.get("pqc_algorithms_detected", []),
            signature_algorithm=cert.get("signature_algorithm"),
        )


class ScanResult(BaseModel):
    """One scan attempt for one target at one point in time."""

    target_hostname: str
    target_port: int
    scanned_at: datetime
    # Named group intentionally offered for this targeted capability probe.
    probe_group: str | None = None
    pcap_path: str | None = None
    # Full JSON blob returned by Tool 1 (may be None if analyzer failed or
    # no analyzer is installed yet).
    analyzer_output: dict[str, Any] | None = None
    # Structured subset for fast SQL queries.
    handshake: HandshakeData | None = None
    # Non-None when the scan itself failed (DNS failure, timeout, TLS error…).
    error: str | None = None
    # Wall-clock time for the complete capture + handshake, in milliseconds.
    scan_duration_ms: int | None = None
