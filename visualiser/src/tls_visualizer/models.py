from __future__ import annotations

from typing import Optional
from pydantic import BaseModel


class KeyShareEntry(BaseModel):
    group_id: Optional[int] = None
    group_name: Optional[str] = None
    key_exchange_length: Optional[int] = None


class ClientHelloInfo(BaseModel):
    tls_version: Optional[str] = None
    cipher_suites: Optional[list[str]] = None
    supported_groups: Optional[list[str]] = None
    signature_algorithms: Optional[list[str]] = None
    extensions: Optional[dict] = None
    key_shares: Optional[list[KeyShareEntry]] = None


class ServerHelloInfo(BaseModel):
    negotiated_cipher_suite: Optional[str] = None
    selected_group: Optional[str] = None
    key_share_size_bytes: Optional[int] = None
    is_pqc: Optional[bool] = None
    is_hybrid: Optional[bool] = None
    pqc_algorithms_detected: Optional[list[str]] = None


class CaptureMetadata(BaseModel):
    filename: Optional[str] = None
    captured_at: Optional[str] = None
    source_host: Optional[str] = None
    destination_host: Optional[str] = None


class CertificateInfo(BaseModel):
    signature_algorithm: Optional[str] = None
    is_pqc_signature: Optional[bool] = None


class HandshakeTiming(BaseModel):
    client_hello_timestamp: Optional[float] = None
    server_hello_timestamp: Optional[float] = None
    handshake_duration_ms: Optional[float] = None


class TLSHandshakeRecord(BaseModel):
    capture_metadata: Optional[CaptureMetadata] = None
    client_hello: Optional[ClientHelloInfo] = None
    server_hello: Optional[ServerHelloInfo] = None
    certificate_info: Optional[CertificateInfo] = None
    handshake_timing: Optional[HandshakeTiming] = None
