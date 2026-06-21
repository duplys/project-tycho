"""
Core TLS PCAP parser.

Loads a pcap file with scapy, reassembles TCP streams, and extracts structured
information about TLS 1.3 handshakes with first-class support for PQC and
hybrid algorithms.
"""

from __future__ import annotations

import struct
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from scapy.all import rdpcap  # type: ignore[import-untyped]
from scapy.layers.inet import IP, TCP  # type: ignore[import-untyped]
from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]

from .models import (
    CaptureMetadata,
    CertificateInfo,
    ClientHelloInfo,
    HandshakeTiming,
    KeyShareEntry,
    ServerHelloInfo,
    TLSHandshakeRecord,
)
from .pqc_registry import (
    PQC_CERT_SIG_ALGO_OIDS,
    cipher_suite_name,
    group_name,
    is_hybrid_group,
    is_pqc_cert_sig_algo,
    is_pqc_group,
    sig_algo_name,
)

# TLS record content types
_TLS_HANDSHAKE = 22

# TLS handshake message types
_HS_CLIENT_HELLO = 1
_HS_SERVER_HELLO = 2
_HS_CERTIFICATE = 11

# TLS extension types
_EXT_SERVER_NAME = 0x0000
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SIG_ALGOS = 0x000D
_EXT_SIG_ALGOS_CERT = 0x0032
_EXT_KEY_SHARE = 0x0033
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_ECH = 0xFE0D

# TLS version wire values
_TLS_VERSION_13 = 0x0304
_TLS_VERSION_12 = 0x0303


# ---------------------------------------------------------------------------
# TCP stream reassembly
# ---------------------------------------------------------------------------

FlowKey = tuple[str, int, str, int]  # (src_ip, sport, dst_ip, dport)


def _extract_flow_key(pkt) -> FlowKey | None:
    """Return the 4-tuple flow key for an IP/TCP packet, or None."""
    if pkt.haslayer(IP):
        ip = pkt[IP]
        src_ip, dst_ip = ip.src, ip.dst
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src_ip, dst_ip = ip6.src, ip6.dst
    else:
        return None
    if not pkt.haslayer(TCP):
        return None
    tcp = pkt[TCP]
    return (src_ip, tcp.sport, dst_ip, tcp.dport)


def _reassemble_tcp_streams(
    packets,
) -> dict[FlowKey, tuple[list[tuple[int, bytes, float]], str, str]]:
    """
    Group TCP packets by 4-tuple and return per-direction data.

    Returns a dict mapping flow-key → (segments, src_ip, dst_ip) where each
    segment is (seq, payload_bytes, timestamp).  Segments are *not* yet
    concatenated so callers can do sequence-number–aware assembly.
    """
    flows: dict[FlowKey, tuple[list[tuple[int, bytes, float]], str, str]] = {}
    for pkt in packets:
        key = _extract_flow_key(pkt)
        if key is None:
            continue
        tcp = pkt[TCP]
        raw = bytes(tcp.payload)
        if not raw:
            continue
        src_ip = key[0]
        dst_ip = key[2]
        if key not in flows:
            flows[key] = ([], src_ip, dst_ip)
        flows[key][0].append((tcp.seq, raw, float(pkt.time)))
    return flows


def _concat_stream(segments: list[tuple[int, bytes, float]]) -> bytes:
    """
    Assemble TCP segments into a contiguous byte stream.

    Sorts by sequence number and handles simple overlaps / retransmits.
    Sequence-number wrap-around is handled via modular arithmetic.
    """
    if not segments:
        return b""
    segments = sorted(segments, key=lambda s: s[0])
    data = bytearray(segments[0][1])
    next_seq = (segments[0][0] + len(segments[0][1])) & 0xFFFF_FFFF
    for seq, payload, _ in segments[1:]:
        seq_end = (seq + len(payload)) & 0xFFFF_FFFF
        if seq == next_seq:
            data.extend(payload)
            next_seq = seq_end
        elif seq < next_seq:
            # Overlap or retransmit
            overlap = (next_seq - seq) & 0xFFFF_FFFF
            if overlap < len(payload):
                data.extend(payload[overlap:])
                next_seq = seq_end
        else:
            # Gap — append anyway (best effort)
            data.extend(payload)
            next_seq = seq_end
    return bytes(data)


# ---------------------------------------------------------------------------
# TLS record / handshake framing
# ---------------------------------------------------------------------------


def _iter_tls_records(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield (content_type, payload) for each TLS record in *data*."""
    pos = 0
    while pos + 5 <= len(data):
        content_type = data[pos]
        length = struct.unpack_from(">H", data, pos + 3)[0]
        end = pos + 5 + length
        if end > len(data):
            break
        yield content_type, data[pos + 5 : end]
        pos = end


def _iter_handshake_messages(record_payload: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield (msg_type, body) for each handshake message in a Handshake record."""
    pos = 0
    while pos + 4 <= len(record_payload):
        msg_type = record_payload[pos]
        length = (
            (record_payload[pos + 1] << 16)
            | (record_payload[pos + 2] << 8)
            | record_payload[pos + 3]
        )
        end = pos + 4 + length
        if end > len(record_payload):
            break
        yield msg_type, record_payload[pos + 4 : end]
        pos = end


# ---------------------------------------------------------------------------
# Extension parsing helpers
# ---------------------------------------------------------------------------


def _parse_extensions(ext_data: bytes, *, is_client: bool) -> dict[str, object]:
    """
    Parse TLS extensions from raw bytes.

    Returns a dict of extracted fields.  Extension types that are not
    explicitly handled are stored as ``{"ext_0xXXXX": "<hex>"}`` entries
    so that callers can still detect their presence.
    """
    result: dict[str, object] = {}
    pos = 0
    while pos + 4 <= len(ext_data):
        ext_type = struct.unpack_from(">H", ext_data, pos)[0]
        ext_len = struct.unpack_from(">H", ext_data, pos + 2)[0]
        pos += 4
        body = ext_data[pos : pos + ext_len]
        pos += ext_len

        if ext_type == _EXT_SERVER_NAME:
            result["server_name"] = _parse_sni(body)

        elif ext_type == _EXT_SUPPORTED_GROUPS:
            result["supported_groups_raw"] = _parse_group_list(body)

        elif ext_type == _EXT_SIG_ALGOS:
            result["signature_algorithms_raw"] = _parse_uint16_list(body, offset=0)

        elif ext_type == _EXT_SIG_ALGOS_CERT:
            result["signature_algorithms_cert_raw"] = _parse_uint16_list(body, offset=0)

        elif ext_type == _EXT_SUPPORTED_VERSIONS:
            result["supported_versions"] = _parse_supported_versions(body, is_client=is_client)

        elif ext_type == _EXT_KEY_SHARE:
            result["key_share"] = _parse_key_share(body, is_client=is_client)

        elif ext_type == _EXT_ECH:
            result["encrypted_client_hello"] = True

        else:
            # Record presence of unknown/unhandled extensions by type number
            result[f"ext_0x{ext_type:04X}"] = body.hex() if body else True

    return result


def _parse_sni(data: bytes) -> str | None:
    if len(data) < 5:
        return None
    # 2-byte list length, then entries: 1-byte type + 2-byte name length + name
    list_len = struct.unpack_from(">H", data, 0)[0]
    pos = 2
    end = min(pos + list_len, len(data))
    while pos + 3 <= end:
        name_type = data[pos]
        name_len = struct.unpack_from(">H", data, pos + 1)[0]
        pos += 3
        if name_type == 0 and pos + name_len <= end:
            return data[pos : pos + name_len].decode("ascii", errors="replace")
        pos += name_len
    return None


def _parse_group_list(data: bytes) -> list[int]:
    if len(data) < 2:
        return []
    list_len = struct.unpack_from(">H", data, 0)[0]
    groups = []
    for i in range(0, min(list_len, len(data) - 2), 2):
        groups.append(struct.unpack_from(">H", data, 2 + i)[0])
    return groups


def _parse_uint16_list(data: bytes, *, offset: int = 0) -> list[int]:
    """Parse a length-prefixed list of uint16 values starting at *offset*."""
    if len(data) < offset + 2:
        return []
    list_len = struct.unpack_from(">H", data, offset)[0]
    items = []
    for i in range(0, min(list_len, len(data) - offset - 2), 2):
        items.append(struct.unpack_from(">H", data, offset + 2 + i)[0])
    return items


def _parse_supported_versions(data: bytes, *, is_client: bool) -> list[str]:
    if is_client:
        # ClientHello: 1-byte length + list of 2-byte versions
        if not data:
            return []
        list_len = data[0]
        versions = []
        for i in range(0, min(list_len, len(data) - 1), 2):
            ver = struct.unpack_from(">H", data, 1 + i)[0]
            versions.append(f"0x{ver:04X}")
        return versions
    else:
        # ServerHello: single 2-byte selected version
        if len(data) < 2:
            return []
        ver = struct.unpack_from(">H", data, 0)[0]
        return [f"0x{ver:04X}"]


def _parse_key_share(data: bytes, *, is_client: bool) -> list[dict]:
    entries = []
    if is_client:
        # 2-byte total length, then entries
        if len(data) < 2:
            return entries
        total = struct.unpack_from(">H", data, 0)[0]
        pos = 2
        end = min(pos + total, len(data))
    else:
        # ServerHello key_share: no leading length; directly one entry
        pos = 0
        end = len(data)

    while pos + 4 <= end:
        group_id = struct.unpack_from(">H", data, pos)[0]
        ke_len = struct.unpack_from(">H", data, pos + 2)[0]
        pos += 4
        entries.append(
            {
                "group_id": group_id,
                "group_name": group_name(group_id),
                "key_exchange_length": ke_len,
            }
        )
        pos += ke_len
    return entries


# ---------------------------------------------------------------------------
# ClientHello / ServerHello parsing
# ---------------------------------------------------------------------------


def _parse_client_hello(body: bytes) -> ClientHelloInfo | None:
    """Parse a ClientHello handshake body and return a ClientHelloInfo."""
    try:
        pos = 0
        if len(body) < 2 + 32:
            return None
        # legacy_version
        pos += 2
        # random
        pos += 32
        # session_id
        session_id_len = body[pos]
        pos += 1 + session_id_len
        # cipher suites
        if pos + 2 > len(body):
            return None
        cs_len = struct.unpack_from(">H", body, pos)[0]
        pos += 2
        cipher_suites_raw: list[int] = []
        for i in range(0, cs_len, 2):
            if pos + i + 2 > len(body):
                break
            cipher_suites_raw.append(struct.unpack_from(">H", body, pos + i)[0])
        pos += cs_len
        # compression methods
        if pos >= len(body):
            return None
        cm_len = body[pos]
        pos += 1 + cm_len
        # extensions
        extensions_raw: dict[str, object] = {}
        if pos + 2 <= len(body):
            ext_total = struct.unpack_from(">H", body, pos)[0]
            pos += 2
            ext_data = body[pos : pos + ext_total]
            extensions_raw = _parse_extensions(ext_data, is_client=True)

        # Build friendly cipher suite list
        cipher_suites = [cipher_suite_name(cs) for cs in cipher_suites_raw]

        # supported_groups comes from the extension
        supported_groups_raw: list[int] = extensions_raw.pop("supported_groups_raw", [])  # type: ignore[arg-type]
        supported_groups = [group_name(g) for g in supported_groups_raw]

        # signature_algorithms from extension
        sig_algos_raw: list[int] = extensions_raw.pop("signature_algorithms_raw", [])  # type: ignore[arg-type]
        # Also remove cert sig algos (keep in extensions dict for reference)
        signature_algorithms = [sig_algo_name(s) for s in sig_algos_raw]

        # key_shares from key_share extension
        key_share_raw: list[dict] = extensions_raw.pop("key_share", [])  # type: ignore[assignment]
        key_shares = [
            KeyShareEntry(
                group_id=ks["group_id"],
                group_name=ks["group_name"],
                key_exchange_length=ks["key_exchange_length"],
            )
            for ks in key_share_raw
        ]

        # Determine negotiated TLS version from supported_versions extension
        sup_vers: list[str] = extensions_raw.get("supported_versions", [])  # type: ignore[assignment]
        tls_version = "TLS 1.3" if "0x0304" in sup_vers else "TLS 1.2 or earlier"

        return ClientHelloInfo(
            tls_version=tls_version,
            cipher_suites=cipher_suites,
            supported_groups=supported_groups,
            signature_algorithms=signature_algorithms,
            extensions=extensions_raw,
            key_shares=key_shares,
        )
    except (struct.error, IndexError):
        return None


def _parse_server_hello(body: bytes) -> ServerHelloInfo | None:
    """Parse a ServerHello handshake body and return a ServerHelloInfo."""
    try:
        pos = 0
        if len(body) < 2 + 32:
            return None
        # legacy_version
        pos += 2
        # random (could be HelloRetryRequest magic — we ignore that distinction here)
        pos += 32
        # session_id echo
        session_id_len = body[pos]
        pos += 1 + session_id_len
        # cipher suite (single value)
        if pos + 2 > len(body):
            return None
        cs_id = struct.unpack_from(">H", body, pos)[0]
        pos += 2
        # compression method
        pos += 1
        # extensions
        extensions_raw: dict[str, object] = {}
        if pos + 2 <= len(body):
            ext_total = struct.unpack_from(">H", body, pos)[0]
            pos += 2
            ext_data = body[pos : pos + ext_total]
            extensions_raw = _parse_extensions(ext_data, is_client=False)

        # key_share in ServerHello: single entry
        key_share_raw: list[dict] = extensions_raw.pop("key_share", [])  # type: ignore[assignment]
        selected_group_id: int | None = None
        key_share_size = 0
        if key_share_raw:
            first = key_share_raw[0]
            selected_group_id = first["group_id"]
            key_share_size = first["key_exchange_length"]

        selected_group_str = (
            group_name(selected_group_id) if selected_group_id is not None else None
        )

        is_pqc = selected_group_id is not None and is_pqc_group(selected_group_id)
        is_hybrid = selected_group_id is not None and is_hybrid_group(selected_group_id)

        pqc_detected: list[str] = []
        if selected_group_id is not None and is_pqc_group(selected_group_id):
            pqc_detected.append(group_name(selected_group_id))

        return ServerHelloInfo(
            negotiated_cipher_suite=cipher_suite_name(cs_id),
            selected_group=selected_group_str,
            key_share_size_bytes=key_share_size,
            is_pqc=is_pqc,
            is_hybrid=is_hybrid,
            pqc_algorithms_detected=pqc_detected,
        )
    except (struct.error, IndexError):
        return None


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------


def _parse_certificate_info(body: bytes) -> CertificateInfo | None:
    """
    Parse the first leaf certificate from a TLS 1.3 Certificate message.

    Returns basic signature algorithm information.
    """
    try:
        from cryptography import x509  # lazy import
        from cryptography.hazmat.primitives.serialization import Encoding  # noqa: F401

        pos = 0
        # certificate_request_context length (1 byte)
        if pos >= len(body):
            return None
        ctx_len = body[pos]
        pos += 1 + ctx_len
        # certificate_list length (3 bytes)
        if pos + 3 > len(body):
            return None
        list_len = (body[pos] << 16) | (body[pos + 1] << 8) | body[pos + 2]
        pos += 3
        list_end = pos + list_len
        # First cert entry: 3-byte cert_data_length + DER data
        if pos + 3 > list_end:
            return None
        cert_data_len = (body[pos] << 16) | (body[pos + 1] << 8) | body[pos + 2]
        pos += 3
        if pos + cert_data_len > len(body):
            return None
        cert_der = body[pos : pos + cert_data_len]
        cert = x509.load_der_x509_certificate(cert_der)
        oid = cert.signature_algorithm_oid.dotted_string
        algo_name = PQC_CERT_SIG_ALGO_OIDS.get(oid, oid)
        is_pqc = is_pqc_cert_sig_algo(oid)
        return CertificateInfo(signature_algorithm=algo_name, is_pqc_signature=is_pqc)
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_pcap(filepath: str | Path) -> list[TLSHandshakeRecord]:
    """
    Parse a pcap file and return a list of TLSHandshakeRecord objects.

    Each record corresponds to one TLS connection found in the capture.
    The function is tolerant of malformed or truncated data and will skip
    unparseable packets rather than raising exceptions.

    Parameters
    ----------
    filepath:
        Path to the pcap (or pcapng) file.

    Returns
    -------
    list[TLSHandshakeRecord]
        Possibly empty list if no TLS handshakes were found.
    """
    filepath = Path(filepath)
    packets = rdpcap(str(filepath))

    # Collect the timestamp of the first packet for capture metadata
    first_ts: float | None = None
    for pkt in packets:
        first_ts = float(pkt.time)
        break

    captured_at: str | None = None
    if first_ts is not None:
        captured_at = datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat()

    # Reassemble TCP streams per direction
    flows = _reassemble_tcp_streams(packets)

    # Build per-connection handshake records
    # A TLS connection has two directions: client→server and server→client.
    # We index by the normalised connection key (sorted 4-tuple) and accumulate
    # messages from both directions.
    Connection = tuple[str, int, str, int]  # normalised so smaller tuple comes first

    class _ConnState:
        client_hello: ClientHelloInfo | None = None
        server_hello: ServerHelloInfo | None = None
        cert_info: CertificateInfo | None = None
        client_ip: str | None = None
        server_ip: str | None = None
        ch_ts: float | None = None
        sh_ts: float | None = None

    conn_states: dict[Connection, _ConnState] = {}

    for flow_key, (segments, src_ip, dst_ip) in flows.items():
        stream = _concat_stream(segments)
        if not stream:
            continue

        # Track per-segment timestamps for timing
        seg_ts_map: dict[int, float] = {}  # seq → timestamp
        for seq, _payload, ts in segments:
            seg_ts_map.setdefault(seq, ts)
        first_seg_ts = segments[0][2] if segments else None

        # Normalise connection key
        rev_key = (flow_key[2], flow_key[3], flow_key[0], flow_key[1])
        conn_key: Connection = min(flow_key, rev_key)

        if conn_key not in conn_states:
            conn_states[conn_key] = _ConnState()
        state = conn_states[conn_key]

        for ct, record_payload in _iter_tls_records(stream):
            if ct != _TLS_HANDSHAKE:
                continue
            for msg_type, msg_body in _iter_handshake_messages(record_payload):
                if msg_type == _HS_CLIENT_HELLO and state.client_hello is None:
                    ch = _parse_client_hello(msg_body)
                    if ch is not None:
                        state.client_hello = ch
                        state.client_ip = src_ip
                        state.server_ip = dst_ip
                        state.ch_ts = first_seg_ts

                elif msg_type == _HS_SERVER_HELLO and state.server_hello is None:
                    sh = _parse_server_hello(msg_body)
                    if sh is not None:
                        state.server_hello = sh
                        state.sh_ts = first_seg_ts

                elif msg_type == _HS_CERTIFICATE and state.cert_info is None:
                    ci = _parse_certificate_info(msg_body)
                    if ci is not None:
                        state.cert_info = ci

    # Convert connection states to TLSHandshakeRecord objects
    records: list[TLSHandshakeRecord] = []
    for state in conn_states.values():
        if state.client_hello is None and state.server_hello is None:
            continue

        duration_ms: float | None = None
        if state.ch_ts is not None and state.sh_ts is not None:
            duration_ms = (state.sh_ts - state.ch_ts) * 1000.0

        record = TLSHandshakeRecord(
            capture_metadata=CaptureMetadata(
                filename=filepath.name,
                captured_at=captured_at,
                source_host=state.client_ip,
                destination_host=state.server_ip,
            ),
            client_hello=state.client_hello,
            server_hello=state.server_hello,
            certificate_info=state.cert_info,
            handshake_timing=HandshakeTiming(
                client_hello_timestamp=state.ch_ts,
                server_hello_timestamp=state.sh_ts,
                handshake_duration_ms=duration_ms,
            ),
        )
        records.append(record)

    return records
