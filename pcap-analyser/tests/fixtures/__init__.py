"""
Helpers to build synthetic TLS handshake pcap fixtures for testing.

All generated pcaps contain a single TLS 1.3 ClientHello and ServerHello
carried over TCP/IP.  No application data or encryption is present — the
tool only inspects the plaintext handshake records.
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Low-level TLS record / handshake building helpers
# ---------------------------------------------------------------------------

def _uint8(v: int) -> bytes:
    return struct.pack("B", v)


def _uint16(v: int) -> bytes:
    return struct.pack(">H", v)


def _uint24(v: int) -> bytes:
    return struct.pack(">I", v)[1:]


def _tls_handshake_record(msg_type: int, body: bytes) -> bytes:
    """Wrap *body* in a TLS Handshake message and then in a TLS record."""
    hs_msg = _uint8(msg_type) + _uint24(len(body)) + body
    # content_type=22 (Handshake), version=TLS 1.2 compat (0x0303), length
    return b"\x16\x03\x03" + _uint16(len(hs_msg)) + hs_msg


def _client_hello(
    cipher_suites: list[int],
    supported_groups: list[int],
    sig_algos: list[int],
    key_shares: list[tuple[int, bytes]],
    sni: str | None = None,
) -> bytes:
    """Build a minimal TLS 1.3-advertising ClientHello."""
    # legacy_version = TLS 1.2
    legacy_version = b"\x03\x03"
    # random (32 bytes of zeros for testing)
    random = b"\x00" * 32
    # session_id (empty)
    session_id = b"\x00"

    # cipher suites
    cs_bytes = b"".join(_uint16(cs) for cs in cipher_suites)
    cs_block = _uint16(len(cs_bytes)) + cs_bytes

    # compression methods (no compression)
    compression = b"\x01\x00"

    # --- Extensions ---
    exts = b""

    # SNI extension
    if sni is not None:
        sni_encoded = sni.encode("ascii")
        sni_entry = _uint8(0) + _uint16(len(sni_encoded)) + sni_encoded
        sni_list = _uint16(len(sni_entry)) + sni_entry
        exts += _uint16(0x0000) + _uint16(len(sni_list)) + sni_list

    # supported_groups extension
    sg_bytes = b"".join(_uint16(g) for g in supported_groups)
    sg_body = _uint16(len(sg_bytes)) + sg_bytes
    exts += _uint16(0x000A) + _uint16(len(sg_body)) + sg_body

    # signature_algorithms extension
    sa_bytes = b"".join(_uint16(s) for s in sig_algos)
    sa_body = _uint16(len(sa_bytes)) + sa_bytes
    exts += _uint16(0x000D) + _uint16(len(sa_body)) + sa_body

    # supported_versions extension (advertise TLS 1.3)
    sv_bytes = _uint16(0x0304) + _uint16(0x0303)  # TLS 1.3, TLS 1.2
    sv_body = _uint8(len(sv_bytes)) + sv_bytes
    exts += _uint16(0x002B) + _uint16(len(sv_body)) + sv_body

    # key_share extension
    ks_entries = b""
    for group_id, ke_data in key_shares:
        ks_entries += _uint16(group_id) + _uint16(len(ke_data)) + ke_data
    ks_body = _uint16(len(ks_entries)) + ks_entries
    exts += _uint16(0x0033) + _uint16(len(ks_body)) + ks_body

    ext_block = _uint16(len(exts)) + exts

    body = legacy_version + random + session_id + cs_block + compression + ext_block
    return _tls_handshake_record(1, body)


def _server_hello(
    cipher_suite: int,
    selected_group: int,
    ke_data: bytes,
) -> bytes:
    """Build a minimal TLS 1.3 ServerHello."""
    legacy_version = b"\x03\x03"
    random = b"\x00" * 32
    session_id = b"\x00"
    cs = _uint16(cipher_suite)
    compression = b"\x00"

    exts = b""

    # supported_versions: TLS 1.3
    sv_body = _uint16(0x0304)
    exts += _uint16(0x002B) + _uint16(len(sv_body)) + sv_body

    # key_share: single entry (no leading length in ServerHello)
    ks_entry = _uint16(selected_group) + _uint16(len(ke_data)) + ke_data
    exts += _uint16(0x0033) + _uint16(len(ks_entry)) + ks_entry

    ext_block = _uint16(len(exts)) + exts
    body = legacy_version + random + session_id + cs + compression + ext_block
    return _tls_handshake_record(2, body)


# ---------------------------------------------------------------------------
# Pcap writer (no external dependency — minimal pcap format)
# ---------------------------------------------------------------------------

_PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic
    2, 4,        # version
    0,           # timezone offset
    0,           # timestamp accuracy
    65535,       # snap length
    1,           # link type: Ethernet
)

_ETH_IP_TCP_HEADER_LEN = 14 + 20 + 20  # Ethernet + IPv4 + TCP


def _pcap_packet(
    payload: bytes,
    timestamp: float = 0.0,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    sport: int = 52345,
    dport: int = 443,
    seq: int = 1000,
) -> bytes:
    """Wrap *payload* in a pcap packet record with a minimal Ethernet/IP/TCP header."""
    # Ethernet header: dst=00:00:00:00:00:01, src=00:00:00:00:00:02, type=IPv4
    eth = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x08\x00"
    total_ip_len = 20 + 20 + len(payload)
    src_bytes = bytes(int(x) for x in src_ip.split("."))
    dst_bytes = bytes(int(x) for x in dst_ip.split("."))
    # IPv4 header (no options, no checksum validation needed for pcap)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,           # version=4, IHL=5
        0,              # DSCP/ECN
        total_ip_len,
        0x1234,         # identification
        0x4000,         # Don't Fragment
        64,             # TTL
        6,              # protocol TCP
        0,              # checksum (0 for test)
        src_bytes,
        dst_bytes,
    )
    # TCP header (minimal)
    tcp = struct.pack(
        ">HHIIBBHHH",
        sport,          # src port
        dport,          # dst port
        seq,            # seq
        0,              # ack
        0x50,           # data offset=5 (20 bytes), reserved=0
        0x00,           # flags
        65535,          # window
        0,              # checksum
        0,              # urgent pointer
    )
    frame = eth + ip + tcp + payload
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1_000_000)
    pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
    return pkt_hdr + frame


def _write_pcap(path: Path, packets: list[tuple[bytes, float, dict]]) -> None:
    """
    Write a minimal pcap file.

    *packets* is a list of (payload, timestamp, kwargs) where kwargs are
    forwarded to ``_pcap_packet`` (src_ip, dst_ip, sport, dport, seq).
    """
    with path.open("wb") as f:
        f.write(_PCAP_GLOBAL_HEADER)
        for payload, ts, kwargs in packets:
            f.write(_pcap_packet(payload, timestamp=ts, **kwargs))


# ---------------------------------------------------------------------------
# Fixture factories
# ---------------------------------------------------------------------------

def make_classical_tls13_pcap(path: Path | None = None) -> Path:
    """
    Create a pcap with a classical TLS 1.3 handshake (x25519 key exchange).
    """
    ch = _client_hello(
        cipher_suites=[0x1301, 0x1302, 0x1303],
        supported_groups=[0x001D, 0x0017, 0x0018],  # x25519, secp256r1, secp384r1
        sig_algos=[0x0804, 0x0403, 0x0807],          # rsa_pss_rsae_sha256, ecdsa_secp256r1, ed25519
        key_shares=[(0x001D, b"\xAB" * 32)],         # x25519 key (32 bytes)
        sni="example.com",
    )
    sh = _server_hello(
        cipher_suite=0x1301,
        selected_group=0x001D,
        ke_data=b"\xCD" * 32,
    )
    if path is None:
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        path = Path(tmp.name)
        tmp.close()
    _write_pcap(
        path,
        [
            (ch, 1000.0, {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "sport": 52345, "dport": 443, "seq": 1}),
            (sh, 1000.1, {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "sport": 443, "dport": 52345, "seq": 1}),
        ],
    )
    return path


def make_hybrid_mlkem768_pcap(path: Path | None = None) -> Path:
    """
    Create a pcap with a hybrid TLS 1.3 handshake (X25519MLKEM768).
    ML-KEM-768 public key is 1184 bytes; X25519 adds 32 bytes → 1216 total.
    """
    hybrid_ke = b"\xAB" * 1216  # 32 (X25519) + 1184 (ML-KEM-768 encapsulation key)
    ch = _client_hello(
        cipher_suites=[0x1301, 0x1302, 0x1303],
        supported_groups=[0x11EC, 0x001D, 0x0017],  # X25519MLKEM768, x25519, secp256r1
        sig_algos=[0x0804, 0x0403, 0x0807],
        key_shares=[(0x11EC, hybrid_ke)],
        sni="cloudflare.com",
    )
    hybrid_sh_ke = b"\xCD" * 1120  # ML-KEM-768 ciphertext is 1088 bytes + 32 X25519
    sh = _server_hello(
        cipher_suite=0x1301,
        selected_group=0x11EC,
        ke_data=hybrid_sh_ke,
    )
    if path is None:
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        path = Path(tmp.name)
        tmp.close()
    _write_pcap(
        path,
        [
            (ch, 2000.0, {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "sport": 52345, "dport": 443, "seq": 1}),
            (sh, 2000.2, {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "sport": 443, "dport": 52345, "seq": 1}),
        ],
    )
    return path


def make_empty_pcap(path: Path | None = None) -> Path:
    """Create a pcap with no TLS traffic."""
    if path is None:
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        path = Path(tmp.name)
        tmp.close()
    _write_pcap(path, [])
    return path
