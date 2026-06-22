"""
Registry of TLS algorithm identifiers with PQC and hybrid classification.

Sources:
  - IANA TLS Parameters: https://www.iana.org/assignments/tls-parameters/
  - NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
  - draft-ietf-tls-hybrid-design (hybrid key exchange)
  - draft-ietf-tls-mlkem (standalone ML-KEM key exchange)
  - draft-ietf-tls-ecdhe-mlkem (ECDHE/ML-KEM hybrid groups)
  - draft-yang-tls-hybrid-sm2-mlkem (SM2/ML-KEM hybrid group)
  - draft-ietf-tls-mldsa (ML-DSA in TLS)
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TLS 1.3 cipher suites
# ---------------------------------------------------------------------------

CIPHER_SUITE_NAMES: dict[int, str] = {
    # TLS 1.3
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    # TLS 1.2 (common subset)
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    # GREASE values (RFC 8701)
    0x0A0A: "GREASE",
    0x1A1A: "GREASE",
    0x2A2A: "GREASE",
    0x3A3A: "GREASE",
    0x4A4A: "GREASE",
    0x5A5A: "GREASE",
    0x6A6A: "GREASE",
    0x7A7A: "GREASE",
    0x8A8A: "GREASE",
    0x9A9A: "GREASE",
    0xAAAA: "GREASE",
    0xBABA: "GREASE",
    0xCACA: "GREASE",
    0xDADA: "GREASE",
    0xEAEA: "GREASE",
    0xFAFA: "GREASE",
}

# ---------------------------------------------------------------------------
# Named groups (supported_groups / key_share)
# ---------------------------------------------------------------------------

NAMED_GROUP_NAMES: dict[int, str] = {
    # Finite-field Diffie-Hellman
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
    # Elliptic curves (classical)
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0023: "brainpoolP256r1",
    0x0024: "brainpoolP384r1",
    0x0025: "brainpoolP512r1",
    # Pure ML-KEM groups, registered in the IANA TLS Supported Groups registry.
    # Source: https://datatracker.ietf.org/doc/html/draft-ietf-tls-mlkem#section-4.1
    0x0200: "MLKEM512",
    0x0201: "MLKEM768",
    0x0202: "MLKEM1024",
    # ECDHE/ML-KEM hybrid groups.
    # Source: https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem#section-7
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    # SM2/ML-KEM hybrid group (TLS 1.3 only).
    # Source: https://datatracker.ietf.org/doc/html/draft-yang-tls-hybrid-sm2-mlkem#section-4
    0x11EE: "curveSM2MLKEM768",
    # Obsolete pre-standard Kyber hybrid groups, retained for PCAP analysis.
    # Source: https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem#section-7.4
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
    # GREASE values (RFC 8701)
    0x0A0A: "GREASE",
    0x1A1A: "GREASE",
    0x2A2A: "GREASE",
    0x3A3A: "GREASE",
    0x4A4A: "GREASE",
    0x5A5A: "GREASE",
    0x6A6A: "GREASE",
    0x7A7A: "GREASE",
    0x8A8A: "GREASE",
    0x9A9A: "GREASE",
    0xAAAA: "GREASE",
    0xBABA: "GREASE",
    0xCACA: "GREASE",
    0xDADA: "GREASE",
    0xEAEA: "GREASE",
    0xFAFA: "GREASE",
}

# Set of pure PQC (non-hybrid) group IDs
PQC_ONLY_GROUPS: frozenset[int] = frozenset({0x0200, 0x0201, 0x0202})

# Set of hybrid (classical + PQC) group IDs
HYBRID_GROUPS: frozenset[int] = frozenset(
    {0x11EB, 0x11EC, 0x11ED, 0x11EE, 0x6399, 0x639A}
)

# All groups that carry PQC material
PQC_GROUPS: frozenset[int] = PQC_ONLY_GROUPS | HYBRID_GROUPS

# ---------------------------------------------------------------------------
# Signature algorithms (SignatureScheme in TLS 1.3)
# ---------------------------------------------------------------------------

SIG_ALGO_NAMES: dict[int, str] = {
    # RSA PKCS1
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    # ECDSA
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    # RSA-PSS RSAE
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    # EdDSA
    0x0807: "ed25519",
    0x0808: "ed448",
    # RSA-PSS PSS
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
    # Brainpool ECDSA
    0x081A: "ecdsa_brainpoolP256r1tls13_sha256",
    0x081B: "ecdsa_brainpoolP384r1tls13_sha384",
    0x081C: "ecdsa_brainpoolP512r1tls13_sha512",
    # ML-DSA (draft-ietf-tls-mldsa codepoints)
    0x0904: "mldsa44",
    0x0905: "mldsa65",
    0x0906: "mldsa87",
    # Hybrid ML-DSA (draft-ietf-tls-mldsa)
    0x0907: "mldsa44_rsa2048_pkcs1_sha256",
    0x0908: "mldsa44_rsa2048_pss_sha256",
    0x0909: "mldsa44_ed25519",
    0x090A: "mldsa44_ecdsa_secp256r1_sha256",
    0x090B: "mldsa65_rsa3072_pkcs1_sha512",
    0x090C: "mldsa65_rsa3072_pss_sha512",
    0x090D: "mldsa65_ecdsa_secp256r1_sha512",
    0x090E: "mldsa65_ed25519",
    0x090F: "mldsa87_ecdsa_secp384r1_sha512",
    0x0910: "mldsa87_ed448",
    # SLH-DSA (FIPS 205 / draft-ietf-tls-slhdsa codepoints)
    0x0B01: "slhdsa_sha2_128s",
    0x0B02: "slhdsa_sha2_128f",
    0x0B03: "slhdsa_sha2_192s",
    0x0B04: "slhdsa_sha2_192f",
    0x0B05: "slhdsa_sha2_256s",
    0x0B06: "slhdsa_sha2_256f",
    0x0B07: "slhdsa_shake_128s",
    0x0B08: "slhdsa_shake_128f",
    0x0B09: "slhdsa_shake_192s",
    0x0B0A: "slhdsa_shake_192f",
    0x0B0B: "slhdsa_shake_256s",
    0x0B0C: "slhdsa_shake_256f",
    # GREASE
    0x0A0A: "GREASE",
    0x1A1A: "GREASE",
    0x2A2A: "GREASE",
    0x3A3A: "GREASE",
    0x4A4A: "GREASE",
    0x5A5A: "GREASE",
    0x6A6A: "GREASE",
    0x7A7A: "GREASE",
    0x8A8A: "GREASE",
    0x9A9A: "GREASE",
    0xAAAA: "GREASE",
    0xBABA: "GREASE",
    0xCACA: "GREASE",
    0xDADA: "GREASE",
    0xEAEA: "GREASE",
    0xFAFA: "GREASE",
}

# Pure ML-DSA / SLH-DSA signature algorithm IDs
PQC_SIG_ALGOS: frozenset[int] = frozenset(
    {0x0904, 0x0905, 0x0906}  # ML-DSA
    | {0x0B01, 0x0B02, 0x0B03, 0x0B04, 0x0B05, 0x0B06,
       0x0B07, 0x0B08, 0x0B09, 0x0B0A, 0x0B0B, 0x0B0C}  # SLH-DSA
)

# X.509 signature algorithm OIDs for PQC
# Source: NIST FIPS 204 / 205 and IANA registrations
PQC_CERT_SIG_ALGO_OIDS: dict[str, str] = {
    # ML-DSA (FIPS 204)
    "2.16.840.1.101.3.4.3.17": "mldsa44",
    "2.16.840.1.101.3.4.3.18": "mldsa65",
    "2.16.840.1.101.3.4.3.19": "mldsa87",
    # SLH-DSA (FIPS 205) SHA-2 variants
    "2.16.840.1.101.3.4.3.20": "slhdsa_sha2_128s",
    "2.16.840.1.101.3.4.3.21": "slhdsa_sha2_128f",
    "2.16.840.1.101.3.4.3.22": "slhdsa_sha2_192s",
    "2.16.840.1.101.3.4.3.23": "slhdsa_sha2_192f",
    "2.16.840.1.101.3.4.3.24": "slhdsa_sha2_256s",
    "2.16.840.1.101.3.4.3.25": "slhdsa_sha2_256f",
    # SLH-DSA (FIPS 205) SHAKE variants
    "2.16.840.1.101.3.4.3.26": "slhdsa_shake_128s",
    "2.16.840.1.101.3.4.3.27": "slhdsa_shake_128f",
    "2.16.840.1.101.3.4.3.28": "slhdsa_shake_192s",
    "2.16.840.1.101.3.4.3.29": "slhdsa_shake_192f",
    "2.16.840.1.101.3.4.3.30": "slhdsa_shake_256s",
    "2.16.840.1.101.3.4.3.31": "slhdsa_shake_256f",
}

# ---------------------------------------------------------------------------
# TLS extension types
# ---------------------------------------------------------------------------

TLS_EXTENSION_NAMES: dict[int, str] = {
    0x0000: "server_name",
    0x0001: "max_fragment_length",
    0x0005: "status_request",
    0x000A: "supported_groups",
    0x000B: "ec_point_formats",
    0x000D: "signature_algorithms",
    0x000F: "heartbeat",
    0x0010: "application_layer_protocol_negotiation",
    0x0012: "signed_certificate_timestamp",
    0x0015: "padding",
    0x0017: "extended_master_secret",
    0x001B: "compress_certificate",
    0x001C: "record_size_limit",
    0x0023: "session_ticket",
    0x0029: "pre_shared_key",
    0x002A: "early_data",
    0x002B: "supported_versions",
    0x002C: "cookie",
    0x002D: "psk_key_exchange_modes",
    0x002F: "certificate_authorities",
    0x0031: "post_handshake_auth",
    0x0032: "signature_algorithms_cert",
    0x0033: "key_share",
    0xFE0D: "encrypted_client_hello",
    0xFF01: "renegotiation_info",
}

# ---------------------------------------------------------------------------
# TLS version constants
# ---------------------------------------------------------------------------

TLS_VERSIONS: dict[int, str] = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def group_name(group_id: int) -> str:
    """Return a human-readable name for a named group ID."""
    return NAMED_GROUP_NAMES.get(group_id, f"0x{group_id:04X}")


def cipher_suite_name(cs_id: int) -> str:
    """Return a human-readable name for a cipher suite ID."""
    return CIPHER_SUITE_NAMES.get(cs_id, f"0x{cs_id:04X}")


def sig_algo_name(sa_id: int) -> str:
    """Return a human-readable name for a signature algorithm ID."""
    return SIG_ALGO_NAMES.get(sa_id, f"0x{sa_id:04X}")


def is_pqc_group(group_id: int) -> bool:
    """Return True if the group carries PQC key material."""
    return group_id in PQC_GROUPS


def is_hybrid_group(group_id: int) -> bool:
    """Return True if the group is a classical+PQC hybrid."""
    return group_id in HYBRID_GROUPS


def is_pqc_sig_algo(sa_id: int) -> bool:
    """Return True if the signature algorithm is a PQC scheme."""
    return sa_id in PQC_SIG_ALGOS


def is_pqc_cert_sig_algo(oid: str) -> bool:
    """Return True if the X.509 signature OID belongs to a PQC scheme."""
    return oid in PQC_CERT_SIG_ALGO_OIDS
