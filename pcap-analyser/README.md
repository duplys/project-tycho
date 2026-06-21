# PCAP Analyser

A command-line tool and importable Python library that parses pcap files and
extracts structured data about TLS handshakes, with **first-class support for
PQC cipher suites, key exchange groups, and signature algorithms**.

This is the PCAP Analyser component of the [PQC-TLS Observatory](../PQC-TLS-observatory-spec.md).

---

## Features

- Reads pcap / pcapng files (post-hoc analysis, no live capture)
- Parses TLS 1.3 handshake records using **scapy**
- Extracts from **ClientHello**:
  - Supported cipher suites
  - Supported groups (including PQC and hybrid groups)
  - Signature algorithms
  - Extensions: SNI, ECH, key_share, supported_versions, …
- Extracts from **ServerHello**:
  - Negotiated cipher suite
  - Selected group
  - Key share payload size (useful for identifying PQC handshakes by their
    larger payloads)
- **Identifies PQC algorithms**: ML-KEM-512/768/1024, ML-DSA-44/65/87,
  SLH-DSA (all FIPS 205 variants), and all known hybrid identifiers
  (X25519MLKEM768, SecP256r1MLKEM768, …)
- Emits **structured JSON** consumable by the Visualiser
- Graceful on malformed or truncated captures — skips unparseable records
  rather than crashing

## Requirements

- Python >= 3.10
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Installation

```bash
cd pcap-analyser
uv sync
```

Or with pip:

```bash
pip install -e .
```

## Usage

### CLI

```bash
# Analyse a single capture (outputs the first TLS connection)
tls-pcap-analyzer capture.pcap

# Pretty-print
tls-pcap-analyzer capture.pcap --pretty

# Output all TLS connections found in the capture
tls-pcap-analyzer capture.pcap --all --pretty

# Write to a file instead of stdout
tls-pcap-analyzer capture.pcap --output result.json
```

### Python library

```python
from tls_pcap_analyzer import parse_pcap

records = parse_pcap("capture.pcap")
for r in records:
    print(r.capture_metadata.filename)
    print(r.server_hello.selected_group)
    print(r.server_hello.is_pqc)
    print(r.server_hello.pqc_algorithms_detected)
```

## Output Schema

```json
{
  "capture_metadata": {
    "filename": "cloudflare-2026-04-23.pcap",
    "captured_at": "2026-04-23T02:00:01+00:00",
    "source_host": "192.168.1.10",
    "destination_host": "104.16.0.1"
  },
  "client_hello": {
    "tls_version": "TLS 1.3",
    "cipher_suites": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
    "supported_groups": ["X25519MLKEM768", "x25519", "secp256r1"],
    "signature_algorithms": ["rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256"],
    "extensions": {
      "server_name": "cloudflare.com",
      "supported_versions": ["0x0304", "0x0303"]
    },
    "key_shares": [
      { "group_id": 4587, "group_name": "X25519MLKEM768", "key_exchange_length": 1216 }
    ]
  },
  "server_hello": {
    "negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256",
    "selected_group": "X25519MLKEM768",
    "key_share_size_bytes": 1120,
    "is_pqc": true,
    "is_hybrid": true,
    "pqc_algorithms_detected": ["X25519MLKEM768"]
  },
  "certificate_info": {
    "signature_algorithm": "ecdsa_secp256r1_sha256",
    "is_pqc_signature": false
  },
  "handshake_timing": {
    "client_hello_timestamp": 1745373601.0,
    "server_hello_timestamp": 1745373601.2,
    "handshake_duration_ms": 200.0
  }
}
```

## Development

```bash
# Install with dev dependencies
uv sync --extra dev

# Run tests
uv run pytest tests/ -v
```

## Recognized PQC Algorithms

### Key Exchange / Named Groups

| Code point | Name | Type |
|---|---|---|
| 0x0200 | MLKEM512 | Pure PQC |
| 0x0201 | MLKEM768 | Pure PQC |
| 0x0202 | MLKEM1024 | Pure PQC |
| 0x11EB | X25519MLKEM768 | Hybrid |
| 0x11EC | SecP256r1MLKEM768 | Hybrid |
| 0x11ED | SecP384r1MLKEM1024 | Hybrid |
| 0x6399 | X25519Kyber768Draft00 | Hybrid (experimental) |

### Signature Algorithms

| Code point | Name | Standard |
|---|---|---|
| 0x0904 | mldsa44 | FIPS 204 |
| 0x0905 | mldsa65 | FIPS 204 |
| 0x0906 | mldsa87 | FIPS 204 |
| 0x0B01-0x0B0C | slhdsa_* | FIPS 205 |
