"""
TLS PCAP Analyzer — parse pcap files to extract TLS handshake information
with first-class support for PQC and hybrid algorithms.

Public API
----------
    from tls_pcap_analyzer import parse_pcap

    records = parse_pcap("capture.pcap")
    for record in records:
        print(record.server_hello.is_pqc)
"""

from .parser import parse_pcap

__all__ = ["parse_pcap"]
