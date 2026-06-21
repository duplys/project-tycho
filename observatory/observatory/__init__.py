"""PQC Observatory — Tool 3 of Project Tycho.

Periodically scans a curated list of target sites, captures TLS handshakes
as pcap files, invokes the PCAP Analyzer (Tool 1), and persists structured
time-series results in a machine-readable JSON file for the adoption dashboard
(Tool 2).
"""

__version__ = "0.1.0"
