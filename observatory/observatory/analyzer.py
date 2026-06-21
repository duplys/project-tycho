"""Tool 1 (PCAP Analyzer) integration.

Calls the tls_pcap_analyzer library directly (no subprocess) to extract
structured TLS handshake data from a pcap file.
"""

from __future__ import annotations

import dataclasses
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def run_analyzer(pcap_path: Path) -> dict[str, Any] | None:
    """Analyse *pcap_path* with Tool 1 and return its output as a dict.

    Parameters
    ----------
    pcap_path:
        Path to the pcap file to analyse.

    Returns
    -------
    dict or None
        Parsed handshake data, or ``None`` if no TLS handshake was found or
        an error occurred during analysis.
    """
    try:
        from tls_pcap_analyzer.parser import parse_pcap  # type: ignore[import]
    except ImportError:
        log.error(
            "tls_pcap_analyzer is not installed. "
            "Ensure the package is listed as a dependency and the environment "
            "has been set up with 'uv sync'."
        )
        return None

    log.debug("Analysing pcap with tls_pcap_analyzer: %s", pcap_path)
    try:
        records = parse_pcap(pcap_path)
    except Exception as exc:
        log.error("tls_pcap_analyzer failed to parse %s: %s", pcap_path, exc)
        return None

    if not records:
        log.warning("No TLS handshakes found in %s", pcap_path)
        return None

    return dataclasses.asdict(records[0])
