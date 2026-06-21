"""TLS handshake pcap capture.

Captures a complete TLS handshake between the observatory host and a remote
target by:

1. Starting ``tcpdump`` as a background subprocess, filtered to the target's
   IP address and port so only relevant packets are written to disk.
2. Opening a TCP connection and performing a TLS handshake via the standard
   library ``ssl`` module.
3. Sending a minimal HTTP/1.0 request so the remote side sends at least one
   application-data record, confirming the handshake completed successfully.
4. Stopping ``tcpdump`` and returning the path to the captured ``.pcap`` file.

Requires ``tcpdump`` to be installed and the process to have the ``cap_net_raw``
capability (or to run as root).  In the Docker Compose setup this is handled by
granting ``NET_RAW`` to the observatory container.
"""

from __future__ import annotations

import logging
import re
import shutil
import signal
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from observatory.config import settings

log = logging.getLogger(__name__)

# Number of bytes to attempt to read from the TLS connection after the GET
# request — just enough to confirm the handshake completed.
_RESPONSE_PEEK_BYTES = 4096

# Grace period (seconds) given to tcpdump after the connection is closed so
# that any buffered packets are flushed to the pcap file before we send SIGTERM.
_TCPDUMP_FLUSH_DELAY_S = 0.5

# Maximum time (seconds) to wait for tcpdump to exit cleanly after SIGTERM.
_TCPDUMP_TERMINATE_TIMEOUT_S = 5

# Extra grace window added on top of network timeout for external TLS clients.
_EXTERNAL_TLS_TIMEOUT_GRACE_S = 5


def _safe_filename_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")


def _resolve_ip(hostname: str, port: int) -> str:
    """Return the first IPv4/IPv6 address for *hostname*."""
    results = socket.getaddrinfo(
        hostname,
        port,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    if not results:
        raise OSError(f"DNS resolution returned no results for {hostname}")
    return results[0][4][0]


def _tcpdump_available() -> bool:
    return shutil.which("tcpdump") is not None


def _openssl_available() -> bool:
    return shutil.which("openssl") is not None


def _perform_python_tls_handshake(
    *,
    ip_addr: str,
    hostname: str,
    port: int,
    timeout_s: int,
) -> None:
    """Perform a TLS handshake using Python's stdlib ssl module."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Explicitly require TLS 1.2 or higher; PQC suites only exist in TLS 1.3
    # and allowing earlier versions serves no observatory purpose.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Connect to the same resolved IP address used by the tcpdump filter
    # so the captured traffic always includes this handshake. Keep using
    # the original hostname for SNI and certificate hostname validation.
    with socket.create_connection((ip_addr, port), timeout=timeout_s) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            log.debug(
                "TLS handshake complete with %s:%d — cipher=%s, version=%s",
                hostname,
                port,
                ssock.cipher(),
                ssock.version(),
            )
            # Minimal HTTP request to receive at least one application
            # record before closing, ensuring the full handshake appears
            # in the capture.
            http_req = (
                f"GET / HTTP/1.0\\r\\n"
                f"Host: {hostname}\\r\\n"
                f"User-Agent: {settings.scan_user_agent}\\r\\n"
                f"Connection: close\\r\\n"
                f"\\r\\n"
            ).encode()
            ssock.sendall(http_req)
            try:
                ssock.recv(_RESPONSE_PEEK_BYTES)
            except ssl.SSLError:
                pass  # Some servers close without sending a close_notify.


def _perform_openssl_tls_handshake(
    *,
    ip_addr: str,
    hostname: str,
    port: int,
    timeout_s: int,
    openssl_groups: str | None,
) -> None:
    """Perform a TLS handshake using openssl s_client."""
    if not _openssl_available():
        raise RuntimeError(
            "OpenSSL client not found on PATH. Install openssl to use "
            "scan_client='openssl'."
        )

    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{ip_addr}:{port}",
        "-servername",
        hostname,
        "-tls1_3",
        "-brief",
        "-ign_eof",
    ]
    if openssl_groups:
        cmd.extend(["-groups", openssl_groups])

    http_req = (
        f"GET / HTTP/1.0\\r\\n"
        f"Host: {hostname}\\r\\n"
        f"User-Agent: {settings.scan_user_agent}\\r\\n"
        f"Connection: close\\r\\n"
        f"\\r\\n"
    )

    result = subprocess.run(
        cmd,
        input=http_req,
        capture_output=True,
        text=True,
        timeout=timeout_s + _EXTERNAL_TLS_TIMEOUT_GRACE_S,
        check=False,
    )

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        details = stderr or stdout or "openssl s_client exited non-zero"
        raise RuntimeError(f"openssl handshake failed: {details}")


def capture_tls_handshake(
    hostname: str,
    port: int = 443,
    pcap_dir: Path | None = None,
    timeout_s: int | None = None,
    scan_client: Literal["python", "openssl"] = "python",
    openssl_groups: str | None = None,
    capture_label: str | None = None,
) -> Path:
    """Capture a TLS handshake to a pcap file and return its path.

    Parameters
    ----------
    hostname:
        The remote hostname to connect to.
    port:
        The remote port (default 443).
    pcap_dir:
        Directory in which to write the pcap file.  Defaults to
        ``settings.pcap_dir``.
    timeout_s:
        TCP/TLS connection timeout.  Defaults to ``settings.scan_timeout_s``.
    scan_client:
        TLS client implementation to use for handshake generation.
        ``python`` uses stdlib ssl, ``openssl`` uses ``openssl s_client``.
    openssl_groups:
        Optional OpenSSL ``-groups`` value to explicitly advertise named
        groups (e.g. hybrid PQC groups) when ``scan_client='openssl'``.
    capture_label:
        Optional label included in the output filename to distinguish repeated
        captures for the same host.

    Returns
    -------
    Path
        Absolute path to the written ``.pcap`` file.

    Raises
    ------
    OSError
        On DNS failure, connection error, or pcap directory creation failure.
    RuntimeError
        When ``tcpdump`` is not available on the system PATH.
    """
    if not _tcpdump_available():
        raise RuntimeError(
            "tcpdump is not installed or not on PATH.  "
            "Install it (apt install tcpdump) and ensure the process has "
            "CAP_NET_RAW or is run as root."
        )

    pcap_dir = pcap_dir or settings.pcap_dir
    timeout_s = timeout_s if timeout_s is not None else settings.scan_timeout_s

    pcap_dir.mkdir(parents=True, exist_ok=True)

    # Resolve once so tcpdump's BPF filter uses a stable IP address.
    ip_addr = _resolve_ip(hostname, port)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    filename_parts = [_safe_filename_part(hostname)]
    if capture_label:
        filename_parts.append(_safe_filename_part(capture_label))
    filename_parts.append(timestamp)
    pcap_path = pcap_dir / f"{'_'.join(filename_parts)}.pcap"

    bpf_filter = f"host {ip_addr} and tcp port {port}"
    tcpdump_cmd = [
        "tcpdump",
        "-w", str(pcap_path),
        "--immediate-mode",   # flush packets without waiting for buffer
        "-i", "any",
        bpf_filter,
    ]

    log.debug("Starting tcpdump: %s", " ".join(tcpdump_cmd))
    tcpdump_proc = subprocess.Popen(
        tcpdump_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Give tcpdump a short moment to bind its socket before we open the
    # connection, otherwise the SYN may be missed.
    time.sleep(0.3)
    
    # Check if tcpdump is still running (it exits immediately on permission errors)
    poll_result = tcpdump_proc.poll()
    if poll_result is not None:
        # tcpdump has already exited - collect its error output
        _, stderr = tcpdump_proc.communicate()
        raise RuntimeError(
            f"tcpdump failed to start (exit code {poll_result}): {stderr.strip()}\n"
            f"On macOS/Linux, tcpdump requires elevated privileges. "
            f"Run with sudo or grant CAP_NET_RAW capability."
        )

    tls_error: Exception | None = None
    try:
        if scan_client == "python":
            _perform_python_tls_handshake(
                ip_addr=ip_addr,
                hostname=hostname,
                port=port,
                timeout_s=timeout_s,
            )
        elif scan_client == "openssl":
            _perform_openssl_tls_handshake(
                ip_addr=ip_addr,
                hostname=hostname,
                port=port,
                timeout_s=timeout_s,
                openssl_groups=openssl_groups,
            )
        else:
            raise ValueError(
                f"Unsupported scan client '{scan_client}'. "
                "Expected one of: python, openssl."
            )
    except Exception as exc:
        tls_error = exc
        log.warning("TLS error for %s:%d — %s", hostname, port, exc)
    finally:
        # Allow tcpdump to flush any remaining packets.
        time.sleep(_TCPDUMP_FLUSH_DELAY_S)
        try:
            tcpdump_proc.send_signal(signal.SIGTERM)
            tcpdump_proc.wait(timeout=_TCPDUMP_TERMINATE_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            log.warning("tcpdump did not exit cleanly; sending SIGKILL")
            tcpdump_proc.kill()
            tcpdump_proc.wait()

    if tls_error is not None:
        raise tls_error

    log.info("Captured %s:%d → %s", hostname, port, pcap_path)
    return pcap_path
