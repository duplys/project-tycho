"""Scan orchestration — the core scan loop and APScheduler integration.

A single ``scan_target`` function handles one host from start to finish:
DNS resolution → pcap capture → Tool 1 analysis → file write.  The
``run_scan_round`` function iterates over all active targets using a thread
pool (bounded by ``settings.max_concurrent_scans``) with a per-host rate
limit.

``start_scheduler`` registers a weekly APScheduler job and blocks until the
process receives SIGINT / SIGTERM.
"""

from __future__ import annotations

import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo

from apscheduler.schedulers.blocking import BlockingScheduler

from observatory.analyzer import run_analyzer
from observatory.config import settings
from observatory.database import (
    apply_schema,
    get_active_targets,
    insert_scan,
    update_scanner_capabilities,
    upsert_target,
)
from observatory.models import HandshakeData, ScanResult, Target
from observatory.scanner import capture_tls_handshake, discover_openssl_capabilities
from observatory.targets import load_targets

log = logging.getLogger(__name__)


def scan_target(
    hostname: str,
    port: int = 443,
    *,
    scan_client: Literal["python", "openssl"] = "python",
    openssl_groups: str | None = None,
    probe_group: str | None = None,
    scan_round_id: str | None = None,
    diagnostics: bool = False,
) -> ScanResult:
    """Run a full capture + analysis cycle for one host.

    All errors are caught and recorded in the returned :class:`ScanResult` so
    that the overall scan round is not interrupted by a single failing host.
    """
    started = time.monotonic()
    scanned_at = datetime.now(timezone.utc)
    scan_round_id = scan_round_id or uuid.uuid4().hex
    pcap_path: Path | None = None
    analyzer_output = None
    handshake: HandshakeData | None = None
    error: str | None = None

    try:
        pcap_path = capture_tls_handshake(
            hostname,
            port=port,
            scan_client=scan_client,
            openssl_groups=openssl_groups,
            capture_label=probe_group,
        )
    except Exception as exc:
        error = f"capture failed: {exc}"
        log.warning("Capture failed for %s:%d — %s", hostname, port, exc)
        return ScanResult(
            target_hostname=hostname,
            target_port=port,
            scanned_at=scanned_at,
            scan_round_id=scan_round_id,
            probe_group=probe_group,
            error=error,
            scan_duration_ms=int((time.monotonic() - started) * 1000),
        )

    # Tool 1 integration — gracefully skip if analyzer is not installed yet.
    try:
        analyzer_output = run_analyzer(pcap_path)
        if analyzer_output is not None:
            handshake = HandshakeData.from_analyzer_output(analyzer_output)
        if diagnostics and analyzer_output is not None:
            client_hello = analyzer_output.get("client_hello") or {}
            offered_groups = client_hello.get("supported_groups") or []
            key_shares = [
                entry.get("group_name", f"0x{entry.get('group_id', 0):04X}")
                for entry in (client_hello.get("key_shares") or [])
                if isinstance(entry, dict)
            ]
            log.info(
                "Diagnostics %s:%d — supported_groups=%s key_shares=%s",
                hostname,
                port,
                offered_groups,
                key_shares,
            )
    except Exception as exc:
        log.warning("Analysis failed for %s — %s", pcap_path, exc)
        # Non-fatal: we still store the pcap path.

    return ScanResult(
        target_hostname=hostname,
        target_port=port,
        scanned_at=scanned_at,
        scan_round_id=scan_round_id,
        probe_group=probe_group,
        pcap_path=str(pcap_path),
        analyzer_output=analyzer_output,
        handshake=handshake,
        error=error,
        scan_duration_ms=int((time.monotonic() - started) * 1000),
    )


def scan_target_groups(
    target: Target,
    groups: list[str],
    *,
    scan_round_id: str,
    scan_client: Literal["python", "openssl"],
    diagnostics: bool = False,
) -> list[ScanResult]:
    """Probe one target's groups sequentially with a gap between attempts."""
    results: list[ScanResult] = []
    for index, group in enumerate(groups):
        results.append(
            scan_target(
                target.hostname,
                target.port,
                scan_client=scan_client,
                openssl_groups=group,
                probe_group=group,
                scan_round_id=scan_round_id,
                diagnostics=diagnostics,
            )
        )
        if index < len(groups) - 1:
            time.sleep(settings.rate_limit_delay_s)
    return results


def run_scan_round(
    targets: list[Target] | None = None,
    *,
    scan_client: Literal["python", "openssl"] | None = None,
    openssl_groups: str | None = None,
    probe_groups: list[str] | tuple[str, ...] | None = None,
    scan_round_id: str | None = None,
    diagnostics: bool = False,
) -> None:
    """Scan all active targets and persist results.

    Parameters
    ----------
    targets:
        Override list of targets.  When ``None`` the active set is read from
        the data file (populated from the configured YAML file at startup).
    """
    log.info("=== Scan round starting ===")
    round_start = time.monotonic()
    scan_round_id = scan_round_id or uuid.uuid4().hex
    scan_client = scan_client or settings.scan_client
    if openssl_groups is not None:
        groups_to_probe = [openssl_groups]
    else:
        groups_to_probe = list(probe_groups or settings.pqc_probe_groups)
    if groups_to_probe and scan_client != "openssl":
        raise ValueError("Targeted PQC/hybrid probes require scan_client='openssl'.")

    if scan_client == "openssl":
        capabilities = discover_openssl_capabilities()
        implemented = {group.casefold() for group in capabilities.implemented_groups}
        configured_groups = groups_to_probe
        groups_to_probe = [
            group for group in configured_groups if group.casefold() in implemented
        ]
        unsupported_groups = [
            group for group in configured_groups if group.casefold() not in implemented
        ]
        update_scanner_capabilities(
            checked_at=datetime.now(timezone.utc),
            client_version=capabilities.version,
            configured_groups=configured_groups,
            supported_groups=groups_to_probe,
            unsupported_groups=unsupported_groups,
        )
        if unsupported_groups:
            log.warning(
                "Skipping TLS groups unsupported by the local OpenSSL client: %s",
                ", ".join(unsupported_groups),
            )

    if targets is None:
        stored_targets = get_active_targets()
        targets = [
            Target(hostname=r["hostname"], port=r["port"], category=r["category"])
            for r in stored_targets
        ]

    log.info(
        "Scanning %d targets across %d PQC/hybrid groups (max %d concurrent).",
        len(targets),
        len(groups_to_probe),
        settings.max_concurrent_scans,
    )

    with ThreadPoolExecutor(max_workers=settings.max_concurrent_scans) as pool:
        futures = {}
        for t in targets:
            futures[
                pool.submit(
                    scan_target_groups,
                    t,
                    groups_to_probe,
                    scan_round_id=scan_round_id,
                    scan_client=scan_client,
                    diagnostics=diagnostics,
                )
            ] = t

        for future in as_completed(futures):
            target = futures[future]
            try:
                results = future.result()
            except Exception as exc:
                log.error("Unexpected error scanning %s: %s", target.hostname, exc)
                continue

            for result in results:
                try:
                    target_id = upsert_target(target)
                    scan_id = insert_scan(target_id, result)
                    log.info(
                        "Stored scan #%d for %s (round=%s, group=%s, pqc=%s, error=%s)",
                        scan_id,
                        target.hostname,
                        scan_round_id,
                        result.probe_group,
                        result.handshake.is_pqc if result.handshake else "n/a",
                        result.error,
                    )
                except Exception as exc:
                    log.error("Data file write failed for %s: %s", target.hostname, exc)

    elapsed = time.monotonic() - round_start
    log.info("=== Scan round complete in %.1fs ===", elapsed)


def sync_targets_to_store() -> None:
    """Load the YAML target list and reconcile it with the observatory data file."""
    targets = load_targets(settings.targets_file)
    desired_targets = {(t.hostname, t.port) for t in targets}
    deactivated = 0

    apply_schema()
    for t in targets:
        upsert_target(t)

    for existing in get_active_targets():
        if (existing["hostname"], existing["port"]) not in desired_targets:
            upsert_target(
                Target(
                    hostname=existing["hostname"],
                    port=existing["port"],
                    category=existing["category"],
                    is_active=False,
                    notes=existing["notes"],
                )
            )
            deactivated += 1

    log.info(
        "Synced %d targets to the observatory data file; deactivated %d removed targets.",
        len(targets),
        deactivated,
    )


def start_scheduler() -> None:
    """Initialise the data file, sync targets, then schedule weekly scans.

    The scheduler blocks until interrupted.  It intentionally does not run an
    immediate startup scan; scans happen only at the configured cron time.
    """
    log.info("Initialising observatory …")
    sync_targets_to_store()

    schedule_timezone = ZoneInfo(settings.scan_schedule_timezone)
    scheduler = BlockingScheduler(timezone=schedule_timezone)
    scheduler.add_job(
        run_scan_round,
        trigger="cron",
        day_of_week=settings.scan_schedule_day_of_week,
        hour=settings.scan_schedule_hour,
        minute=settings.scan_schedule_minute,
        timezone=schedule_timezone,
        id="weekly_scan",
        name="Weekly PQC Observatory scan",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,  # allow up to 1 h if the process was down
    )

    log.info(
        "Scheduler configured: weekly scan on %s at %02d:%02d %s.",
        settings.scan_schedule_day_of_week,
        settings.scan_schedule_hour,
        settings.scan_schedule_minute,
        settings.scan_schedule_timezone,
    )
    log.info("Entering scheduler loop (Ctrl-C to stop) …")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("Observatory stopped.")
