"""CLI entry point for the PQC Observatory (Tool 3)."""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone

import click

from observatory.config import settings
from observatory.database import (
    apply_schema,
    get_latest_scan_per_target,
    get_pqc_adoption_over_time,
    get_algorithm_popularity,
)
from observatory.models import Target
from observatory.scheduler import (
    run_scan_round,
    scan_target,
    start_scheduler,
    sync_targets_to_store,
)
from observatory.targets import load_targets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stderr,
)
log = logging.getLogger("observatory")


def _print_scan_diagnostics(result_json: dict) -> None:
    """Print offered supported_groups/key_shares from analyzer output."""
    client_hello = (result_json.get("analyzer_output") or {}).get("client_hello") or {}
    offered_groups = client_hello.get("supported_groups") or []
    key_shares = [
        entry.get("group_name", f"0x{entry.get('group_id', 0):04X}")
        for entry in (client_hello.get("key_shares") or [])
        if isinstance(entry, dict)
    ]

    click.echo("diagnostics:")
    click.echo(
        "  offered supported_groups: "
        + (", ".join(str(g) for g in offered_groups) if offered_groups else "(none)")
    )
    click.echo(
        "  offered key_shares: "
        + (", ".join(str(k) for k in key_shares) if key_shares else "(none)")
    )


@click.group()
def cli() -> None:
    """PQC Observatory — TLS handshake scanner and adoption tracker."""


# --------------------------------------------------------------------------- #
# observatory init                                                             #
# --------------------------------------------------------------------------- #

@cli.command("init")
def cmd_init() -> None:
    """Create the data file and sync the target list."""
    apply_schema()
    click.echo(f"Observatory data file ready: {settings.storage_file}")
    sync_targets_to_store()
    click.echo("Target list synced.")


# --------------------------------------------------------------------------- #
# observatory start                                                            #
# --------------------------------------------------------------------------- #

@cli.command("start")
def cmd_start() -> None:
    """Start the observatory scheduler (runs indefinitely)."""
    start_scheduler()


# --------------------------------------------------------------------------- #
# observatory scan                                                             #
# --------------------------------------------------------------------------- #

@cli.command("scan")
@click.argument("hostname", required=False)
@click.option("--port", default=443, show_default=True, help="TCP port.")
@click.option(
    "--client",
    "scan_client",
    type=click.Choice(["python", "openssl"], case_sensitive=False),
    default=settings.scan_client,
    show_default=True,
    help="TLS client backend used to generate the handshake.",
)
@click.option(
    "--openssl-groups",
    default=settings.openssl_groups,
    help=(
        "OpenSSL -groups value used when --client openssl "
        "(for explicit hybrid group advertisement)."
    ),
)
@click.option(
    "--diagnostics",
    is_flag=True,
    default=False,
    help="Print offered supported_groups and key_shares from ClientHello.",
)
def cmd_scan(
    hostname: str | None,
    port: int,
    scan_client: str,
    openssl_groups: str | None,
    diagnostics: bool,
) -> None:
    """Run a single scan round or scan one specific HOSTNAME."""
    if hostname:
        if openssl_groups:
            # One targeted probe; do not require the host to be in the data file.
            result = scan_target(
                hostname,
                port,
                scan_client=scan_client,
                openssl_groups=openssl_groups,
                probe_group=openssl_groups,
                diagnostics=diagnostics,
            )
            result_json = result.model_dump(mode="json")
            click.echo(result.model_dump_json(indent=2))
            if diagnostics:
                _print_scan_diagnostics(result_json)
        else:
            run_scan_round(
                targets=[Target(hostname=hostname, port=port)],
                scan_client=scan_client,
                diagnostics=diagnostics,
            )
            click.echo("Targeted probe round complete.")
    else:
        run_scan_round(
            scan_client=scan_client,
            openssl_groups=openssl_groups,
            diagnostics=diagnostics,
        )
        click.echo("Scan round complete.")


# --------------------------------------------------------------------------- #
# observatory targets                                                          #
# --------------------------------------------------------------------------- #

@cli.command("targets")
@click.option("--sync", is_flag=True, default=False, help="Sync YAML → data file.")
def cmd_targets(sync: bool) -> None:
    """List active targets, or --sync to reload them from the YAML file."""
    if sync:
        sync_targets_to_store()
        click.echo("Target list synced.")
        return

    targets = load_targets(settings.targets_file)
    click.echo(f"{'HOSTNAME':<45} {'PORT':>5}  {'CATEGORY':<20}  NOTES")
    click.echo("-" * 90)
    for t in targets:
        click.echo(f"{t.hostname:<45} {t.port:>5}  {t.category:<20}  {t.notes}")
    click.echo(f"\n{len(targets)} active targets.")


# --------------------------------------------------------------------------- #
# observatory status                                                           #
# --------------------------------------------------------------------------- #

@cli.command("status")
def cmd_status() -> None:
    """Show the most recent scan result for every active target."""
    rows = get_latest_scan_per_target()

    if not rows:
        click.echo("No scans recorded yet.")
        return

    click.echo(
        f"{'HOSTNAME':<40} {'SCANNED AT':<22} {'PQC':>4}  {'HYBRID':>6}  "
        f"{'GROUP':<30} ERROR"
    )
    click.echo("-" * 120)
    for r in rows:
        is_pqc_flag = (
            "Y" if r["is_pqc"] is True else ("?" if r["is_pqc"] is None else "N")
        )
        is_hybrid_flag = (
            "Y"
            if r["is_hybrid"] is True
            else ("?" if r["is_hybrid"] is None else "N")
        )
        click.echo(
            f"{r['hostname']:<40} "
            f"{str(r['scanned_at'])[:19]:<22} "
            f"{is_pqc_flag:>4}  "
            f"{is_hybrid_flag:>6}  "
            f"{(r['selected_group'] or '—'):<30} "
            f"{r['error'] or ''}"
        )


# --------------------------------------------------------------------------- #
# observatory report                                                           #
# --------------------------------------------------------------------------- #

@cli.command("report")
@click.option(
    "--since",
    default=None,
    metavar="YYYY-MM-DD",
    help="Only include data from this date onward.",
)
def cmd_report(since: str | None) -> None:
    """Print a summary adoption report to stdout."""
    since_dt: datetime | None = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
        except ValueError:
            click.echo(f"Invalid date format: {since}  (expected YYYY-MM-DD)", err=True)
            sys.exit(1)

    adoption = get_pqc_adoption_over_time(since=since_dt)
    algorithms = get_algorithm_popularity(since=since_dt)

    if not adoption:
        click.echo("No data available yet.")
        return

    click.echo("=== PQC Adoption Over Time ===")
    click.echo(f"{'DATE':<12} {'TOTAL':>6}  {'PQC':>6}  {'% PQC':>8}")
    click.echo("-" * 40)
    for row in adoption:
        click.echo(
            f"{row['date']:<12} {row['total']:>6}  "
            f"{row['pqc_count']:>6}  {row['pct_pqc']:>7.1f}%"
        )

    click.echo("\n=== Algorithm Popularity ===")
    click.echo(f"{'GROUP':<40} {'COUNT':>6}")
    click.echo("-" * 50)
    for row in algorithms:
        click.echo(f"{(row['selected_group'] or '—'):<40} {row['count']:>6}")


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    cli()
