from datetime import UTC, datetime
from threading import Barrier, Lock, get_ident
from zoneinfo import ZoneInfo

import pytest

from observatory import scheduler as scheduler_module
from observatory.config import Settings, settings
from observatory.models import ScanResult, Target
from observatory.probes import DEFAULT_PQC_PROBE_GROUPS
from observatory.scanner import OpenSSLCapabilities


# OpenSSL 3.5+ treats group names case-insensitively; use lower-case output here
# to ensure configured IANA spelling is matched without relying on exact casing.
CURRENT_OPENSSL_GROUPS = frozenset(group.lower() for group in DEFAULT_PQC_PROBE_GROUPS[:-2])


@pytest.fixture(autouse=True)
def mock_openssl_capability_query(monkeypatch):
    monkeypatch.setattr(
        scheduler_module,
        "discover_openssl_capabilities",
        lambda: OpenSSLCapabilities(
            version="OpenSSL 4.0.1 9 Jun 2026",
            implemented_groups=CURRENT_OPENSSL_GROUPS,
        ),
    )


def test_settings_load_weekly_schedule_env(monkeypatch):
    monkeypatch.setenv("OBSERVATORY_SCAN_SCHEDULE_DAY_OF_WEEK", "sun")
    monkeypatch.setenv("OBSERVATORY_SCAN_SCHEDULE_HOUR", "8")
    monkeypatch.setenv("OBSERVATORY_SCAN_SCHEDULE_MINUTE", "0")
    monkeypatch.setenv("OBSERVATORY_SCAN_SCHEDULE_TIMEZONE", "Europe/Berlin")

    loaded = Settings(_env_file=None)

    assert loaded.scan_schedule_day_of_week == "sun"
    assert loaded.scan_schedule_hour == 8
    assert loaded.scan_schedule_minute == 0
    assert loaded.scan_schedule_timezone == "Europe/Berlin"


def test_settings_load_probe_groups_env(monkeypatch):
    monkeypatch.setenv("OBSERVATORY_PQC_PROBE_GROUPS", "MLKEM768,X25519MLKEM768")

    loaded = Settings(_env_file=None)

    assert loaded.pqc_probe_groups == ["MLKEM768", "X25519MLKEM768"]


def test_settings_default_to_thirty_second_probe_gap():
    loaded = Settings(_env_file=None)

    assert loaded.rate_limit_delay_s == 30.0


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("OBSERVATORY_SCAN_SCHEDULE_HOUR", "24"),
        ("OBSERVATORY_SCAN_SCHEDULE_MINUTE", "60"),
        ("OBSERVATORY_SCAN_SCHEDULE_TIMEZONE", "Not/AZone"),
        ("OBSERVATORY_RATE_LIMIT_DELAY_S", "-1"),
    ],
)
def test_settings_reject_invalid_schedule_values(monkeypatch, name, value):
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError):
        Settings(_env_file=None)


def test_start_scheduler_registers_weekly_berlin_job_without_startup_scan(
    monkeypatch,
):
    add_job_calls = []

    class FakeBlockingScheduler:
        def __init__(self, *, timezone):
            self.timezone = timezone

        def add_job(self, *args, **kwargs):
            add_job_calls.append((self.timezone, args, kwargs))

        def start(self):
            raise KeyboardInterrupt

    def fail_startup_scan(*args, **kwargs):
        raise AssertionError("start_scheduler must not run an immediate scan")

    monkeypatch.setattr(scheduler_module, "BlockingScheduler", FakeBlockingScheduler)
    monkeypatch.setattr(scheduler_module, "sync_targets_to_store", lambda: None)
    monkeypatch.setattr(scheduler_module, "run_scan_round", fail_startup_scan)
    monkeypatch.setattr(settings, "scan_schedule_day_of_week", "sun")
    monkeypatch.setattr(settings, "scan_schedule_hour", 8)
    monkeypatch.setattr(settings, "scan_schedule_minute", 0)
    monkeypatch.setattr(settings, "scan_schedule_timezone", "Europe/Berlin")

    scheduler_module.start_scheduler()

    assert len(add_job_calls) == 1
    scheduler_timezone, args, kwargs = add_job_calls[0]
    assert scheduler_timezone == ZoneInfo("Europe/Berlin")
    assert args == (fail_startup_scan,)
    assert kwargs["trigger"] == "cron"
    assert kwargs["day_of_week"] == "sun"
    assert kwargs["hour"] == 8
    assert kwargs["minute"] == 0
    assert kwargs["timezone"] == ZoneInfo("Europe/Berlin")
    assert kwargs["id"] == "weekly_scan"
    assert kwargs["max_instances"] == 1
    assert kwargs["coalesce"] is True


def test_run_scan_round_probes_each_pqc_group_once_per_target(monkeypatch):
    calls = []
    capability_updates = []
    sleep_calls = []

    monkeypatch.setattr(settings, "scan_client", "openssl")
    monkeypatch.setattr(settings, "pqc_probe_groups", list(DEFAULT_PQC_PROBE_GROUPS))
    monkeypatch.setattr(settings, "max_concurrent_scans", 1)
    monkeypatch.setattr(settings, "rate_limit_delay_s", 30)
    monkeypatch.setattr(scheduler_module.time, "sleep", sleep_calls.append)
    monkeypatch.setattr(scheduler_module, "upsert_target", lambda target: 1)
    monkeypatch.setattr(scheduler_module, "insert_scan", lambda target_id, result: 1)
    monkeypatch.setattr(
        scheduler_module,
        "update_scanner_capabilities",
        lambda **kwargs: capability_updates.append(kwargs),
    )

    def fake_scan_target(
        hostname,
        port=443,
        *,
        scan_client="python",
        openssl_groups=None,
        probe_group=None,
        scan_round_id=None,
        diagnostics=False,
    ):
        calls.append(
            {
                "hostname": hostname,
                "port": port,
                "scan_client": scan_client,
                "openssl_groups": openssl_groups,
                "probe_group": probe_group,
                "scan_round_id": scan_round_id,
                "diagnostics": diagnostics,
            }
        )
        return ScanResult(
            target_hostname=hostname,
            target_port=port,
            probe_group=probe_group,
            scan_round_id=scan_round_id,
            scanned_at=datetime(2026, 6, 17, tzinfo=UTC),
        )

    monkeypatch.setattr(scheduler_module, "scan_target", fake_scan_target)

    scheduler_module.run_scan_round(targets=[Target(hostname="cloudflare.com")])

    assert DEFAULT_PQC_PROBE_GROUPS == (
        "MLKEM512",
        "MLKEM768",
        "MLKEM1024",
        "SecP256r1MLKEM768",
        "X25519MLKEM768",
        "SecP384r1MLKEM1024",
        "curveSM2MLKEM768",
        "X25519Kyber768Draft00",
        "SecP256r1Kyber768Draft00",
    )
    supported_groups = list(DEFAULT_PQC_PROBE_GROUPS[:-2])
    assert len(calls) == 7
    assert [call["openssl_groups"] for call in calls] == supported_groups
    assert [call["probe_group"] for call in calls] == supported_groups
    assert {call["scan_client"] for call in calls} == {"openssl"}
    assert len({call["scan_round_id"] for call in calls}) == 1
    assert sleep_calls == [30] * 6
    assert capability_updates[0]["configured_groups"] == list(DEFAULT_PQC_PROBE_GROUPS)
    assert capability_updates[0]["supported_groups"] == supported_groups
    assert capability_updates[0]["unsupported_groups"] == [
        "X25519Kyber768Draft00",
        "SecP256r1Kyber768Draft00",
    ]


def test_run_scan_round_uses_single_explicit_group(monkeypatch):
    calls = []

    monkeypatch.setattr(settings, "scan_client", "openssl")
    monkeypatch.setattr(settings, "max_concurrent_scans", 1)
    monkeypatch.setattr(settings, "rate_limit_delay_s", 0)
    monkeypatch.setattr(scheduler_module, "upsert_target", lambda target: 1)
    monkeypatch.setattr(scheduler_module, "insert_scan", lambda target_id, result: 1)
    monkeypatch.setattr(scheduler_module, "update_scanner_capabilities", lambda **kwargs: None)

    def fake_scan_target(
        hostname,
        port=443,
        *,
        scan_client="python",
        openssl_groups=None,
        probe_group=None,
        scan_round_id=None,
        diagnostics=False,
    ):
        calls.append((hostname, port, scan_client, openssl_groups, probe_group))
        return ScanResult(
            target_hostname=hostname,
            target_port=port,
            probe_group=probe_group,
            scanned_at=datetime(2026, 6, 17, tzinfo=UTC),
        )

    monkeypatch.setattr(scheduler_module, "scan_target", fake_scan_target)

    scheduler_module.run_scan_round(
        targets=[Target(hostname="cloudflare.com")],
        openssl_groups="X25519MLKEM768",
    )

    assert calls == [
        (
            "cloudflare.com",
            443,
            "openssl",
            "X25519MLKEM768",
            "X25519MLKEM768",
        )
    ]


def test_run_scan_round_rejects_non_openssl_targeted_probe(monkeypatch):
    monkeypatch.setattr(settings, "scan_client", "python")

    with pytest.raises(ValueError, match="require scan_client='openssl'"):
        scheduler_module.run_scan_round(targets=[Target(hostname="cloudflare.com")])


def test_run_scan_round_fails_before_target_work_when_openssl_query_fails(monkeypatch):
    monkeypatch.setattr(settings, "scan_client", "openssl")
    monkeypatch.setattr(
        scheduler_module,
        "discover_openssl_capabilities",
        lambda: (_ for _ in ()).throw(RuntimeError("OpenSSL capability query failed")),
    )
    monkeypatch.setattr(
        scheduler_module,
        "scan_target",
        lambda *args, **kwargs: pytest.fail("target work must not start"),
    )

    with pytest.raises(RuntimeError, match="capability query failed"):
        scheduler_module.run_scan_round(targets=[Target(hostname="cloudflare.com")])


def test_scan_target_groups_continues_after_failed_probe(monkeypatch):
    calls = []
    sleeps = []
    monkeypatch.setattr(settings, "rate_limit_delay_s", 30)
    monkeypatch.setattr(scheduler_module.time, "sleep", sleeps.append)

    def fake_scan_target(hostname, port=443, **kwargs):
        calls.append(kwargs["probe_group"])
        return ScanResult(
            target_hostname=hostname,
            target_port=port,
            scanned_at=datetime(2026, 6, 21, tzinfo=UTC),
            scan_round_id=kwargs["scan_round_id"],
            probe_group=kwargs["probe_group"],
            error="failed" if kwargs["probe_group"] == "MLKEM768" else None,
        )

    monkeypatch.setattr(scheduler_module, "scan_target", fake_scan_target)
    results = scheduler_module.scan_target_groups(
        Target(hostname="example.com"),
        ["MLKEM512", "MLKEM768", "MLKEM1024"],
        scan_round_id="round-id",
        scan_client="openssl",
    )

    assert calls == ["MLKEM512", "MLKEM768", "MLKEM1024"]
    assert sleeps == [30, 30]
    assert results[1].error == "failed"


def test_run_scan_round_allows_five_targets_concurrently(monkeypatch):
    barrier = Barrier(5, timeout=2)
    thread_ids = set()
    lock = Lock()
    monkeypatch.setattr(settings, "scan_client", "openssl")
    monkeypatch.setattr(settings, "max_concurrent_scans", 5)
    monkeypatch.setattr(settings, "pqc_probe_groups", ["X25519MLKEM768"])
    monkeypatch.setattr(scheduler_module, "update_scanner_capabilities", lambda **kwargs: None)

    def fake_target_groups(*args, **kwargs):
        with lock:
            thread_ids.add(get_ident())
        barrier.wait()
        return []

    monkeypatch.setattr(scheduler_module, "scan_target_groups", fake_target_groups)
    scheduler_module.run_scan_round(
        targets=[Target(hostname=f"host-{index}.example") for index in range(5)]
    )

    assert len(thread_ids) == 5
