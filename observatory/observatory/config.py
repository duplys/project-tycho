"""Configuration — loaded from environment variables (prefix: OBSERVATORY_)."""

from pathlib import Path
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from observatory.probes import DEFAULT_PQC_PROBE_GROUPS


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OBSERVATORY_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # ------------------------------------------------------------------ #
    # Storage                                                              #
    # ------------------------------------------------------------------ #
    pcap_dir: Path = Path("./pqc-obs/captures")
    storage_file: Path = Path("./pqc-obs/data/observatory-data.json")

    # ------------------------------------------------------------------ #
    # Scanning behaviour                                                   #
    # ------------------------------------------------------------------ #
    # Per-host TCP/TLS connection timeout (seconds).
    scan_timeout_s: int = 15
    # Minimum gap between consecutive scans of the *same* host (seconds).
    rate_limit_delay_s: float = 30.0
    # Maximum number of hosts scanned in parallel (thread pool size).
    max_concurrent_scans: int = 5
    # User-Agent sent in the HTTP GET used to complete the TLS handshake.
    scan_user_agent: str = (
        "PQC-Observatory/1.0 (https://github.com/duplys/project-tycho; research)"
    )
    # TLS client backend used by scanner: python stdlib ssl or openssl s_client.
    scan_client: Literal["python", "openssl"] = "openssl"
    # Optional openssl -groups value for explicit named-group advertisement.
    openssl_groups: str | None = None
    # Targeted PQC/hybrid OpenSSL groups probed for every active target.
    pqc_probe_groups: Annotated[list[str], NoDecode] = list(DEFAULT_PQC_PROBE_GROUPS)

    # ------------------------------------------------------------------ #
    # Scheduler                                                            #
    # ------------------------------------------------------------------ #
    # Day of week on which the weekly scan job fires.
    scan_schedule_day_of_week: str = "sun"
    # Hour of day at which the weekly scan job fires.
    scan_schedule_hour: int = 8
    # Minute of the hour at which the weekly scan job fires.
    scan_schedule_minute: int = 0
    # IANA timezone used for the weekly scan schedule.
    scan_schedule_timezone: str = "Europe/Berlin"

    # ------------------------------------------------------------------ #
    # Target list                                                          #
    # ------------------------------------------------------------------ #
    targets_file: Path = Path("targets/default_targets.yaml")

    # ------------------------------------------------------------------ #
    # Derived helpers                                                      #
    # ------------------------------------------------------------------ #
    @field_validator("pcap_dir", mode="before")
    @classmethod
    def _expand_pcap_dir(cls, v: str | Path) -> Path:
        return Path(v).expanduser()

    @field_validator("targets_file", mode="before")
    @classmethod
    def _expand_targets_file(cls, v: str | Path) -> Path:
        return Path(v).expanduser()

    @field_validator("storage_file", mode="before")
    @classmethod
    def _expand_storage_file(cls, v: str | Path) -> Path:
        return Path(v).expanduser()

    @field_validator("pqc_probe_groups", mode="before")
    @classmethod
    def _parse_pqc_probe_groups(cls, v: str | list[str] | tuple[str, ...]) -> list[str]:
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return list(v)

    @field_validator("rate_limit_delay_s")
    @classmethod
    def _validate_rate_limit_delay_s(cls, v: float) -> float:
        if v < 0:
            raise ValueError("rate_limit_delay_s must be non-negative")
        return v

    @field_validator("scan_schedule_hour")
    @classmethod
    def _validate_scan_schedule_hour(cls, v: int) -> int:
        if not 0 <= v <= 23:
            raise ValueError("scan_schedule_hour must be between 0 and 23")
        return v

    @field_validator("scan_schedule_minute")
    @classmethod
    def _validate_scan_schedule_minute(cls, v: int) -> int:
        if not 0 <= v <= 59:
            raise ValueError("scan_schedule_minute must be between 0 and 59")
        return v

    @field_validator("scan_schedule_timezone")
    @classmethod
    def _validate_scan_schedule_timezone(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"unknown IANA timezone: {v}") from exc
        return v


settings = Settings()
