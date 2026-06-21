"""Target list management — load, validate, and iterate over scan targets."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from observatory.models import Target

log = logging.getLogger(__name__)


def load_targets(targets_file: Path) -> list[Target]:
    """Load and validate targets from a YAML file.

    The YAML file is expected to contain a top-level ``targets`` list.  Each
    entry must at minimum have a ``hostname`` key.  All other fields are
    optional and match :class:`~observatory.models.Target`.

    Returns only entries with ``is_active: true`` (the default).
    """
    if not targets_file.exists():
        raise FileNotFoundError(
            f"Targets file not found: {targets_file}. "
            "Copy targets/default_targets.yaml or set OBSERVATORY_TARGETS_FILE."
        )

    with targets_file.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict) or "targets" not in raw:
        raise ValueError(
            f"Invalid targets file {targets_file}: expected a top-level 'targets' key."
        )

    targets: list[Target] = []
    for entry in raw["targets"]:
        try:
            target = Target(**entry)
        except Exception as exc:
            log.warning("Skipping malformed target entry %r: %s", entry, exc)
            continue
        if target.is_active:
            targets.append(target)

    log.info("Loaded %d active targets from %s", len(targets), targets_file)
    return targets
