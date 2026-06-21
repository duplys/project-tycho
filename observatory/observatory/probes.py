"""PQC and hybrid TLS named groups used for targeted Observatory probes."""

from __future__ import annotations

DEFAULT_PQC_PROBE_GROUPS: tuple[str, ...] = (
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",
    "SecP256r1MLKEM768",
    "X25519MLKEM768",
    "SecP384r1MLKEM1024",
)

