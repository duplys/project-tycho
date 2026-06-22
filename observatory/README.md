# Observatory: PQC Observatory

The **PQC Observatory** is the Observatory component of [Project Tycho](../README.md).  It
is a long-running measurement service that periodically scans a curated list of
websites, records their TLS handshakes as pcap files, invokes the PCAP Analyser
to extract structured data, and stores time-series results in a
machine-readable JSON file for the adoption dashboard (Visualiser).

---

## Architecture

```
Target sites (the web)
        │ TLS handshake
        ▼
┌─────────────────────────────┐
│  OBSERVATORY (this tool)    │
│  scheduler · scanner ·      │
│  target list manager        │
└──────┬──────────────┬───────┘
       │ writes pcap  │ triggers
       ▼              ▼
 ┌──────────┐   ┌─────────────┐
 │ pcap     │──▶│  PCAP Analyser  │
 │ store    │   │  (analyzer)     │
 └──────────┘   └──────┬──────┘
                       │ JSON
                       ▼
                ┌─────────────┐
                │ JSON data   │
                │ file        │
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │  Visualiser │
                │  dashboard  │
                └─────────────┘
```

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.11+ | Managed with [uv](https://github.com/astral-sh/uv) |
| `tcpdump` | Must be on PATH; process needs `CAP_NET_RAW` or root |
| PCAP Analyser (`pcap-analyzer`) | Optional at runtime — pcap files are always stored for retrospective analysis |

---

## Quick Start (Docker Compose)

```bash
# 1. Clone the repository and enter the tool directory.
cd observatory

# 2. (Optional) Create a .env file to override defaults.
cat > .env <<EOF
OBSERVATORY_STORAGE_FILE=/var/pqc-obs/data/observatory-data.json
OBSERVATORY_SCAN_SCHEDULE_DAY_OF_WEEK=sun
OBSERVATORY_SCAN_SCHEDULE_HOUR=8
OBSERVATORY_SCAN_SCHEDULE_MINUTE=0
OBSERVATORY_SCAN_SCHEDULE_TIMEZONE=Europe/Berlin
OBSERVATORY_SCAN_CLIENT=openssl
OBSERVATORY_PQC_PROBE_GROUPS=X25519MLKEM768
EOF

# 3. Build and start.
docker compose up -d

# 4. Check logs.
docker compose logs -f observatory
```

The scanner runs one `X25519MLKEM768` TLS probe per target each week. The
default is Sunday 08:00 Europe/Berlin, and the named timezone keeps the scan at
local 08:00 across summer/winter daylight saving time changes. The container is granted
`CAP_NET_RAW` capability, which allows `tcpdump` to capture packets without
running as root.

---

## Local Development

```bash
# Install dependencies with uv.
uv sync --group dev

# Create the JSON data file and sync the target list.
observatory init

# Sync the target list into the data file.
observatory targets --sync

# Run a one-shot scan of a single host.
# NOTE: Requires sudo on macOS/Linux for tcpdump to capture packets.
# (Docker containers don't need sudo - they use CAP_NET_RAW instead.)
sudo uv run observatory scan cloudflare.com

# Run a one-shot scan with OpenSSL and explicit named groups.
# This can advertise hybrid groups when supported by the local OpenSSL build.
sudo uv run observatory scan cloudflare.com --client openssl \
  --openssl-groups X25519MLKEM768:SecP256r1MLKEM768 --diagnostics

# Run a full scan round across all active targets.
sudo observatory scan

# Print a summary adoption report.
observatory report

# Start the scheduler (blocks until Ctrl-C).
sudo observatory start
```

---

## Configuration

All settings can be overridden via environment variables (prefix
`OBSERVATORY_`) or an `.env` file in the working directory.

| Variable | Default | Description |
|---|---|---|
| `OBSERVATORY_PCAP_DIR` | `/var/pqc-obs/captures` | Directory for pcap files |
| `OBSERVATORY_STORAGE_FILE` | `/var/pqc-obs/data/observatory-data.json` | JSON file containing targets and scan history |
| `OBSERVATORY_SCAN_TIMEOUT_S` | `15` | Per-host TLS timeout (seconds) |
| `OBSERVATORY_RATE_LIMIT_DELAY_S` | `1.0` | Minimum gap between consecutive scans |
| `OBSERVATORY_MAX_CONCURRENT_SCANS` | `5` | Thread pool size |
| `OBSERVATORY_SCAN_CLIENT` | `openssl` | TLS client used for the scheduled probe |
| `OBSERVATORY_PQC_PROBE_GROUPS` | `X25519MLKEM768` | Comma-separated groups; each additional group adds another TLS scan per target |
| `OBSERVATORY_SCAN_SCHEDULE_DAY_OF_WEEK` | `sun` | Day of week for the weekly scan |
| `OBSERVATORY_SCAN_SCHEDULE_HOUR` | `8` | Hour in the configured timezone |
| `OBSERVATORY_SCAN_SCHEDULE_MINUTE` | `0` | Minute in the configured timezone |
| `OBSERVATORY_SCAN_SCHEDULE_TIMEZONE` | `Europe/Berlin` | IANA timezone for the schedule |
| `OBSERVATORY_TARGETS_FILE` | `targets/default_targets.yaml` | Path to target list |

---

## Target List

Targets are maintained in `targets/default_targets.yaml`.  The default list
covers:

- Major CDNs (Cloudflare, Fastly, Akamai)
- Hyperscalers (AWS, Azure, GCP)
- Technology-forward early adopters (Google, GitHub, Mozilla, …)
- Standards bodies and government agencies (NIST, CISA, NCSC, BSI)
- Financial institutions (Visa, Mastercard, JPMorgan, HSBC)
- Educational institutions (MIT, Stanford, Harvard, Cambridge)

To add a host, append an entry to the YAML file and run
`observatory targets --sync` (or restart the container).

---

## Data File Format

The observatory stores its state in a single JSON file with top-level keys:

- `version` — file format version
- `next_target_id` / `next_scan_id` — monotonically increasing numeric IDs
- `targets` — configured targets plus metadata such as category and activation
- `scans` — append-only scan history with analyzer output and indexed summary fields

This keeps the stored results machine-readable and easy to back up, inspect, or
mount into the Visualiser without running a database server.

---

## Scan Politeness

The observatory is designed to be a good citizen:

- **Rate limiting** — a configurable minimum delay (`OBSERVATORY_RATE_LIMIT_DELAY_S`)
  between consecutive scans.
- **Identified User-Agent** — the HTTP request used to complete the handshake
  includes a descriptive `User-Agent` header with a project URL.
- **Read-only** — only the public TLS negotiation is observed; no application
  data is stored.
- **Targeted** — only a curated list of hosts is scanned, not arbitrary
  internet ranges.

---

## Integration with PCAP Analyser

When `pcap-analyzer` is installed and on PATH, the observatory
automatically invokes it on each freshly captured pcap and stores its JSON
output alongside the scan record.  If the PCAP Analyser is not yet available the pcap
files are still written to disk and can be analysed retrospectively once it
is installed.

---

## License

MIT — see [LICENSE](../LICENSE).
