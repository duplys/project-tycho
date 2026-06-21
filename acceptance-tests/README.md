# Acceptance Tests

End-to-end acceptance tests for the Project Tycho system that validate the
**PCAP TLS Parser**, **Observatory**, and **Visualiser** work together correctly.

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- [uv](https://github.com/astral-sh/uv) installed (`curl -LsSf https://astral.sh/uv/install.sh | sh`)

## Running the Tests

```bash
cd acceptance-tests
./run.sh
```

The script will:

1. Build the Visualiser Docker image
2. Start the Visualiser container with pre-seeded Observatory data
3. Wait for the service to become healthy
4. Install test dependencies via `uv sync`
5. Run `pytest test_acceptance.py -v`
6. Tear the container down (even on failure)

## What Is Tested

### PCAP Analyser → Visualiser pipeline

| Test | What it checks |
|------|---------------|
| `test_post_hybrid_handshake_is_pqc` | PCAP Analyser parses a synthetic hybrid (X25519MLKEM768) PCAP and correctly flags `is_pqc=True`, `is_hybrid=True` |
| `test_post_classical_handshake_is_not_pqc` | PCAP Analyser parses a classical (x25519) PCAP and correctly flags `is_pqc=False` |
| `test_get_stored_handshake` | A POSTed handshake record is retrievable by ID |
| `test_list_handshakes_includes_stored` | The list endpoint includes the stored record |
| `test_tikz_handshake_flow_export` | The TikZ handshake-flow export is valid LaTeX/TikZ |
| `test_tikz_key_share_comparison_export` | The TikZ key-share-comparison export contains the PQC group name |
| `test_delete_removes_handshake` | A deleted record returns HTTP 404 on subsequent GET |

### Observatory → Visualiser integration

The pre-seeded `data/observatory-data.json` contains two targets
(cloudflare.com, example.com) and three historical scans.

| Test | What it checks |
|------|---------------|
| `test_status_returns_two_active_targets` | `/api/observatory/status` returns one row per active target |
| `test_cloudflare_latest_scan_is_pqc` | cloudflare.com latest scan shows PQC / X25519MLKEM768 |
| `test_example_latest_scan_is_not_pqc` | example.com latest scan shows classical / x25519 |
| `test_adoption_trend_two_days` | `/api/observatory/adoption` computes 50 % on 2026-05-21 and 100 % on 2026-05-22 |
| `test_algorithm_popularity_x25519mlkem768_first` | `/api/observatory/algorithms` ranks X25519MLKEM768 first (2 counts) |
| `test_adoption_since_filter` | `?since=2026-05-22` returns only the second day |
| `test_algorithms_since_filter` | `?since=2026-05-22` returns only the second day's scans |
| `test_adoption_invalid_since_returns_400` | Malformed `since=` value returns HTTP 400 |

## Running Tests Manually

Start the Visualiser first (from within this directory):

```bash
docker compose up -d --build
```

Run the tests, overriding the default URL if needed:

```bash
VISUALISER_URL=http://localhost:8765 uv run pytest test_acceptance.py -v
```

Tear down when done:

```bash
docker compose down
```

## Service Ports

| Service | Host port | Container port |
|---------|-----------|----------------|
| Visualiser | **8765** | 8000 |

If port 8765 is already in use, edit `docker-compose.yml` and set `VISUALISER_URL`
accordingly before running the tests.
