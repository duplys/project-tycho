# TLS Visualiser

Interactive web visualization tool for TLS handshake data produced by the PCAP Analyser (tls-pcap-analyzer) of the PQC-TLS Observatory project. Generates interactive charts and PGF/TikZ LaTeX output for academic publications.

## Features

- **Upload / paste** PCAP Analyser JSON output directly in the browser
- **Handshake Flow diagram** — SVG sequence diagram (ClientHello → ServerHello, with continuation indicator) with PQC/hybrid color-coding
- **Cipher Suite table** — highlights negotiated suite and PQC groups
- **Key Share Size chart** — horizontal bar chart comparing key exchange lengths (classical / PQC / hybrid)
- **TikZ export** — download `.tex` files for direct inclusion in LaTeX/pdflatex documents
- **REST API** — FastAPI backend with auto-generated docs at `/docs`

## Requirements

- Python ≥ 3.10 with [uv](https://github.com/astral-sh/uv)
- Node.js ≥ 18 with npm (for frontend development)
- Docker + Docker Compose (optional, for production deployment)

## Installation

```bash
# Backend
cd visualiser
uv sync --extra dev

# Frontend (development only)
cd visualiser/frontend
npm install
```

## Development Usage

```bash
# Backend (from visualiser/)
uv run uvicorn tls_visualizer.app:app --reload --host 0.0.0.0 --port 8000

# Frontend (from visualiser/frontend/) in a separate terminal
npm run dev
```

The frontend Vite dev server (default port 5173) proxies `/api` requests to `http://localhost:8000`.

If you want the Visualiser to read Observatory history, point it at the shared
JSON file:

```bash
export TLS_VISUALIZER_OBSERVATORY_DATA_FILE=/var/pqc-obs/data/observatory-data.json
```

## Production Build

```bash
# Build frontend static assets
cd visualiser/frontend && npm run build

# Start backend (serves built frontend from frontend/dist/)
cd visualiser && uv run uvicorn tls_visualizer.app:app --host 0.0.0.0 --port 8000
```

The dashboard at `/` is served only when frontend build assets exist and include
`index.html` in the configured dist directory.

To override where the backend looks for dist assets, set:

```bash
export TLS_VISUALIZER_FRONTEND_DIST=/absolute/path/to/frontend/dist
```

Or with Docker Compose:

```bash
cd visualiser
docker compose --profile build run frontend-build   # builds frontend
docker compose up backend
```

```bash
docker compose --profile build run --rm frontend-build
docker compose up -d --build backend
curl -i http://127.0.0.1:8000/
```

For container deployments, the backend reads frontend assets from
`/app/frontend/dist` by default (also set explicitly in compose via
`TLS_VISUALIZER_FRONTEND_DIST=/app/frontend/dist`).

After rebuilding frontend assets, restart the backend container so startup can
mount static files again:

```bash
docker compose up -d --build backend
```

## Troubleshooting

### Symptom

The browser returns `{"detail":"Not Found"}` at `/` while `/health` and
`/docs` still work.

### Root Cause

The backend serves the dashboard only when it can find frontend build assets
(`index.html` + `assets/*`).

In Docker installs, Python imports from `site-packages` (for example
`/usr/local/lib/python3.12/site-packages/tls_visualizer/app.py`). The previous
code resolved `frontend/dist` relative to that import path, which produced a
non-existent location (`/usr/local/lib/python3.12/frontend/dist`) and skipped
the static mount for `/`.

### Fix Implemented

The backend now resolves frontend assets from deterministic candidates and mounts
`/` only when `index.html` exists:

1. `TLS_VISUALIZER_FRONTEND_DIST` (explicit override)
2. `/app/frontend/dist` (container runtime default)
3. Source and cwd fallbacks for local development

Compose also sets `TLS_VISUALIZER_FRONTEND_DIST=/app/frontend/dist` explicitly
for the backend service.

### How To Verify On VPS

```bash
cd /srv/project-tycho
docker compose --profile build run --rm visualiser-frontend
docker compose up -d --build --force-recreate visualiser
docker compose exec visualiser sh -lc "ls -lah /app/frontend/dist && find /app/frontend/dist -maxdepth 2 -type f"
curl -i http://127.0.0.1:8000/
```

Expected result: `/` returns `200 OK` with HTML content.

### Important Compose Note

In the repository root Compose setup, frontend assets are shared via the named
volume `frontend_dist`, not from the host folder `visualiser/frontend/dist`
directly. The `visualiser-frontend` service writes to `/app/dist`, and
`visualiser` reads the same data at `/app/frontend/dist`.

## API Documentation

With the backend running, visit:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health check**: http://localhost:8000/health

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/handshakes` | Store a TLS handshake record |
| `GET` | `/api/handshakes` | List all stored records (summaries) |
| `GET` | `/api/handshakes/{id}` | Get full record |
| `DELETE` | `/api/handshakes/{id}` | Delete a record |
| `GET` | `/api/observatory/status` | Latest Observatory scan per active target |
| `GET` | `/api/observatory/adoption` | Daily PQC adoption summary from the Observatory JSON store |
| `GET` | `/api/observatory/algorithms` | Negotiated group counts from the Observatory JSON store |
| `GET` | `/api/handshakes/{id}/export/tikz/handshake-flow` | Download handshake flow `.tex` |
| `GET` | `/api/handshakes/{id}/export/tikz/key-share-comparison` | Download key share comparison `.tex` |
| `GET` | `/health` | Health check |

## Testing

```bash
cd visualiser
uv run pytest tests/ -v
```

## LaTeX Export

The exported `.tex` files require:

```tex
% handshake-flow.tex
\usepackage{tikz}
\usepackage{xcolor}

% key-share-comparison.tex
\usepackage{tikz}
\usepackage{pgfplots}
\usepackage{xcolor}
\pgfplotsset{compat=1.18}
```

Compile with:

```bash
pdflatex handshake-flow.tex
pdflatex key-share-comparison.tex
```
