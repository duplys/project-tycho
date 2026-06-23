# Project Tycho

Project Tycho is an automated research platform for observing PQC adoption in TLS.

![Tycho Brahe](assets/tycho-brahe.png)

## Vision
Project Tycho is a four-part research platform that for observing PQC adoption in TLS. The platform combines empirical measurement, structured analysis, publication-ready visualization, and experimental autonomous research generation around the theme of post-quantum cryptography (PQC) in TLS.

### PCAP Analyser

A command-line / library tool that parses pcap files and extracts structured data about TLS handshakes, with particular focus on PQC cipher suites, key exchange parameters, and signature algorithms.

### Visualiser

A FastAPI + Vue.js web app that consumes the analyzer's output, renders interactive visualizations of TLS handshakes, and exports publication-ready PGF/TikZ source for LaTeX.

### Observatory

An orchestration service that periodically scans a curated list of target websites, records their TLS handshakes as pcaps, invokes the analyzer, and updates a live adoption dashboard.

### Researcher (Autonomous Research Agent)

The `researcher/` tool is an AI-powered agent (LangChain + LangGraph) that combines book theory, empirical Observatory data, and Visualiser-generated assets to draft short research summaries, article drafts, and blog posts about PQC adoption in TLS.

Current scope is a **CLI one-shot MVP** (no built-in scheduler or long-running API service yet).

The first three tools compose into a single continuous pipeline on one VPS. The fourth is a deliberate experiment in AI-augmented research workflows.

## Current Limitations

Two Observatory behaviors are important when interpreting current results. These are current implementation limitations, not intended guarantees:

- **Manual single-group probes are not persisted.** Running `observatory scan HOST --openssl-groups GROUP` prints the probe result to stdout, but it does not append a scan row to the Observatory JSON store. These ad-hoc probes therefore do not appear in status output, scan history, Visualiser dashboards, or adoption calculations.
- **Per-host probe results are persisted only after that host's full group sequence finishes.** During scheduled rounds, completed probes for a target are kept in memory until all locally supported groups for that target have been attempted. If the process stops mid-target, those completed probes are lost from the JSON history; if an individual write later fails, the stored round can be incomplete and the current reporting layer cannot distinguish that from a complete round.

Quick start:

```bash
cd researcher
uv sync --extra dev
uv run researcher run \
  --topic "Weekly PQC TLS adoption update" \
  --output-type research-summary
```

## Running with Docker Compose

The fastest way to run the Observatory and Visualiser together is with a single command from the repository root:

```bash
docker compose up
```

This builds and starts:

- **Observatory** – scans TLS handshakes on a weekly schedule and writes results to a shared volume (`observatory_data`). Requires `NET_RAW` capability so `tcpdump` can capture packets.
- **Visualiser** – serves the interactive dashboard at <http://localhost:8000>. The Vue.js frontend is built automatically before the backend starts.

To also run the one-shot Researcher agent (requires an OpenAI API key):

```bash
OPENAI_API_KEY=sk-... docker compose --profile research run --rm researcher
```

Override the topic or output type via environment variables:

```bash
OPENAI_API_KEY=sk-... \
RESEARCHER_TOPIC="Monthly PQC digest" \
RESEARCHER_OUTPUT_TYPE=blog-post \
docker compose --profile research run --rm researcher
```

When running from the root `docker-compose.yml`, keep service settings in a single repository-root `.env` file. Docker Compose reads this file and passes the relevant values to each service.

## Deploying PCAP Analyser, Visualiser, and Observatory on a Hetzner VPS

The simplest production layout on a Hetzner Ubuntu VPS is:

- **PCAP Analyser** installed as a local CLI that the Observatory can call
- **Visualiser** running as a `systemd` service behind Nginx
- **Observatory** running as a long-lived `systemd` service

The steps below assume:

- Ubuntu 24.04 on the VPS
- a public DNS name such as `tycho.example.com`
- the repository checked out to `/srv/project-tycho`
- a non-root deployment user, for example `deploy`

### 1. Prepare the VPS

```bash
sudo apt update
sudo apt install -y \
  git curl nginx tcpdump \
  python3 python3-venv python3-pip \
  nodejs npm

curl -LsSf https://astral.sh/uv/install.sh | sh
source "$HOME/.local/bin/env"
```

`tcpdump` needs elevated packet-capture privileges, so the Observatory service below
is configured with `CAP_NET_RAW`.

Because `CAP_NET_RAW` allows raw packet capture, keep this VPS limited to this
workload or otherwise isolate the service carefully with additional hardening
such as AppArmor/SELinux policy, a dedicated deployment user, or container /
VM isolation.

For production, review the `uv` installer script before executing it.

Create the deployment user if you do not already have one:

```bash
sudo adduser deploy
sudo usermod -aG sudo deploy
```

Clone the repository:

```bash
sudo mkdir -p /srv
sudo chown "$USER":"$USER" /srv
git clone https://github.com/duplys/project-tycho.git /srv/project-tycho
cd /srv/project-tycho
```

### 2. Install PCAP Analyser

The PCAP Analyser is best deployed as a local command that the Observatory can execute directly.

```bash
cd /srv/project-tycho/pcap-analyser
uv sync
```

Test it:

```bash
cd /srv/project-tycho/pcap-analyser
uv run tls-pcap-analyzer --help
```

For integration with the Observatory, use the absolute analyzer path:

```text
/srv/project-tycho/pcap-analyser/.venv/bin/tls-pcap-analyzer
```

### 3. Install Visualiser

Build the frontend and install the backend:

```bash
cd /srv/project-tycho/visualiser
uv sync

cd /srv/project-tycho/visualiser/frontend
npm install
npm run build
```

Create a `systemd` unit at `/etc/systemd/system/tycho-visualiser.service`:

```ini
[Unit]
Description=Project Tycho Visualiser (TLS Visualizer)
After=network.target

[Service]
User=deploy
Group=deploy
WorkingDirectory=/srv/project-tycho/visualiser
Environment=PATH=/srv/project-tycho/visualiser/.venv/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/srv/project-tycho/visualiser/.venv/bin/uvicorn tls_visualizer.app:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tycho-visualiser
sudo systemctl status tycho-visualiser
```

### 4. Install Observatory

Install the application:

```bash
cd /srv/project-tycho/observatory
uv sync
sudo mkdir -p /var/pqc-obs/captures
sudo chown deploy:deploy /var/pqc-obs/captures
```

Create `/srv/project-tycho/observatory/.env`:

```env
OBSERVATORY_PCAP_DIR=/var/pqc-obs/captures
OBSERVATORY_STORAGE_FILE=/var/pqc-obs/data/observatory-data.json
OBSERVATORY_SCAN_SCHEDULE_DAY_OF_WEEK=sun
OBSERVATORY_SCAN_SCHEDULE_HOUR=8
OBSERVATORY_SCAN_SCHEDULE_MINUTE=0
OBSERVATORY_SCAN_SCHEDULE_TIMEZONE=Europe/Berlin
```

Restrict the file so only the deployment user can read it:

```bash
chmod 600 /srv/project-tycho/observatory/.env
```

Initialize the schema and targets:

```bash
cd /srv/project-tycho/observatory
uv run observatory init
```

Create a `systemd` unit at `/etc/systemd/system/tycho-observatory.service`:

```ini
[Unit]
Description=Project Tycho Observatory (PQC Observatory)
After=network.target

[Service]
User=deploy
Group=deploy
WorkingDirectory=/srv/project-tycho/observatory
Environment=PATH=/srv/project-tycho/observatory/.venv/bin:/usr/local/bin:/usr/bin:/bin
# Required so tcpdump can capture packets without running the whole service as root.
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
ExecStart=/srv/project-tycho/observatory/.venv/bin/observatory start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tycho-observatory
sudo systemctl status tycho-observatory
```

### 5. Put Visualiser behind Nginx

Create `/etc/nginx/sites-available/project-tycho`:

Replace `tycho.example.com` with your real domain name.

```nginx
server {
    listen 80;
    server_name tycho.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/project-tycho /etc/nginx/sites-enabled/project-tycho
sudo nginx -t
sudo systemctl reload nginx
```

Then add HTTPS with Let's Encrypt if the domain is public:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d tycho.example.com
```

### 6. Operations

Useful commands after deployment:

```bash
# Visualiser logs
sudo journalctl -u tycho-visualiser -f

# Observatory logs
sudo journalctl -u tycho-observatory -f

# Observatory status
cd /srv/project-tycho/observatory
uv run observatory status

# One manual scan
uv run observatory scan cloudflare.com
```

### 7. Updating the deployment

```bash
cd /srv/project-tycho
git pull

cd /srv/project-tycho/pcap-analyser && uv sync
cd /srv/project-tycho/visualiser && uv sync
cd /srv/project-tycho/visualiser/frontend && npm install && npm run build
cd /srv/project-tycho/observatory && uv sync

sudo systemctl restart tycho-visualiser
sudo systemctl restart tycho-observatory
```

## Deploying on a Hetzner VPS with Docker

If you prefer containers over a native install, `docker-compose.yml` at the repository root is the only runtime dependency you need on the VPS — no Python, Node.js, or `uv` required on the host.

The steps below assume:

- Ubuntu 24.04 on the VPS
- a public DNS name such as `tycho.example.com`
- the repository checked out to `/srv/project-tycho`

### 1. Prepare the VPS

Install Git and Docker Engine with the Compose plugin:

```bash
sudo apt update && sudo apt install -y git
```

Follow the [official Docker documentation](https://docs.docker.com/engine/install/ubuntu/) to install Docker Engine and the Compose plugin (`docker compose`).

Clone the repository:

```bash
sudo mkdir -p /srv
sudo chown "$USER":"$USER" /srv
git clone https://codeberg.org/TLS-Port/project-tycho.git /srv/project-tycho
cd /srv/project-tycho
```

### 2. Configure the stack (optional)

Create a repository-root `.env` file alongside `docker-compose.yml` to override defaults for any service:

```env
OBSERVATORY_SCAN_SCHEDULE_DAY_OF_WEEK=sun
OBSERVATORY_SCAN_SCHEDULE_HOUR=8
OBSERVATORY_SCAN_SCHEDULE_MINUTE=0
OBSERVATORY_SCAN_SCHEDULE_TIMEZONE=Europe/Berlin
# OPENAI_API_KEY=sk-...
```

This example schedules the Observatory for Sunday morning at 08:00 in Berlin
local time. The `Europe/Berlin` timezone keeps the scan at local 08:00 across
summer/winter daylight saving time changes.

Restrict the file so only the deployment user can read it:

```bash
chmod 600 /srv/project-tycho/.env
```

All services have sensible defaults except the optional Researcher API key; this step can be skipped for a quick start. See [§4 Install Observatory](#4-install-observatory) for the full list of Observatory variables.

### 3. Configure the Researcher API key (optional)

If you want to run the one-shot Researcher agent from Docker Compose, add the API key to the same repository-root `.env` file:

```env
OPENAI_API_KEY=sk-...
```

Docker Compose automatically reads this file when evaluating `${OPENAI_API_KEY}` in `docker-compose.yml`, so you do not need to export the variable manually for each run.

### 4. Start the stack

```bash
cd /srv/project-tycho
docker compose up -d
```

This builds images from the repository and starts:

- **Observatory** – runs the periodic TLS scanner. Pcap captures and scan results are written to Docker-managed named volumes (`pcap_store`, `observatory_data`). Granted `NET_RAW` capability so `tcpdump` can capture packets without running as root.
- **Visualiser** – serves the interactive dashboard at <http://localhost:8000>. The Vue.js frontend is built automatically by the `visualiser-frontend` helper service before the backend starts.

Verify both services are up:

```bash
docker compose ps
```

### 5. Put the Visualiser behind Nginx

The Visualiser binds to port 8000 on the host. Install Nginx with:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

Create the reverse-proxy site at `/etc/nginx/sites-available/project-tycho` (replace `tycho.example.com` with your real domain):

```nginx
server {
    listen 80;
    server_name tycho.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

If you already have other Nginx sites on the VPS, keep Project Tycho in its own
vhost file and give it its own certificate. The TLS block for
`project-tycho.vier99.de` should point at:

```text
/etc/letsencrypt/live/project-tycho.vier99.de/fullchain.pem
/etc/letsencrypt/live/project-tycho.vier99.de/privkey.pem
```

Do not reuse another site's certificate path unless that certificate already
covers `project-tycho.vier99.de` as a SAN name.

For the first issuance, make sure Nginx can pass `nginx -t` before running
Certbot. If the `project-tycho` HTTPS block points at a cert that does not
exist yet, temporarily remove that block or point it at an existing cert until
the new one is created.

Create a dedicated certificate with:

```bash
sudo certbot --nginx --cert-name project-tycho.vier99.de -d project-tycho.vier99.de
```

Enable the site and add HTTPS with Let's Encrypt:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
sudo ln -s /etc/nginx/sites-available/project-tycho /etc/nginx/sites-enabled/project-tycho
sudo nginx -t && sudo systemctl reload nginx
```

### 6. Operations

```bash
# Follow logs for all services
docker compose -f /srv/project-tycho/docker-compose.yml logs -f

# Follow a single service
docker compose -f /srv/project-tycho/docker-compose.yml logs -f observatory
docker compose -f /srv/project-tycho/docker-compose.yml logs -f visualiser

# Run the one-shot Researcher agent
OPENAI_API_KEY=sk-... docker compose -f /srv/project-tycho/docker-compose.yml \
  --profile research run --rm researcher
```

#### Extracting Tool 1 JSON for Visualiser

The Observatory stores Tool 1 (PCAP Analyser) output inside the shared JSON data file. You can extract a single handshake record and upload it to the Visualiser frontend for interactive analysis and TikZ export.

**Export the latest successful scan as a standalone JSON file:**

```bash
cd /srv/project-tycho
docker compose exec -T observatory python - <<'PY' > /srv/project-tycho/tool1-latest.json
import json
p = "/var/pqc-obs/data/observatory-data.json"
d = json.load(open(p))
for scan in reversed(d.get("scans", [])):
    ao = scan.get("analyzer_output")
    if scan.get("error") is None and ao:
        print(json.dumps(ao, indent=2))
        break
else:
    raise SystemExit("No successful scan with analyzer_output found")
PY
```

Verify the file was created:

```bash
ls -lah /srv/project-tycho/tool1-latest.json
head -n 30 /srv/project-tycho/tool1-latest.json
```

**Copy the file to your local machine:**

```bash
scp root@tycho.vier99.de:/srv/project-tycho/tool1-latest.json .
```

**Upload to Visualiser:**

1. Open the Visualiser dashboard at https://tycho.vier99.de
2. Click "Load" under "Load TLS Handshake Data"
3. Select the downloaded `tool1-latest.json` file
4. Click the "Load" button
5. Click "⬇ Handshake Flow (.tex)" to download the LaTeX source
6. Compile with `pdflatex` — cipher suite names are now properly escaped (underscores become `\_`)

**Export a specific hostname's latest successful scan:**

```bash
cd /srv/project-tycho
docker compose exec -T observatory python - <<'PY' > /srv/project-tycho/tool1-cloudflare.json
import json
hostname = "cloudflare.com"
p = "/var/pqc-obs/data/observatory-data.json"
d = json.load(open(p))
target_id = None
for t in d.get("targets", []):
    if t["hostname"] == hostname:
        target_id = t["id"]
        break
if not target_id:
    raise SystemExit(f"Target {hostname} not found")
for scan in reversed(d.get("scans", [])):
    if scan["target_id"] == target_id:
        ao = scan.get("analyzer_output")
        if scan.get("error") is None and ao:
            print(json.dumps(ao, indent=2))
            break
else:
    raise SystemExit(f"No successful scan with analyzer_output for {hostname}")
PY
```

This exports only the latest successful capture for that hostname.

### 7. Updating the deployment

Pull the latest code, rebuild images, and restart the stack:

```bash
cd /srv/project-tycho
git pull
docker compose up -d --build
```

Clean up dangling images after the update:

```bash
docker image prune -f
```
