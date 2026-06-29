# Blog (Tool 5)

`blog` is the static publishing service for Project Tycho. It accepts
research posts from the Researcher agent and renders them as a static HTML
blog site.

## Scope

- ✅ HTTP API for post submission (`POST /api/posts`) and site rebuild (`POST /api/rebuild`)
- ✅ Static HTML generation from Markdown via Jinja2 templates
- ✅ Dark/light-mode responsive CSS
- ✅ Posts stored as JSON files in a persistent volume
- ✅ List all published posts (`GET /api/posts`)
- ❌ Comment system, search, RSS feed (out of scope for this MVP)

## Installation

```bash
cd blog
uv sync --extra dev
```

## Usage

### Start the blog server

```bash
cd blog
uv run blog serve
```

Starts a FastAPI server on `http://0.0.0.0:8001`. The static HTML site is
served at `/` and the management API lives under `/api/`.

### Build the static site manually

```bash
cd blog
uv run blog build
```

Reads all JSON posts from `BLOG_POSTS_DIR`, renders HTML into `BLOG_SITE_DIR`.

### Submit a post via the API

```bash
curl -X POST http://localhost:8001/api/posts \
  -H "Content-Type: application/json" \
  -d '{
    "title": "ML-KEM dominates this week",
    "slug": "ml-kem-dominates-this-week",
    "summary": "ML-KEM768 is now the most widely deployed PQC algorithm across our targets.",
    "tags": ["PQC", "TLS", "ML-KEM768"],
    "markdown_content": "## Findings\n\nThis week we observed...",
    "run_id": "abc123def456"
  }'
```

### Trigger a site rebuild

```bash
curl -X POST http://localhost:8001/api/rebuild
```

### View published posts

```bash
curl http://localhost:8001/api/posts
```

## Configuration

Set with environment variables (prefix `BLOG_`):

| Variable | Default | Description |
|---|---|---|
| `BLOG_POSTS_DIR` | `/var/pqc-obs/blog-posts` | Directory where post JSON files are stored |
| `BLOG_SITE_DIR` | `/var/pqc-obs/blog-site` | Directory where generated static HTML is written |
| `BLOG_HOST` | `0.0.0.0` | Server bind address |
| `BLOG_PORT` | `8001` | Server port |
| `BLOG_TITLE` | `Project Tycho — PQC Observatory Blog` | Blog title shown in header |
| `BLOG_AUTHOR` | `Tycho Researcher` | Default author for posts |
| `BLOG_DESCRIPTION` | `Weekly analysis of post-quantum cryptography adoption in TLS` | Meta description |

## Docker

Build from repository root:

```bash
docker build -f blog/Dockerfile -t tycho-blog .
```

Example run:

```bash
docker run --rm \
  -p 8001:8001 \
  -v /srv/project-tycho/blog-posts:/var/pqc-obs/blog-posts \
  -v /srv/project-tycho/blog-site:/var/pqc-obs/blog-site \
  tycho-blog
```

### With Docker Compose

From the repository root:

```bash
docker compose up -d
```

The blog is included in the default profile and starts automatically alongside
the Observatory and Visualiser. It binds to port `8001` on the host.

To publish a weekly blog post via the Researcher agent:

```bash
OPENAI_API_KEY=sk-... \
  docker compose --profile research run --rm researcher blog-weekly
```

Or with a custom topic:

```bash
OPENAI_API_KEY=sk-... \
  docker compose --profile research run --rm researcher run \
    --topic "PQC adoption in the financial sector" \
    --output-type blog-post \
    --since 2026-06-22 \
    --publish-to-blog
```

The blog site is available at <http://localhost:8001>.

### Nginx reverse proxy (production)

If you want to expose the blog alongside the Visualiser on a single domain,
add a location block to your Nginx config:

```nginx
location /blog/ {
    rewrite ^/blog(/.*)$ $1 break;
    proxy_pass http://127.0.0.1:8001;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Note: when mounted under a sub-path, update `BLOG_SITE_DIR` and rebuild after
each publish cycle.

## Tests

```bash
cd blog
uv run pytest tests/ -v
```
