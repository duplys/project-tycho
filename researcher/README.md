# Researcher (Tool 4)

`researcher` is the autonomous AI research agent in Project Tycho.  
It is built with **LangChain + LangGraph** and combines:

- Observatory scan data,
- reference corpus files mounted in the container (e.g., LaTeX chapters),
- Visualiser-generated artifacts,

to draft short outputs on PQC adoption in TLS.

## Scope of this MVP

- ✅ CLI one-shot autonomous runs
- ✅ Markdown draft + JSON metadata output
- ✅ Visualiser TikZ asset generation from observed handshakes
- ✅ Blog post publishing to the blog service (`--publish-to-blog`)
- ✅ Weekly blog automation (`blog-weekly` subcommand)
- ✅ Customizable blog system prompt via file
- ❌ Built-in scheduler (out of scope)
- ❌ Long-running API service (out of scope)

## Installation

```bash
cd researcher
uv sync --extra dev
```

## Usage

### One-shot research draft

```bash
cd researcher
uv run researcher run \
  --topic "What has changed in PQC TLS adoption this month?" \
  --output-type research-summary \
  --since 2026-05-01
```

### Publish a blog post

Generates a blog-formatted draft and publishes it to the blog service:

```bash
cd researcher
uv run researcher run \
  --topic "ML-KEM takes the lead this week" \
  --output-type blog-post \
  --since 2026-06-22 \
  --publish-to-blog \
  --blog-system-prompt ../system-prompts/blog-prompt.txt
```

The `--blog-system-prompt` flag overrides the default system prompt with a
custom file. This is how you control the tone, themes, and focus of generated
blog posts.

### Weekly blog automation

The `blog-weekly` subcommand wraps the most common use case — generating and
publishing a blog post covering the last 7 days of observatory data:

```bash
cd researcher
uv run researcher blog-weekly \
  --topic "Weekly PQC TLS Observatory Analysis" \
  --blog-system-prompt ../system-prompts/blog-prompt.txt
```

This automatically sets `--since` to 7 days ago, `--output-type` to `blog-post`,
and enables `--publish-to-blog`. The blog service must be running at
`RESEARCHER_BLOG_BASE_URL`.

On a production server, schedule it with cron (every Monday at 09:00, after the
Sunday observatory scan):

```
0 9 * * 1 cd /srv/project-tycho && docker compose --profile research run --rm researcher blog-weekly
```

The command writes:

- `draft.md`
- `metadata.json`
- generated TikZ files under `assets/`

inside `RESEARCHER_OUTPUT_DIR/<run_id>/`.

## Configuration

Set with environment variables (prefix `RESEARCHER_`):

| Variable | Default | Description |
|---|---|---|
| `RESEARCHER_OBSERVATORY_DATA_FILE` | `/var/pqc-obs/data/observatory-data.json` | Observatory JSON store path |
| `RESEARCHER_REFERENCE_DIR` | `/var/pqc-obs/references` | Directory containing reference files (`.tex`, `.md`, `.txt`) |
| `RESEARCHER_OUTPUT_DIR` | `/var/pqc-obs/researcher-output` | Output root for generated drafts/artifacts |
| `RESEARCHER_VISUALISER_BASE_URL` | `http://127.0.0.1:8000` | Visualiser API base URL |
| `RESEARCHER_LLM_MODEL` | `gpt-4.1-mini` | LLM model used by LangChain |
| `RESEARCHER_LLM_TEMPERATURE` | `0.2` | LLM sampling temperature |
| `RESEARCHER_MAX_REFERENCE_SNIPPETS` | `6` | Maximum retrieved reference chunks |
| `RESEARCHER_MAX_VISUALIZATIONS` | `3` | Maximum scan-derived visualizations per run |
| `RESEARCHER_BLOG_BASE_URL` | `http://blog:8001` | Blog service API base URL |
| `RESEARCHER_BLOG_SYSTEM_PROMPT_FILE` | (none) | Path to a file containing a custom system prompt for blog generation |

`OPENAI_API_KEY` must be set for the default OpenAI-backed LangChain model.

## Docker

Build from repository root:

```bash
docker build -f researcher/Dockerfile -t tycho-researcher .
```

Example run:

```bash
docker run --rm \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e RESEARCHER_VISUALISER_BASE_URL="http://host.docker.internal:8000" \
  -e RESEARCHER_BLOG_BASE_URL="http://host.docker.internal:8001" \
  -v /var/pqc-obs/data:/var/pqc-obs/data:ro \
  -v /var/pqc-obs/references:/var/pqc-obs/references:ro \
  -v /var/pqc-obs/researcher-output:/var/pqc-obs/researcher-output \
  tycho-researcher \
  run --topic "Weekly PQC TLS adoption update" --output-type blog-post
```

### Publish to blog via Docker Compose

From the repository root, with the blog service already running:

```bash
OPENAI_API_KEY=sk-... \
  docker compose --profile research run --rm researcher \
    run \
      --topic "ML-KEM dominates this week" \
      --output-type blog-post \
      --since 2026-06-22 \
      --publish-to-blog
```

Override the blog system prompt by mounting your own file:

```bash
OPENAI_API_KEY=sk-... \
  RESEARCHER_BLOG_SYSTEM_PROMPT_FILE=/var/pqc-obs/system-prompts/blog-prompt.txt \
  docker compose --profile research run --rm researcher blog-weekly
```

## Tests

```bash
cd researcher
uv run pytest tests/ -v
```
