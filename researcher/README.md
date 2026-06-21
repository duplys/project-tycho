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
- ❌ Built-in scheduler (out of scope)
- ❌ Long-running API service (out of scope)

## Installation

```bash
cd researcher
uv sync --extra dev
```

## Usage

```bash
cd researcher
uv run researcher run \
  --topic "What has changed in PQC TLS adoption this month?" \
  --output-type research-summary \
  --since 2026-05-01
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
  -v /var/pqc-obs/data:/var/pqc-obs/data:ro \
  -v /var/pqc-obs/references:/var/pqc-obs/references:ro \
  -v /var/pqc-obs/researcher-output:/var/pqc-obs/researcher-output \
  tycho-researcher \
  run --topic "Weekly PQC TLS adoption update" --output-type blog-post
```

## Tests

```bash
cd researcher
uv run pytest tests/ -v
```
