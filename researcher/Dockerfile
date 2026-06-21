# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

COPY researcher/pyproject.toml ./pyproject.toml
COPY researcher/researcher ./researcher

RUN uv pip install --system --no-cache .

ENV RESEARCHER_OBSERVATORY_DATA_FILE=/var/pqc-obs/data/observatory-data.json
ENV RESEARCHER_REFERENCE_DIR=/var/pqc-obs/references
ENV RESEARCHER_OUTPUT_DIR=/var/pqc-obs/researcher-output
ENV RESEARCHER_VISUALISER_BASE_URL=http://127.0.0.1:8000

ENTRYPOINT ["researcher"]
