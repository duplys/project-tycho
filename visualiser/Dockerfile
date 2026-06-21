# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency resolution.
COPY --from=ghcr.io/astral-sh/uv:0.11.19 /uv /usr/local/bin/

# Copy application source.
COPY src/ ./src/

# Install Python dependencies before copying source for better layer caching.
COPY pyproject.toml README.md ./
RUN uv pip install --system --no-cache .

EXPOSE 8000

CMD ["uvicorn", "tls_visualizer.app:app", "--host", "0.0.0.0", "--port", "8000"]
