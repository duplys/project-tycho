# syntax=docker/dockerfile:1
FROM python:3.12-slim

# tcpdump is required for pcap capture.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Grant the observatory process CAP_NET_RAW so tcpdump can capture without
# running as root.  The capability is set at container runtime (see
# docker-compose.yml).

WORKDIR /app/observatory

# Install uv for fast dependency resolution.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Copy PCAP Analyser source first (referenced as a path dependency by the Observatory).
COPY pcap-analyser/ /app/pcap-analyser/

# Install Observatory dependencies (including the path-resolved PCAP Analyser) before
# copying the full source for better layer caching.
COPY observatory/pyproject.toml ./pyproject.toml
COPY observatory/README.md ./README.md
COPY observatory/observatory/ ./observatory/
RUN uv pip install --system --no-cache .

# Copy Observatory source.
COPY observatory/targets/ ./targets/

# Default command: start the scheduler.
CMD ["observatory", "start"]
