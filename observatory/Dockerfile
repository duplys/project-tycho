# syntax=docker/dockerfile:1

FROM python:3.12-slim AS openssl-builder

ARG OPENSSL_VERSION=4.0.1
ARG OPENSSL_SHA256=2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/openssl-build

RUN curl --fail --location --show-error \
        "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
        --output openssl.tar.gz \
    && echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum --check - \
    && tar --extract --gzip --file openssl.tar.gz --strip-components=1 \
    && ./config \
        --prefix=/opt/openssl \
        --openssldir=/opt/openssl/ssl \
        no-docs \
        no-shared \
        no-tests \
    && make -j"$(nproc)" \
    && make install_sw install_ssldirs

# Fail the build if the pinned client cannot provide every current PQC group.
RUN test "$(/opt/openssl/bin/openssl version | awk '{print $2}')" = "${OPENSSL_VERSION}" \
    && /opt/openssl/bin/openssl list -tls1_3 -tls-groups \
        | tr ':' '\n' > /tmp/tls-groups.txt \
    && for group in \
        MLKEM512 \
        MLKEM768 \
        MLKEM1024 \
        SecP256r1MLKEM768 \
        X25519MLKEM768 \
        SecP384r1MLKEM1024 \
        curveSM2MLKEM768; \
       do grep --fixed-strings --line-regexp "$group" /tmp/tls-groups.txt; done


FROM python:3.12-slim

COPY --from=openssl-builder /opt/openssl /opt/openssl

ENV PATH="/opt/openssl/bin:${PATH}" \
    OPENSSL_CONF="/opt/openssl/ssl/openssl.cnf"

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
