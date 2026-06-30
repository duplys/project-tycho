# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

COPY blog/pyproject.toml ./pyproject.toml
COPY blog/blog ./blog

RUN uv pip install --system --no-cache .

ENV BLOG_POSTS_DIR=/var/pqc-obs/blog-posts
ENV BLOG_SITE_DIR=/var/pqc-obs/blog-site

EXPOSE 8001

ENTRYPOINT ["blog", "serve"]
