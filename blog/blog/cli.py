from __future__ import annotations

import click

from blog.config import BlogSettings
from blog.generator import SiteGenerator


@click.group()
def main() -> None:
    """Blog service — static site generator and API."""


@main.command("build")
def build() -> None:
    """Regenerate the static HTML site from stored posts."""
    settings = BlogSettings()
    generator = SiteGenerator(settings=settings)
    result = generator.build()
    click.echo(f"Site built: {result['posts_rendered']} posts rendered")


@main.command("serve")
def serve() -> None:
    """Start the blog API and static file server."""
    import uvicorn
    settings = BlogSettings()
    uvicorn.run(
        "blog.app:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
