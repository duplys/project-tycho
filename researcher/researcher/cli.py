from __future__ import annotations

from pathlib import Path

import click

from researcher.config import ResearcherSettings
from researcher.connectors import (
    BlogConnector,
    ObservatoryConnector,
    ReferenceRetriever,
    VisualiserConnector,
)
from researcher.graph import GraphDependencies, build_research_graph
from researcher.llm import build_llm
from researcher.models import OutputType


@click.group()
def main() -> None:
    """Tool 4 researcher — autonomous PQC TLS research drafting."""


@main.command("run")
@click.option("--topic", required=True, help="Research topic or framing prompt.")
@click.option(
    "--output-type",
    type=click.Choice([member.value for member in OutputType]),
    default=OutputType.RESEARCH_SUMMARY.value,
    show_default=True,
    help="Draft format to generate.",
)
@click.option(
    "--since",
    default=None,
    metavar="YYYY-MM-DD",
    help="Only include Observatory/Visualiser data from this date onward.",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path, file_okay=False, dir_okay=True),
    default=None,
    help="Override output directory for generated drafts/artifacts.",
)
@click.option(
    "--max-visualizations",
    type=int,
    default=None,
    help="Maximum number of scan-derived visualizations to export.",
)
@click.option(
    "--publish-to-blog",
    is_flag=True,
    default=False,
    help="Upload the final draft to the blog service and trigger a site rebuild.",
)
@click.option(
    "--blog-system-prompt",
    type=click.Path(path_type=Path, file_okay=True, dir_okay=False, exists=True),
    default=None,
    help="Path to a file containing a custom system prompt for blog post generation.",
)
def run(
    topic: str,
    output_type: str,
    since: str | None,
    output_dir: Path | None,
    max_visualizations: int | None,
    publish_to_blog: bool,
    blog_system_prompt: Path | None,
) -> None:
    settings = ResearcherSettings()
    if output_dir is not None:
        settings = settings.model_copy(update={"output_dir": output_dir})
    if max_visualizations is not None:
        settings = settings.model_copy(
            update={"max_visualizations": max_visualizations}
        )

    observatory = ObservatoryConnector(data_file=settings.observatory_data_file)
    visualiser = VisualiserConnector(
        base_url=settings.visualiser_base_url,
        timeout_s=settings.http_timeout_s,
    )
    references = ReferenceRetriever(
        reference_dir=settings.reference_dir,
        chunk_size=settings.reference_chunk_size,
        chunk_overlap=settings.reference_chunk_overlap,
    )
    llm = build_llm(settings=settings)

    blog = None
    blog_system_prompt_text = None
    if publish_to_blog:
        blog = BlogConnector(
            base_url=settings.blog_base_url,
            timeout_s=settings.http_timeout_s,
        )
        prompt_path = blog_system_prompt or settings.blog_system_prompt_file
        if prompt_path and prompt_path.exists():
            blog_system_prompt_text = prompt_path.read_text(encoding="utf-8").strip()

    graph = build_research_graph(
        deps=GraphDependencies(
            settings=settings,
            observatory=observatory,
            visualiser=visualiser,
            references=references,
            llm=llm,
            blog=blog,
        )
    )

    result = graph.invoke(
        {
            "topic": topic,
            "output_type": output_type,
            "since": since,
            "max_visualizations": settings.max_visualizations,
            "blog_system_prompt": blog_system_prompt_text,
        }
    )
    output_paths = result.get("output_paths", {})
    click.echo(f"Draft saved to: {output_paths.get('draft_markdown', 'N/A')}")
    click.echo(f"Metadata saved to: {output_paths.get('metadata_json', 'N/A')}")
    if publish_to_blog:
        click.echo(f"Blog post published: {result.get('blog_post_url', 'N/A')}")


@main.command("blog-weekly")
@click.option(
    "--topic",
    default="Weekly PQC TLS Observatory Analysis",
    help="Blog post topic.",
)
@click.option(
    "--blog-system-prompt",
    type=click.Path(
        path_type=Path, file_okay=True, dir_okay=False, exists=True
    ),
    default=None,
    help="Custom system prompt file for blog generation.",
)
def blog_weekly(topic: str, blog_system_prompt: Path | None) -> None:
    """Generate and publish a weekly blog post (last 7 days of data)."""
    from datetime import UTC, datetime, timedelta

    week_ago = (datetime.now(UTC) - timedelta(days=7)).strftime("%Y-%m-%d")

    ctx = click.get_current_context()
    run_cmd = ctx.parent.commands["run"]
    click.echo(f"Generating weekly blog post (since {week_ago})...")
    run_cmd.invoke(
        ctx,
        topic=topic,
        output_type="blog-post",
        since=week_ago,
        publish_to_blog=True,
        blog_system_prompt=blog_system_prompt,
    )


if __name__ == "__main__":
    main()
