from __future__ import annotations

from pathlib import Path

import click

from researcher.config import ResearcherSettings
from researcher.connectors import (
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
def run(
    topic: str,
    output_type: str,
    since: str | None,
    output_dir: Path | None,
    max_visualizations: int | None,
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

    graph = build_research_graph(
        deps=GraphDependencies(
            settings=settings,
            observatory=observatory,
            visualiser=visualiser,
            references=references,
            llm=llm,
        )
    )

    result = graph.invoke(
        {
            "topic": topic,
            "output_type": output_type,
            "since": since,
            "max_visualizations": settings.max_visualizations,
        }
    )
    output_paths = result["output_paths"]
    click.echo(f"Draft saved to: {output_paths['draft_markdown']}")
    click.echo(f"Metadata saved to: {output_paths['metadata_json']}")


if __name__ == "__main__":
    main()
