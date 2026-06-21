from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypedDict

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import END, START, StateGraph

from researcher.config import ResearcherSettings
from researcher.connectors.observatory import ObservatoryConnector
from researcher.connectors.references import ReferenceRetriever
from researcher.connectors.visualiser import VisualiserConnector
from researcher.nodes.workflow import (
    collect_observatory_node,
    collect_references_node,
    collect_visuals_node,
    critique_node,
    draft_node,
    finalize_node,
    plan_run_node,
)


class ResearchState(TypedDict, total=False):
    run_id: str
    topic: str
    output_type: str
    since: str | None
    max_visualizations: int
    requested_at: str
    observatory_context: dict[str, Any]
    candidate_scans: list[dict[str, Any]]
    visualiser_context: dict[str, Any]
    references: list[dict[str, Any]]
    visual_artifacts: list[dict[str, Any]]
    draft_markdown: str
    critique_markdown: str
    final_markdown: str
    output_paths: dict[str, str]


@dataclass(frozen=True)
class GraphDependencies:
    settings: ResearcherSettings
    observatory: ObservatoryConnector
    visualiser: VisualiserConnector
    references: ReferenceRetriever
    llm: BaseChatModel


def build_research_graph(deps: GraphDependencies):
    graph = StateGraph(ResearchState)

    graph.add_node("plan_run", lambda state: plan_run_node(state=state, deps=deps))
    graph.add_node(
        "collect_observatory",
        lambda state: collect_observatory_node(state=state, deps=deps),
    )
    graph.add_node(
        "collect_visuals",
        lambda state: collect_visuals_node(state=state, deps=deps),
    )
    graph.add_node(
        "collect_references",
        lambda state: collect_references_node(state=state, deps=deps),
    )
    graph.add_node("draft", lambda state: draft_node(state=state, deps=deps))
    graph.add_node("critique", lambda state: critique_node(state=state, deps=deps))
    graph.add_node("finalize", lambda state: finalize_node(state=state, deps=deps))

    graph.add_edge(START, "plan_run")
    graph.add_edge("plan_run", "collect_observatory")
    graph.add_edge("collect_observatory", "collect_visuals")
    graph.add_edge("collect_visuals", "collect_references")
    graph.add_edge("collect_references", "draft")
    graph.add_edge("draft", "critique")
    graph.add_edge("critique", "finalize")
    graph.add_edge("finalize", END)

    return graph.compile()
