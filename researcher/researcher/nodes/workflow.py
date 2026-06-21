from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from langchain_core.prompts import ChatPromptTemplate

from researcher.models import OutputType, ResearchMetadata, VisualArtifact


def _parse_since(since: str | None) -> datetime | None:
    if since is None:
        return None
    parsed = datetime.fromisoformat(since)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _message_text(message: Any) -> str:
    content = getattr(message, "content", message)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, dict):
                text = part.get("text")
                if isinstance(text, str):
                    parts.append(text)
            elif isinstance(part, str):
                parts.append(part)
        return "\n".join(parts)
    return str(content)


def _json_dump(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def plan_run_node(state: dict[str, Any], deps: Any) -> dict[str, Any]:
    run_id = state.get("run_id") or uuid.uuid4().hex[:12]
    requested_at = datetime.now(UTC).isoformat()
    max_visualizations = int(
        state.get("max_visualizations", deps.settings.max_visualizations)
    )
    return {
        "run_id": run_id,
        "requested_at": requested_at,
        "max_visualizations": max_visualizations,
    }


def collect_observatory_node(state: dict[str, Any], deps: Any) -> dict[str, Any]:
    since_dt = _parse_since(state.get("since"))
    observatory_context = deps.observatory.build_research_context(since=since_dt)
    sample_limit = max(1, state["max_visualizations"] * 2)
    candidate_scans = deps.observatory.get_recent_scans(
        limit=sample_limit,
        since=since_dt,
        only_with_analyzer_output=True,
    )
    return {
        "observatory_context": observatory_context,
        "candidate_scans": candidate_scans,
    }


def collect_visuals_node(state: dict[str, Any], deps: Any) -> dict[str, Any]:
    since = state.get("since")
    visualiser_context = {
        "status": deps.visualiser.get_status(),
        "adoption": deps.visualiser.get_adoption(since=since),
        "algorithms": deps.visualiser.get_algorithms(since=since),
    }

    run_asset_dir = deps.settings.output_dir / state["run_id"] / "assets"
    visual_artifacts: list[dict[str, Any]] = []
    scan_index = 0

    for scan in state.get("candidate_scans", []):
        analyzer_output = scan.get("analyzer_output")
        if not analyzer_output:
            continue
        if scan.get("is_pqc") is False:
            continue
        scan_index += 1
        if scan_index > state["max_visualizations"]:
            break

        exported = deps.visualiser.export_handshake_assets(analyzer_output=analyzer_output)
        for export_kind, tex_source in exported.items():
            filename = f"scan-{scan_index:02d}-{export_kind}.tex"
            output_path = run_asset_dir / filename
            _write_text(output_path, tex_source)
            artifact = VisualArtifact(
                kind=export_kind,
                filename=filename,
                relative_path=str(output_path.relative_to(deps.settings.output_dir)),
                description=(
                    f"{export_kind} for {scan.get('target_id', 'unknown-target')} "
                    f"at {scan.get('scanned_at')}"
                ),
            )
            visual_artifacts.append(artifact.model_dump())

    return {
        "visualiser_context": visualiser_context,
        "visual_artifacts": visual_artifacts,
    }


def collect_references_node(state: dict[str, Any], deps: Any) -> dict[str, Any]:
    top_groups = [
        row.get("selected_group")
        for row in state["observatory_context"].get("algorithms", [])[:5]
        if row.get("selected_group")
    ]
    query = f"{state['topic']} PQC TLS {' '.join(top_groups)}"
    references = deps.references.retrieve(
        query=query,
        limit=deps.settings.max_reference_snippets,
    )
    return {"references": [snippet.model_dump() for snippet in references]}


def draft_node(state: dict[str, Any], deps: Any) -> dict[str, Any]:
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You draft concise technical research text about PQC adoption in TLS. "
                "Every major claim must be grounded in supplied evidence.",
            ),
            (
                "human",
                "Create a {output_type} draft on topic: {topic}\n\n"
                "Observatory context:\n{observatory_context}\n\n"
                "Visualiser context:\n{visualiser_context}\n\n"
                "Reference snippets:\n{references}\n\n"
                "Available visual artifacts:\n{visual_artifacts}\n\n"
                "Output markdown with sections:\n"
                "1) Title\n2) Executive summary\n3) Evidence-based findings\n"
                "4) Interpretation grounded in references\n5) Suggested figure placements\n"
                "6) Caveats and uncertainty\n",
            ),
        ]
    )
    messages = prompt.format_messages(
        output_type=state["output_type"],
        topic=state["topic"],
        observatory_context=_json_dump(state["observatory_context"]),
        visualiser_context=_json_dump(state["visualiser_context"]),
        references=_json_dump(state["references"]),
        visual_artifacts=_json_dump(state["visual_artifacts"]),
    )
    response = deps.llm.invoke(messages)
    return {"draft_markdown": _message_text(response).strip()}


def critique_node(state: dict[str, Any], deps: Any) -> dict[str, Any]:
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a strict research reviewer. Detect unsupported claims, "
                "missing qualifiers, and weak evidence mapping.",
            ),
            (
                "human",
                "Review this draft:\n{draft}\n\n"
                "Against evidence:\n{observatory_context}\n\n"
                "References:\n{references}\n\n"
                "Return a concise critique with required fixes.",
            ),
        ]
    )
    messages = prompt.format_messages(
        draft=state["draft_markdown"],
        observatory_context=_json_dump(state["observatory_context"]),
        references=_json_dump(state["references"]),
    )
    response = deps.llm.invoke(messages)
    return {"critique_markdown": _message_text(response).strip()}


def finalize_node(state: dict[str, Any], deps: Any) -> dict[str, Any]:
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You produce final publication drafts that are explicit about limits "
                "and trace claims back to evidence.",
            ),
            (
                "human",
                "Revise the draft using the critique.\n\n"
                "Draft:\n{draft}\n\n"
                "Critique:\n{critique}\n\n"
                "Ensure the final markdown is polished, concise, and evidence-grounded.",
            ),
        ]
    )
    messages = prompt.format_messages(
        draft=state["draft_markdown"],
        critique=state["critique_markdown"],
    )
    response = deps.llm.invoke(messages)
    final_markdown = _message_text(response).strip()

    output_dir = deps.settings.output_dir / state["run_id"]
    markdown_path = output_dir / "draft.md"
    metadata_path = output_dir / "metadata.json"
    _write_text(markdown_path, final_markdown + "\n")

    metadata = ResearchMetadata(
        run_id=state["run_id"],
        generated_at=datetime.now(UTC).isoformat(),
        topic=state["topic"],
        output_type=OutputType(state["output_type"]),
        since=state.get("since"),
        observatory_context=state["observatory_context"],
        visualiser_context=state["visualiser_context"],
        references=state["references"],
        visual_artifacts=state["visual_artifacts"],
    )
    _write_text(metadata_path, metadata.model_dump_json(indent=2) + "\n")

    return {
        "final_markdown": final_markdown,
        "output_paths": {
            "draft_markdown": str(markdown_path),
            "metadata_json": str(metadata_path),
        },
    }
