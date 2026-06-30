import json

from researcher.config import ResearcherSettings
from researcher.connectors.observatory import ObservatoryConnector
from researcher.connectors.references import ReferenceRetriever
from researcher.graph import GraphDependencies, build_research_graph


class _FakeBlog:
    def __init__(self):
        self.published: list[dict] = []
        self.rebuilt = 0

    def publish_post(self, payload: dict) -> dict:
        self.published.append(payload)
        return {"slug": payload["slug"], "message": "Post created"}

    def rebuild_site(self) -> dict:
        self.rebuilt += 1
        return {"status": "ok", "posts_rendered": len(self.published)}


class _FakeMessage:
    def __init__(self, content: str):
        self.content = content


class _FakeLLM:
    def __init__(self, responses: list[str]):
        self._responses = iter(responses)

    def invoke(self, _input):
        return _FakeMessage(next(self._responses))


class _FakeVisualiser:
    def get_status(self):
        return [{"hostname": "cloudflare.com", "is_pqc": True}]

    def get_adoption(self, since=None):
        return [{"date": "2026-05-21", "total": 1, "pqc_count": 1, "pct_pqc": 100.0}]

    def get_algorithms(self, since=None):
        return [{"selected_group": "X25519MLKEM768", "count": 1}]

    def export_handshake_assets(self, analyzer_output):
        return {
            "handshake-flow": "\\begin{tikzpicture}flow\\end{tikzpicture}",
            "key-share-comparison": "\\begin{tikzpicture}keys\\end{tikzpicture}",
        }


def _write_observatory_data(path):
    payload = {
        "version": 1,
        "targets": [
            {"id": 1, "hostname": "cloudflare.com", "port": 443, "category": "cdn", "is_active": True}
        ],
        "scans": [
            {
                "id": 1,
                "target_id": 1,
                "scanned_at": "2026-05-21T10:00:00+00:00",
                "selected_group": "X25519MLKEM768",
                "negotiated_cipher_suite": "TLS_AES_128_GCM_SHA256",
                "is_pqc": True,
                "is_hybrid": True,
                "analyzer_output": {
                    "capture_metadata": {"filename": "cloudflare.pcap"},
                    "client_hello": {"tls_version": "TLS 1.3"},
                    "server_hello": {"selected_group": "X25519MLKEM768", "is_pqc": True, "is_hybrid": True},
                },
                "error": None,
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_graph_writes_outputs(tmp_path):
    data_file = tmp_path / "observatory-data.json"
    ref_dir = tmp_path / "refs"
    output_dir = tmp_path / "out"
    ref_dir.mkdir()
    (ref_dir / "chapter.tex").write_text(
        "TLS hybrid deployment with ML-KEM improves transition strategies.",
        encoding="utf-8",
    )
    _write_observatory_data(data_file)

    settings = ResearcherSettings(
        observatory_data_file=data_file,
        reference_dir=ref_dir,
        output_dir=output_dir,
        max_visualizations=1,
    )

    graph = build_research_graph(
        GraphDependencies(
            settings=settings,
            observatory=ObservatoryConnector(data_file=data_file),
            visualiser=_FakeVisualiser(),
            references=ReferenceRetriever(reference_dir=ref_dir),
            llm=_FakeLLM(
                [
                    "# Draft\nInitial content",
                    "Needs stronger caveats",
                    "# Final Draft\nEvidence-grounded final content",
                ]
            ),
            blog=None,
        )
    )

    result = graph.invoke(
        {
            "topic": "Monthly PQC adoption update",
            "output_type": "research-summary",
            "since": "2026-05-01",
        }
    )

    draft_path = result["output_paths"]["draft_markdown"]
    metadata_path = result["output_paths"]["metadata_json"]
    assert "Evidence-grounded final content" in open(draft_path, encoding="utf-8").read()
    metadata = json.loads(open(metadata_path, encoding="utf-8").read())
    assert metadata["topic"] == "Monthly PQC adoption update"
    assert len(metadata["visual_artifacts"]) >= 1


def test_graph_routes_to_publish_node_for_blog_post(tmp_path):
    data_file = tmp_path / "observatory-data.json"
    ref_dir = tmp_path / "refs"
    output_dir = tmp_path / "out"
    ref_dir.mkdir()
    (ref_dir / "chapter.tex").write_text(
        "TLS hybrid deployment with ML-KEM improves transition strategies.",
        encoding="utf-8",
    )
    _write_observatory_data(data_file)

    fake_blog = _FakeBlog()
    settings = ResearcherSettings(
        observatory_data_file=data_file,
        reference_dir=ref_dir,
        output_dir=output_dir,
        max_visualizations=1,
    )

    graph = build_research_graph(
        GraphDependencies(
            settings=settings,
            observatory=ObservatoryConnector(data_file=data_file),
            visualiser=_FakeVisualiser(),
            references=ReferenceRetriever(reference_dir=ref_dir),
            llm=_FakeLLM(
                [
                    "# Weekly PQC Update\nML-KEM768 takes the lead this week.",
                    "Looks good, minor caveats needed",
                    "# Weekly PQC Update\nML-KEM768 dominates. Evidence is strong.",
                ]
            ),
            blog=fake_blog,
        )
    )

    result = graph.invoke(
        {
            "topic": "Weekly PQC Update",
            "output_type": "blog-post",
            "since": "2026-05-01",
        }
    )

    assert fake_blog.rebuilt == 1
    assert len(fake_blog.published) == 1
    assert "blog_slug" in result
    assert result["blog_post_url"].startswith("/posts/")


def test_graph_skips_publish_node_when_no_blog(tmp_path):
    data_file = tmp_path / "observatory-data.json"
    ref_dir = tmp_path / "refs"
    output_dir = tmp_path / "out"
    ref_dir.mkdir()
    (ref_dir / "chapter.tex").write_text("ML-KEM reference.", encoding="utf-8")
    _write_observatory_data(data_file)

    settings = ResearcherSettings(
        observatory_data_file=data_file,
        reference_dir=ref_dir,
        output_dir=output_dir,
        max_visualizations=1,
    )

    graph = build_research_graph(
        GraphDependencies(
            settings=settings,
            observatory=ObservatoryConnector(data_file=data_file),
            visualiser=_FakeVisualiser(),
            references=ReferenceRetriever(reference_dir=ref_dir),
            llm=_FakeLLM(["# Draft\nContent", "OK", "# Final\nContent"]),
            blog=None,
        )
    )

    result = graph.invoke(
        {
            "topic": "Weekly PQC Update",
            "output_type": "blog-post",
            "since": "2026-05-01",
        }
    )

    assert "blog_slug" not in result or result.get("blog_slug") is None
