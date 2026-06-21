from researcher.connectors.references import ReferenceRetriever


def test_reference_retrieval_finds_pqc_snippets(tmp_path):
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    (ref_dir / "chapter-mlkem.tex").write_text(
        "ML-KEM in TLS hybrid groups such as X25519MLKEM768 improve transition safety.",
        encoding="utf-8",
    )
    (ref_dir / "chapter-intro.md").write_text(
        "General introduction without matching keywords.",
        encoding="utf-8",
    )

    retriever = ReferenceRetriever(reference_dir=ref_dir, chunk_size=100, chunk_overlap=10)
    snippets = retriever.retrieve("ML-KEM TLS hybrid X25519MLKEM768", limit=3)

    assert len(snippets) >= 1
    assert "X25519MLKEM768" in snippets[0].excerpt
    assert snippets[0].score > 0
