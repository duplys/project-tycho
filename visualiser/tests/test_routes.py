from tests.conftest import SAMPLE_RECORD


def test_post_handshake(client):
    resp = client.post("/api/handshakes", json=SAMPLE_RECORD)
    assert resp.status_code == 200
    body = resp.json()
    assert "id" in body
    assert "data" in body
    assert body["data"]["capture_metadata"]["filename"] == "cloudflare-2026-04-23.pcap"


def test_list_handshakes_empty(client):
    resp = client.get("/api/handshakes")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_handshakes_after_post(client):
    post_resp = client.post("/api/handshakes", json=SAMPLE_RECORD)
    record_id = post_resp.json()["id"]

    resp = client.get("/api/handshakes")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    assert items[0]["id"] == record_id
    assert items[0]["capture_metadata"]["filename"] == "cloudflare-2026-04-23.pcap"
    assert items[0]["is_pqc"] is True


def test_get_handshake(client):
    post_resp = client.post("/api/handshakes", json=SAMPLE_RECORD)
    record_id = post_resp.json()["id"]

    resp = client.get(f"/api/handshakes/{record_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == record_id
    assert body["data"]["server_hello"]["selected_group"] == "X25519MLKEM768"


def test_get_handshake_not_found(client):
    resp = client.get("/api/handshakes/nonexistent")
    assert resp.status_code == 404


def test_delete_handshake(client):
    post_resp = client.post("/api/handshakes", json=SAMPLE_RECORD)
    record_id = post_resp.json()["id"]

    del_resp = client.delete(f"/api/handshakes/{record_id}")
    assert del_resp.status_code == 200

    get_resp = client.get(f"/api/handshakes/{record_id}")
    assert get_resp.status_code == 404


def test_delete_handshake_not_found(client):
    resp = client.delete("/api/handshakes/nonexistent")
    assert resp.status_code == 404


def test_export_handshake_flow(client):
    post_resp = client.post("/api/handshakes", json=SAMPLE_RECORD)
    record_id = post_resp.json()["id"]

    resp = client.get(f"/api/handshakes/{record_id}/export/tikz/handshake-flow")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert r"\begin{tikzpicture}" in resp.text
    assert r"\end{tikzpicture}" in resp.text


def test_export_handshake_flow_not_found(client):
    resp = client.get("/api/handshakes/nonexistent/export/tikz/handshake-flow")
    assert resp.status_code == 404


def test_export_key_share_comparison(client):
    post_resp = client.post("/api/handshakes", json=SAMPLE_RECORD)
    record_id = post_resp.json()["id"]

    resp = client.get(f"/api/handshakes/{record_id}/export/tikz/key-share-comparison")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert r"\begin{tikzpicture}" in resp.text
    assert r"\end{tikzpicture}" in resp.text


def test_export_key_share_comparison_not_found(client):
    resp = client.get("/api/handshakes/nonexistent/export/tikz/key-share-comparison")
    assert resp.status_code == 404


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
