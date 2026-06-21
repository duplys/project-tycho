import httpx

from researcher.connectors.visualiser import VisualiserConnector


def test_visualiser_connector_endpoints(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/observatory/status":
            return httpx.Response(200, json=[{"hostname": "cloudflare.com"}])
        if request.method == "GET" and request.url.path == "/api/observatory/adoption":
            return httpx.Response(200, json=[{"date": "2026-05-21", "pct_pqc": 50.0}])
        if request.method == "GET" and request.url.path == "/api/observatory/algorithms":
            return httpx.Response(200, json=[{"selected_group": "X25519MLKEM768", "count": 3}])
        if request.method == "POST" and request.url.path == "/api/handshakes":
            return httpx.Response(200, json={"id": "record-1"})
        if request.method == "GET" and request.url.path.endswith("/export/tikz/handshake-flow"):
            return httpx.Response(200, text="FLOW_TEX")
        if request.method == "GET" and request.url.path.endswith("/export/tikz/key-share-comparison"):
            return httpx.Response(200, text="KEY_TEX")
        if request.method == "DELETE" and request.url.path == "/api/handshakes/record-1":
            return httpx.Response(200, json={"status": "deleted"})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)

    def _mock_client(self):
        return httpx.Client(
            transport=transport,
            base_url=self.base_url,
            timeout=self.timeout_s,
        )

    monkeypatch.setattr(VisualiserConnector, "_client", _mock_client)

    connector = VisualiserConnector(base_url="http://visualiser.local", timeout_s=5.0)
    assert connector.get_status()[0]["hostname"] == "cloudflare.com"
    assert connector.get_adoption()[0]["pct_pqc"] == 50.0
    assert connector.get_algorithms()[0]["selected_group"] == "X25519MLKEM768"

    exports = connector.export_handshake_assets({"server_hello": {}})
    assert exports["handshake-flow"] == "FLOW_TEX"
    assert exports["key-share-comparison"] == "KEY_TEX"
