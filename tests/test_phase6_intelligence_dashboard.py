from __future__ import annotations

from frontend.intelligence_dashboard import fetch_payload, graphviz_source, page_count, safe_source_url, sanitize_evidence, search_params


class Response:
    def __init__(self, payload=None, *, status=200, invalid_json=False):
        self.payload = payload
        self.status_code = status
        self.ok = status < 400
        self.invalid_json = invalid_json

    def json(self):
        if self.invalid_json:
            raise ValueError("not json")
        return self.payload


def test_fetch_payload_uses_mock_api_and_propagates_api_errors():
    seen = []

    def request(method, path, **kwargs):
        seen.append((method, path, kwargs))
        return Response({"items": [], "total": 0})

    payload, error = fetch_payload(request, "/intelligence/search", params={"q": "test"})
    assert payload == {"items": [], "total": 0} and error is None
    assert seen[0] == ("GET", "/intelligence/search", {"params": {"q": "test"}})

    response = Response({"detail": "unauthorized"}, status=401)
    payload, error = fetch_payload(lambda *_a, **_k: response, "/intelligence/statistics")
    assert payload is None and error is response


def test_dashboard_query_pagination_and_url_secret_filtering():
    assert search_params("  CVE-1 ", ["cve", "sigma"], 2, 10) == {
        "q": "CVE-1", "record_type": ["cve", "sigma"], "page": 2, "page_size": 10,
    }
    assert page_count(0, 20) == 1
    assert page_count(21, 20) == 2
    assert safe_source_url("https://example.test/path?api_key=secret#token") == "https://example.test/path"
    assert safe_source_url("not a url") is None
    clean = sanitize_evidence({"source_url": "https://example.test/feed?api_key=secret",
                               "error": "failed at https://example.test/?token=hidden"})
    assert "secret" not in str(clean) and "hidden" not in str(clean)


def test_relationship_graph_distinguishes_official_and_inferred_edges():
    graph = graphviz_source({"record_type": "cve", "record_id": "CVE-1"}, [
        {"source": {"type": "cve", "id": "CVE-1"},
         "target": {"type": "technique", "id": "T1000"}, "type": "maps", "origin": "official_source"},
        {"source": {"type": "cve", "id": "CVE-1"},
         "target": {"type": "capec", "id": "CAPEC-9"}, "type": "related", "origin": "inferred"},
    ])
    assert "official_source" in graph and "inferred" in graph
    assert "style=\"dashed\"" in graph and "CVE-1" in graph and "CAPEC-9" in graph
