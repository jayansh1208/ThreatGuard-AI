from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.intelligence.search import (
    get_intelligence_record,
    intelligence_statistics,
    list_relationships,
    search_intelligence,
)
from backend.app.intelligence.ingestion import _process_capec_items


class Cursor(list):
    def batch_size(self, _size):
        return self

    def sort(self, field, direction=1):
        return Cursor(sorted(self, key=lambda row: row.get(field), reverse=direction < 0))

    def limit(self, size):
        return Cursor(self[:size])


class Collection:
    def __init__(self, rows):
        self.rows = rows

    def find(self, query, _projection=None):
        return Cursor([dict(row) for row in self.rows if _matches(row, query)])

    def find_one(self, query, _projection=None):
        return next((dict(row) for row in self.rows if _matches(row, query)), None)

    def count_documents(self, query):
        return len(self.find(query))


class FakeDB(dict):
    def __getitem__(self, key):
        return super().__getitem__(key)


def _matches(row, query):
    for key, value in query.items():
        if key == "$or":
            if not any(_matches(row, clause) for clause in value):
                return False
        elif key == "$and":
            if not all(_matches(row, clause) for clause in value):
                return False
        elif isinstance(row.get(key), list) and value in row.get(key):
            continue
        elif row.get(key) != value:
            return False
    return True


class SemanticProvider:
    model_name = "test"
    dimension = 2

    def embed(self, texts):
        return [[1.0, 0.0] if any(word in text.lower() for word in ("cryptographic", "cipher", "weakness"))
                else [0.0, 1.0] for text in texts]


class OfflineProviderUnavailable:
    def embed(self, _texts):
        raise RuntimeError("embedding model unavailable in offline test")


def sample_db():
    db = FakeDB()
    db["vulnerabilities"] = Collection([
        {"org_id": "o1", "tenant_id": "t1", "cve_id": "CVE-2026-1000",
         "description": "A cryptographic weakness allows remote compromise", "severity": "high"},
        {"org_id": "o2", "tenant_id": "t2", "cve_id": "CVE-2026-1001",
         "description": "A cryptographic cipher weakness in another tenant", "severity": "critical"},
        {"org_id": "o2", "tenant_id": "t1", "cve_id": "CVE-2026-1002",
         "description": "A cryptographic weakness in another organization", "severity": "medium"},
    ])
    db["attack_techniques"] = Collection([
        {"org_id": "o1", "tenant_id": "t1", "technique_id": "T1566",
         "name": "Phishing", "description": "Sends deceptive messages"},
    ])
    db["attack_patterns"] = Collection([{
        "org_id": "o1", "tenant_id": "t1", "pattern_id": "CAPEC-98",
        "name": "Phishing", "description": "Social engineering attack pattern", "technique_ids": [],
    }])
    db["detection_rules"] = Collection([
        {"org_id": "o1", "tenant_id": "t1", "rule_id": "sigma-1", "title": "Detect phishing",
         "description": "Detects malicious email", "technique_refs": ["attack.t1566"]},
    ])
    db["threat_relationships"] = Collection([])
    return db


def test_hybrid_search_finds_semantic_match_and_keeps_tenant_scope():
    result = search_intelligence(sample_db(), org_id="o1", tenant_id="t1",
                                  query="cipher weakness", provider=SemanticProvider())
    assert result["search_mode"] == "hybrid"
    assert result["total"] == 1
    assert result["items"][0]["record_id"] == "CVE-2026-1000"
    assert result["items"][0]["semantic_score"] == 1.0


def test_search_paginates_and_returns_keyword_without_embedding_provider():
    db = sample_db()
    result = search_intelligence(db, org_id="o1", tenant_id="t1", query="phishing",
                                 page=1, page_size=1, provider=OfflineProviderUnavailable())
    assert result["search_mode"] == "keyword"
    assert result["total"] >= 1
    assert len(result["items"]) == 1


@pytest.mark.parametrize("record_type,query,expected_id", [
    ("cve", "CVE-2026-1000", "CVE-2026-1000"),
    ("technique", "phishing", "T1566"),
    ("capec", "phishing", "CAPEC-98"),
    ("sigma", "phishing", "sigma-1"),
])
def test_keyword_search_covers_each_intelligence_type(record_type, query, expected_id):
    result = search_intelligence(sample_db(), org_id="o1", tenant_id="t1", query=query,
                                 record_types=[record_type], provider=OfflineProviderUnavailable())
    assert result["total"] == 1
    assert result["items"][0]["record_type"] == record_type
    assert result["items"][0]["record_id"] == expected_id


def test_details_and_official_sigma_technique_relationship_have_provenance():
    db = sample_db()
    record = get_intelligence_record(db, org_id="o1", tenant_id="t1",
                                     record_type="sigma", record_id="sigma-1")
    assert record["title"] == "Detect phishing"
    result = list_relationships(db, org_id="o1", tenant_id="t1", record_type="sigma",
                                record_id="sigma-1")
    assert result["total"] == 1
    relation = result["items"][0]
    assert relation["origin"] == "official_source"
    assert relation["inferred"] is False
    assert relation["evidence"] == {"field": "technique_refs", "value": "attack.t1566",
                                     "source_references": []}


def test_statistics_count_only_requested_tenant():
    stats = intelligence_statistics(sample_db(), org_id="o1", tenant_id="t1")
    assert stats["counts"]["cve"] == 1
    assert stats["counts"]["technique"] == 1
    assert stats["total_records"] == 4


def test_persisted_relationships_are_labeled_as_inferred_with_evidence():
    db = sample_db()
    db["threat_relationships"] = Collection([{
        "org_id": "o1", "tenant_id": "t1", "relationship_id": "rel-1",
        "source_record_id": "CVE-2026-1000", "target_record_id": "T1566",
        "type": "related_to", "description": "Analyst linked these records based on the cited report.",
        "inferred": True,
    }])
    relation = list_relationships(db, org_id="o1", tenant_id="t1", record_type="cve",
                                  record_id="CVE-2026-1000")["items"][0]
    assert relation["origin"] == "inferred"
    assert relation["evidence"] == "Analyst linked these records based on the cited report."


def test_technique_relationships_include_reverse_sigma_and_capec_source_references():
    db = sample_db()
    db["detection_rules"].rows[0]["source_url"] = "https://github.com/SigmaHQ/sigma/rule.yml"
    db["attack_patterns"] = Collection([{
        "org_id": "o1", "tenant_id": "t1", "pattern_id": "CAPEC-98",
        "name": "Phishing", "technique_ids": ["T1566"],
        "references": ["https://capec.mitre.org/data/definitions/98.html"],
    }])
    result = list_relationships(db, org_id="o1", tenant_id="t1", record_type="technique",
                                record_id="T1566")
    assert result["total"] == 2
    refs = {relation["source"]["type"]: relation["source_references"] for relation in result["items"]}
    assert refs["sigma"] == ["https://github.com/SigmaHQ/sigma/rule.yml"]
    assert refs["capec"] == ["https://capec.mitre.org/data/definitions/98.html"]


def test_capec_ingestion_keeps_only_explicit_technique_mappings_and_references():
    record = _process_capec_items([{
        "capec-id": "98", "name": "Phishing", "summary": "Social engineering",
        "related_techniques": [{"technique_id": "t1566"}, {"id": "not-an-attack-id"}],
        "references": [{"url": "https://capec.mitre.org/data/definitions/98.html"}],
    }])[0]
    assert record["technique_ids"] == ["T1566"]
    assert record["references"] == ["https://capec.mitre.org/data/definitions/98.html"]


@pytest.fixture
def api_client(monkeypatch):
    import backend.app.database.connection as db_connection
    import backend.app.main as app_module
    import backend.app.routes.intelligence as intelligence_routes
    import backend.app.security as security

    db = sample_db()
    db["users"] = Collection([{
        "user_id": "user-1", "org_id": "o1", "tenant_id": "t1", "email": "analyst@example.test",
        "role": "security_analyst", "status": "active",
    }])
    db["revoked_tokens"] = Collection([])
    db["threat_relationships"] = Collection([{
        "org_id": "o1", "tenant_id": "t1", "relationship_id": "rel-1",
        "source_record_id": "sigma-1", "target_record_id": "CVE-2026-1000",
        "type": "related_to", "description": "Analyst documented a shared incident report.",
        "inferred": True,
    }])
    monkeypatch.setattr(security, "get_db", lambda: db)
    monkeypatch.setattr(db_connection, "get_db", lambda: db)
    monkeypatch.setattr(intelligence_routes, "get_db", lambda: db)
    for name in ("ingest_mitre_attack", "ingest_capec", "ingest_nvd", "ingest_cisa_kev", "ingest_sigma"):
        monkeypatch.setattr(intelligence_routes, name,
                            lambda *args, **kwargs: {"status": "completed", "record_count": 0})
    real_search = intelligence_routes.search_intelligence

    class ApiSemanticProvider(SemanticProvider):
        def embed(self, texts):
            vectors = []
            for text in texts:
                lowered = text.lower()
                if "no matching indicator" in lowered:
                    vectors.append([0.0, -1.0])
                elif any(word in lowered for word in ("cryptographic", "cipher", "weakness")):
                    vectors.append([1.0, 0.0])
                else:
                    vectors.append([0.0, 1.0])
            return vectors

    monkeypatch.setattr(intelligence_routes, "search_intelligence",
                        lambda *args, **kwargs: real_search(*args, **{**kwargs, "provider": ApiSemanticProvider()}))
    from backend.app.security import create_access_token
    token = create_access_token(user_id="user-1", org_id="o1", tenant_id="t1",
                                role="security_analyst", email="analyst@example.test")
    return TestClient(app_module.app), {"Authorization": f"Bearer {token}"}


def test_intelligence_api_requires_bearer_jwt_and_swagger_declares_bearer(api_client):
    client, headers = api_client
    endpoints = [
        ("/intelligence/search?q=phishing", "get"),
        ("/intelligence/records/sigma/sigma-1", "get"),
        ("/intelligence/records/sigma/sigma-1/relationships", "get"),
        ("/intelligence/statistics", "get"),
        ("/intelligence/mitre", "post"),
        ("/intelligence/capec", "post"),
        ("/intelligence/nvd", "post"),
        ("/intelligence/cisa", "post"),
        ("/intelligence/sigma", "post"),
    ]
    for path, method in endpoints:
        call = getattr(client, method)
        assert call(path).status_code == 401
        assert call(path, headers={"Authorization": "Bearer invalid"}).status_code == 401
        assert call(path, headers=headers).status_code == 200

    openapi = client.get("/openapi.json").json()
    scheme = openapi["components"]["securitySchemes"]["HTTPBearer"]
    assert scheme == {"type": "http", "scheme": "bearer"}
    for path, method in endpoints:
        template_path = path.split("?")[0].replace("/records/sigma/", "/records/{record_type}/")
        template_path = template_path.replace("sigma-1", "{record_id}")
        assert openapi["paths"][template_path][method]["security"] == [{"HTTPBearer": []}]


def test_authenticated_search_pagination_empty_results_and_validation(api_client):
    client, headers = api_client
    first = client.get("/intelligence/search", params={"q": "phishing", "page_size": 1}, headers=headers)
    second = client.get("/intelligence/search", params={"q": "phishing", "page": 2, "page_size": 1}, headers=headers)
    assert first.status_code == second.status_code == 200
    assert first.json()["total"] == 3
    assert len(first.json()["items"]) == len(second.json()["items"]) == 1
    assert first.json()["items"][0]["record_id"] != second.json()["items"][0]["record_id"]
    empty = client.get("/intelligence/search", params={"q": "no matching indicator"}, headers=headers)
    assert empty.status_code == 200
    assert empty.json()["items"] == [] and empty.json()["total"] == 0
    assert client.get("/intelligence/search", params={"q": "x", "page": 101}, headers=headers).status_code == 422
    assert client.get("/intelligence/search", params={"q": "x", "record_type": "unknown"}, headers=headers).status_code == 400


def test_authenticated_record_relationship_and_statistics_are_tenant_scoped(api_client):
    client, headers = api_client
    record = client.get("/intelligence/records/sigma/sigma-1", headers=headers)
    hidden = client.get("/intelligence/records/cve/CVE-2026-1001", headers=headers)
    assert record.status_code == 200 and record.json()["record_id"] == "sigma-1"
    assert hidden.status_code == 404

    relations = client.get("/intelligence/records/sigma/sigma-1/relationships", headers=headers)
    assert relations.status_code == 200
    origins = {item["origin"] for item in relations.json()["items"]}
    assert origins == {"official_source", "inferred"}
    inferred = client.get("/intelligence/records/sigma/sigma-1/relationships",
                          params={"inferred": "true"}, headers=headers)
    assert inferred.json()["total"] == 1
    assert inferred.json()["items"][0]["evidence"] == "Analyst documented a shared incident report."

    stats = client.get("/intelligence/statistics", headers=headers)
    assert stats.status_code == 200
    assert stats.json()["counts"]["cve"] == 1
    assert stats.json()["counts"]["relationships"] == 1
