from __future__ import annotations

import os
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient
from pymongo import MongoClient

import backend.app.database.connection as db_connection
import backend.app.main as app_module
import backend.app.routes.auth as auth_routes
import backend.app.security as security_module
from backend.app.database.init_db import initialize_database
from backend.app.intelligence import ingestion as intel_ingestion


MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27030")
TEST_DB_NAME = os.getenv("THREATGUARD_TEST_DB", f"threatguard_phase3_test_{uuid.uuid4().hex}")


class FakeResponse:
    def __init__(self, payload=None, status_code=200, text=""):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code
        self.text = text or ""

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("request failed", request=httpx.Request("GET", "https://example.com"), response=self)

    def json(self):
        return self._payload


class StaticClient:
    def __init__(self, payloads=None, exc=None):
        self.payloads = list(payloads or [])
        self.exc = exc

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def get(self, url, params=None, headers=None):
        if self.exc is not None:
            raise self.exc
        if not self.payloads:
            return FakeResponse({"vulnerabilities": []})
        return FakeResponse(self.payloads.pop(0))


@pytest.fixture
def intel_db():
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[TEST_DB_NAME]
    for collection_name in db.list_collection_names():
        db[collection_name].delete_many({})
    initialize_database(db)
    try:
        yield db
    finally:
        for collection_name in db.list_collection_names():
            db[collection_name].delete_many({})
        client.close()


def test_phase3_routes_are_present_and_nvd_ingestion_succeeds(monkeypatch, intel_db, create_test_user, login_test_user):
    monkeypatch.setattr(db_connection, "get_db", lambda: intel_db)
    monkeypatch.setattr(auth_routes, "get_db", lambda: intel_db)
    monkeypatch.setattr(security_module, "get_db", lambda: intel_db)
    monkeypatch.setattr(intel_ingestion, "get_db", lambda: intel_db)

    nvd_pages = [
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [{"lang": "en", "value": "Sample nvd description"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "version": "3.1"}}]},
                        "references": [{"url": "https://example.com/advisory1"}],
                        "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}]}]}],
                        "published": "2024-01-02T00:00:00.000Z",
                        "lastModified": "2024-01-03T00:00:00.000Z",
                    }
                }
            ]
        },
        {"vulnerabilities": []},
    ]
    monkeypatch.setattr(intel_ingestion.httpx, "Client", lambda *args, **kwargs: StaticClient(nvd_pages))

    create_test_user(
        intel_db,
        org_id="org-intel",
        tenant_id="tenant-intel-1",
        email="phase3-admin@example.com",
        role="security_analyst",
    )
    client = TestClient(app_module.app)
    headers = login_test_user(client, email="phase3-admin@example.com")

    route_paths = {route.path for route in app_module.app.routes}
    assert "/intelligence/nvd" in route_paths
    assert "/intelligence/cisa" in route_paths
    assert "/intelligence/sigma" in route_paths

    response = client.post("/intelligence/nvd", params={"url": "https://example.com/nvd.json", "page_size": 10}, headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["record_count"] == 1
    saved = intel_db["vulnerabilities"].find_one({"org_id": "org-intel", "tenant_id": "tenant-intel-1", "cve_id": "CVE-2024-0001"})
    assert saved is not None
    assert saved["severity"] == "CRITICAL"
    assert saved["source_id"] == "nvd"


def test_nvd_pagination_and_network_failure(monkeypatch, intel_db):
    monkeypatch.setattr(intel_ingestion, "get_db", lambda: intel_db)
    page_one = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2024-1111", "descriptions": [{"lang": "en", "value": "First"}], "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "version": "3.1"}}]}}},
            {"cve": {"id": "CVE-2024-2222", "descriptions": [{"lang": "en", "value": "Second"}], "metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "version": "3.0"}}]}}},
        ]
    }
    page_two = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2024-3333", "descriptions": [{"lang": "en", "value": "Third"}], "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH", "version": "4.0"}}]}}}
        ]
    }
    monkeypatch.setattr(intel_ingestion.httpx, "Client", lambda *args, **kwargs: StaticClient([page_one, page_two]))
    result = intel_ingestion.ingest_nvd("org-nvd", "tenant-nvd-a", page_size=2)
    assert result["status"] == "completed"
    assert result["record_count"] == 3
    assert intel_db["vulnerabilities"].count_documents({"org_id": "org-nvd", "tenant_id": "tenant-nvd-a"}) == 3

    monkeypatch.setattr(intel_ingestion.httpx, "Client", lambda *args, **kwargs: (_ for _ in ()).throw(httpx.RequestError("offline")))
    result = intel_ingestion.ingest_nvd("org-nvd", "tenant-nvd-b", page_size=2)
    assert result["status"] == "failed"
    assert "offline" in result["error"]


def test_cisa_kev_ingestion_merges_nvd_and_cisa_without_duplicates(monkeypatch, intel_db):
    monkeypatch.setattr(intel_ingestion, "get_db", lambda: intel_db)
    existing = {
        "org_id": "org-cisa",
        "tenant_id": "tenant-cisa-1",
        "cve_id": "CVE-2024-4242",
        "description": "NVD description",
        "severity": "HIGH",
        "references": ["https://nvd.example/advisory"],
        "cpe": ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"],
        "affected_products": ["vendor:product"],
        "source_provenance": [{"source_id": "nvd", "name": "NVD", "url": "https://nvd.example"}],
        "created_at": __import__("datetime").datetime.utcnow(),
        "updated_at": __import__("datetime").datetime.utcnow(),
    }
    intel_db["vulnerabilities"].insert_one(existing)

    cisa_payload = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-4242",
                "vendorProject": "Vendor",
                "product": "Product",
                "shortDescription": "CISA-specific description",
                "requiredAction": "Patch now",
                "dueDate": "2024-02-01T00:00:00.000Z",
                "knownRansomwareCampaignUse": "Yes",
                "dateAdded": "2024-01-08T00:00:00.000Z",
            }
        ]
    }
    monkeypatch.setattr(intel_ingestion.httpx, "Client", lambda *args, **kwargs: StaticClient([cisa_payload]))
    result = intel_ingestion.ingest_cisa_kev("org-cisa", "tenant-cisa-1")
    assert result["status"] == "completed"
    saved = intel_db["vulnerabilities"].find_one({"org_id": "org-cisa", "tenant_id": "tenant-cisa-1", "cve_id": "CVE-2024-4242"})
    assert saved is not None
    assert saved["description"] == "NVD description"
    assert len(saved["source_provenance"]) == 2
    assert intel_db["vulnerabilities"].count_documents({"org_id": "org-cisa", "tenant_id": "tenant-cisa-1", "cve_id": "CVE-2024-4242"}) == 1


def test_sigma_parsing_and_invalid_rule_handling(monkeypatch, intel_db):
    monkeypatch.setattr(intel_ingestion, "get_db", lambda: intel_db)
    valid_rule = """
    title: Sample Detection
    id: Sample.Rule
    status: experimental
    description: Detects suspicious behavior.
    logsource:
      category: process_creation
      product: windows
    detection:
      selection:
        Image|endswith: 'cmd.exe'
      condition: selection
    level: medium
    tags:
      - attack.t1059
      - attack.execution
    """
    invalid_rule = """
    title: Broken Rule
    detection:
      condition: invalid
    """
    raw_with_invalid = {"path": "rules/windows/process_creation.yml", "content": valid_rule}
    raw_invalid = {"path": "rules/windows/bad_rule.yml", "content": invalid_rule}

    class SigmaClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def get(self, url, params=None, headers=None):
            if url.endswith("bad_rule.yml"):
                return FakeResponse(text=invalid_rule)
            return FakeResponse(text=valid_rule)

    monkeypatch.setattr(intel_ingestion, "_discover_sigma_files", lambda repo, branch, max_rules=None: ["rules/windows/process_creation.yml", "rules/windows/bad_rule.yml"])
    monkeypatch.setattr(intel_ingestion.httpx, "Client", SigmaClient)
    result = intel_ingestion.ingest_sigma("org-sigma", "tenant-sigma-1", max_rules=10)
    assert result["status"] == "completed"
    assert result["record_count"] == 1
    saved = intel_db["detection_rules"].find_one({"org_id": "org-sigma", "tenant_id": "tenant-sigma-1", "rule_id": "Sample.Rule"})
    assert saved is not None
    assert saved["source_path"] == "rules/windows/process_creation.yml"
    assert saved["technique_refs"] == ["attack.t1059"]
    assert saved["sigma"].startswith("title:")


def test_org_and_tenant_isolation_and_job_tracking(monkeypatch, intel_db, create_test_user, login_test_user):
    monkeypatch.setattr(db_connection, "get_db", lambda: intel_db)
    monkeypatch.setattr(auth_routes, "get_db", lambda: intel_db)
    monkeypatch.setattr(security_module, "get_db", lambda: intel_db)
    monkeypatch.setattr(intel_ingestion, "get_db", lambda: intel_db)

    create_test_user(
        intel_db,
        org_id="org-iso",
        tenant_id="tenant-a",
        email="tenant-a@example.com",
        role="security_analyst",
    )
    create_test_user(
        intel_db,
        org_id="org-iso",
        tenant_id="tenant-b",
        email="tenant-b@example.com",
        role="security_analyst",
    )
    client = TestClient(app_module.app)
    headers_a = login_test_user(client, email="tenant-a@example.com")
    headers_b = login_test_user(client, email="tenant-b@example.com")

    payload = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-8888",
                "descriptions": [{"lang": "en", "value": "Tenant-scoped issue."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 6.5, "baseSeverity": "MEDIUM", "version": "3.1"}}]},
            }
        }]
    }
    monkeypatch.setattr(intel_ingestion.httpx, "Client", lambda *args, **kwargs: StaticClient([payload]))

    response_a = client.post("/intelligence/nvd", params={"url": "https://example.com/nvd-tenant-a.json", "page_size": 10}, headers=headers_a)
    response_b = client.post("/intelligence/nvd", params={"url": "https://example.com/nvd-tenant-b.json", "page_size": 10}, headers=headers_b)
    assert response_a.status_code == 200
    assert response_b.status_code == 200
    assert intel_db["vulnerabilities"].count_documents({"org_id": "org-iso", "tenant_id": "tenant-a"}) == 1
    assert intel_db["vulnerabilities"].count_documents({"org_id": "org-iso", "tenant_id": "tenant-b"}) == 1

    job = intel_db["ingestion_jobs"].find_one({"source_id": "nvd"})
    assert job is not None
    assert job["status"] in {"completed", "failed"}
