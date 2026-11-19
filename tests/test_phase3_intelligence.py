from __future__ import annotations

import os
import io
import contextlib
import uuid
import zipfile

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
    assert result["inserted"] == 3
    assert result["updated"] == 0
    assert intel_db["vulnerabilities"].count_documents({"org_id": "org-nvd", "tenant_id": "tenant-nvd-a"}) == 3

    monkeypatch.setattr(intel_ingestion.httpx, "Client", lambda *args, **kwargs: StaticClient([page_one, page_two]))
    result = intel_ingestion.ingest_nvd("org-nvd", "tenant-nvd-a", page_size=2)
    assert result["inserted"] == 0
    assert result["updated"] == 3

    monkeypatch.setattr(intel_ingestion.httpx, "Client", lambda *args, **kwargs: (_ for _ in ()).throw(httpx.RequestError("offline")))
    result = intel_ingestion.ingest_nvd("org-nvd", "tenant-nvd-b", page_size=2)
    assert result["status"] == "failed"
    assert "offline" in result["error"]


def test_nvd_initial_import_limit_stops_before_next_page(monkeypatch, intel_db):
    monkeypatch.setattr(intel_ingestion, "get_db", lambda: intel_db)
    calls = []
    payload = {"totalResults": 10, "vulnerabilities": [
        {"cve": {"id": "CVE-2026-7001", "descriptions": [{"lang": "en", "value": "First"}]}},
        {"cve": {"id": "CVE-2026-7002", "descriptions": [{"lang": "en", "value": "Second"}]}},
    ]}

    class CaptureClient(StaticClient):
        def get(self, url, params=None, headers=None):
            calls.append(dict(params or {}))
            return FakeResponse(payload)

    monkeypatch.setattr(intel_ingestion.httpx, "Client", lambda *args, **kwargs: CaptureClient())
    result = intel_ingestion.ingest_nvd("org-limit", "tenant-limit", page_size=2,
                                        max_records=1, request_delay=0,
                                        last_modified_after="2026-01-01T00:00:00Z",
                                        last_modified_before="2026-01-02T00:00:00Z")
    assert result["status"] == "completed"
    assert result["record_count"] == 1
    assert result["inserted"] == 1
    assert result["limited"] is True
    assert len(calls) == 1
    assert calls[0]["lastModStartDate"].startswith("2026-01-01")
    assert calls[0]["lastModEndDate"].startswith("2026-01-02")
    assert intel_db["vulnerabilities"].count_documents({"org_id": "org-limit", "tenant_id": "tenant-limit"}) == 1


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
    assert saved["known_ransomware_campaign_use"] is True
    assert result["inserted"] == 0
    assert result["updated"] == 1
    assert len(saved["source_provenance"]) == 2
    assert intel_db["vulnerabilities"].count_documents({"org_id": "org-cisa", "tenant_id": "tenant-cisa-1", "cve_id": "CVE-2024-4242"}) == 1


def test_cisa_unknown_ransomware_value_is_not_truthy_and_not_a_date():
    record = intel_ingestion._build_cisa_record(
        "org", "tenant", {"cveID": "CVE-2024-5555", "dateAdded": "2024-03-01T00:00:00Z",
                           "knownRansomwareCampaignUse": "Unknown"},
        "https://www.cisa.gov/kev.json",
    )
    assert record["known_ransomware_campaign_use"] is None
    assert record["ransomware_campaign_use_source_value"] == "Unknown"
    assert record["cisa_date_added"].isoformat().startswith("2024-03-01")


def test_capec_official_xml_archive_parser_preserves_ids_and_explicit_attack_mappings():
    xml = b'''<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
      <Attack_Patterns><Attack_Pattern ID="66" Name="SQL Injection">
        <Description>Injected SQL attack pattern.</Description><Taxonomy_Mappings>
          <Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>T1190</Entry_ID></Taxonomy_Mapping>
        </Taxonomy_Mappings>
      </Attack_Pattern><Attack_Pattern ID="67" Name="Retired Pattern" Status="Deprecated">
        <Description>Deprecated source record.</Description>
      </Attack_Pattern></Attack_Patterns>
    </Attack_Pattern_Catalog>'''
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("2000.xml", xml)
    item = intel_ingestion._capec_xml_items(archive.getvalue())[0]
    assert len(intel_ingestion._capec_xml_items(archive.getvalue())) == 1
    record = intel_ingestion._process_capec_items([item])[0]
    assert record["pattern_id"] == "CAPEC-66"
    assert record["name"] == "SQL Injection"
    assert record["description"] == "Injected SQL attack pattern."
    assert record["technique_ids"] == ["T1190"]
    assert record["references"] == ["https://capec.mitre.org/data/definitions/66.html"]


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
        instances = 0

        def __init__(self, *args, **kwargs):
            type(self).instances += 1

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
    assert result["inserted"] == 1
    assert result["skipped"] == 1
    assert SigmaClient.instances == 1
    saved = intel_db["detection_rules"].find_one({"org_id": "org-sigma", "tenant_id": "tenant-sigma-1", "rule_id": "Sample.Rule"})
    assert saved is not None
    assert saved["source_path"] == "rules/windows/process_creation.yml"
    assert saved["technique_refs"] == ["attack.t1059"]
    assert saved["sigma"].startswith("title:")


def test_sigma_archive_fallback_is_disk_backed_and_applies_rule_cap(monkeypatch):
    archive_data = io.BytesIO()
    with zipfile.ZipFile(archive_data, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("sigma-master/rules/windows/one.yml", "title: one")
        archive.writestr("sigma-master/rules/windows/two.yml", "title: two")

    class StreamResponse:
        def raise_for_status(self):
            return None

        def iter_bytes(self, _size):
            yield archive_data.getvalue()

    monkeypatch.setattr(intel_ingestion.httpx, "stream",
                        lambda *args, **kwargs: contextlib.nullcontext(StreamResponse()))
    path, root, files = intel_ingestion._download_sigma_archive("SigmaHQ/sigma", "master", 1)
    try:
        assert root == "sigma-master"
        assert files == ["rules/windows/one.yml"]
        with zipfile.ZipFile(path) as archive:
            assert archive.read(f"{root}/{files[0]}") == b"title: one"
    finally:
        os.unlink(path)


def test_sigma_tree_discovery_excludes_repository_test_fixtures(monkeypatch):
    class TreeClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def get(self, url, headers=None):
            return FakeResponse({"tree": [
                {"path": "rules/windows/valid.yml", "type": "blob"},
                {"path": "regression_data/rules/windows/fixture/info.yml", "type": "blob"},
                {"path": "rules/windows/readme.md", "type": "blob"},
            ]})

    monkeypatch.setattr(intel_ingestion.httpx, "Client", lambda *args, **kwargs: TreeClient())
    assert intel_ingestion._discover_sigma_files("SigmaHQ/sigma", "master", 100) == ["rules/windows/valid.yml"]


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
