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
TEST_DB_NAME = os.getenv("THREATGUARD_TEST_DB", f"threatguard_intel_test_{uuid.uuid4().hex}")


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class FailingClient:
    def __init__(self, exc):
        self.exc = exc

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def get(self, url):
        raise self.exc


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


def _mock_http_client(payload=None, exc=None):
    class MockClient:
        def __init__(self, *_args, **_kwargs):
            self.payload = payload
            self.exc = exc

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def get(self, url):
            if self.exc is not None:
                raise self.exc
            return FakeResponse(self.payload)

    return MockClient


def test_intelligence_routes_registered_and_mitre_ingestion_works(
    monkeypatch, intel_db, create_test_user, login_test_user
):
    monkeypatch.setattr(db_connection, "get_db", lambda: intel_db)
    monkeypatch.setattr(auth_routes, "get_db", lambda: intel_db)
    monkeypatch.setattr(security_module, "get_db", lambda: intel_db)
    monkeypatch.setattr(intel_ingestion, "get_db", lambda: intel_db)

    mitre_payload = {
        "objects": [
            {
                "type": "attack-pattern",
                "name": "Phishing",
                "description": "Phishing description",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1566", "url": "https://attack.mitre.org/techniques/T1566/"}
                ],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "Initial Access"}],
                "x_mitre_platforms": ["Windows"],
            }
        ]
    }
    monkeypatch.setattr(intel_ingestion.httpx, "Client", _mock_http_client(payload=mitre_payload))

    create_test_user(
        intel_db,
        org_id="org-intel",
        tenant_id="tenant-intel-1",
        email="intel-admin@example.com",
        role="security_analyst",
    )
    client = TestClient(app_module.app)
    headers = login_test_user(client, email="intel-admin@example.com")

    route_paths = {route.path for route in app_module.app.routes}
    assert "/intelligence/mitre" in route_paths
    assert "/intelligence/capec" in route_paths

    response = client.post(
        "/intelligence/mitre",
        params={"url": "https://example.com/mitre.json"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["status"] == "completed"
    assert result["record_count"] == 1

    saved = list(intel_db["attack_techniques"].find({"org_id": "org-intel", "tenant_id": "tenant-intel-1"}))
    assert len(saved) == 1
    assert saved[0]["technique_id"] == "T1566"

    cross_tenant = {
        "org_id": "org-intel",
        "tenant_id": "tenant-intel-2",
        "technique_id": "T1566",
        "name": "Phishing other tenant",
        "description": "Other tenant copy",
        "tactics": ["Initial Access"],
        "platforms": ["Windows"],
        "references": [],
        "created_at": __import__("datetime").datetime.utcnow(),
        "updated_at": __import__("datetime").datetime.utcnow(),
    }
    intel_db["attack_techniques"].insert_one(cross_tenant)
    assert intel_db["attack_techniques"].count_documents({"org_id": "org-intel", "tenant_id": "tenant-intel-1"}) == 1

    second_response = client.post(
        "/intelligence/mitre",
        params={"url": "https://example.com/mitre.json"},
        headers=headers,
    )
    assert second_response.status_code == 200, second_response.text
    assert intel_db["attack_techniques"].count_documents({"org_id": "org-intel", "tenant_id": "tenant-intel-1"}) == 1


def test_capec_ingestion_scopes_and_handles_network_failures(
    monkeypatch, intel_db, create_test_user, login_test_user
):
    monkeypatch.setattr(db_connection, "get_db", lambda: intel_db)
    monkeypatch.setattr(auth_routes, "get_db", lambda: intel_db)
    monkeypatch.setattr(security_module, "get_db", lambda: intel_db)
    monkeypatch.setattr(intel_ingestion, "get_db", lambda: intel_db)

    capec_payload = {
        "attack-patterns": [
            {"capec-id": "98", "name": "Phishing", "summary": "A social engineering technique."}
        ]
    }
    monkeypatch.setattr(intel_ingestion.httpx, "Client", _mock_http_client(payload=capec_payload))

    create_test_user(
        intel_db,
        org_id="org-intel",
        tenant_id="tenant-intel-1",
        email="intel-capec@example.com",
        role="security_analyst",
    )
    client = TestClient(app_module.app)
    headers = login_test_user(client, email="intel-capec@example.com")

    response = client.post(
        "/intelligence/capec",
        params={"url": "https://example.com/capec.json"},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "completed"
    assert data["record_count"] == 1
    assert intel_db["attack_patterns"].count_documents({"org_id": "org-intel", "tenant_id": "tenant-intel-1"}) == 1

    intel_db["attack_patterns"].insert_one(
        {
            "org_id": "org-intel",
            "tenant_id": "tenant-intel-2",
            "pattern_id": "CAPEC-98",
            "name": "Phishing other tenant",
            "description": "Other tenant copy",
            "technique_ids": [],
            "references": [],
            "created_at": __import__("datetime").datetime.utcnow(),
            "updated_at": __import__("datetime").datetime.utcnow(),
        }
    )
    assert intel_db["attack_patterns"].count_documents({"org_id": "org-intel", "tenant_id": "tenant-intel-1"}) == 1

    second_response = client.post(
        "/intelligence/capec",
        params={"url": "https://example.com/capec.json"},
        headers=headers,
    )
    assert second_response.status_code == 200, second_response.text
    assert intel_db["attack_patterns"].count_documents({"org_id": "org-intel", "tenant_id": "tenant-intel-1"}) == 1

    monkeypatch.setattr(intel_ingestion.httpx, "Client", _mock_http_client(exc=httpx.RequestError("offline")))
    failed_response = client.post(
        "/intelligence/capec",
        params={"url": "https://example.com/network-failure.json"},
        headers=headers,
    )
    assert failed_response.status_code == 200, failed_response.text
    failed_payload = failed_response.json()
    assert failed_payload["status"] == "failed"
    assert "offline" in failed_payload["error"]
    failed_job = intel_db["ingestion_jobs"].find_one({"source_id": "capec", "status": "failed"})
    assert failed_job is not None
