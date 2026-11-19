from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "endpoint-agent"
sys.path.insert(0, str(AGENT))

from api_client import ThreatGuardClient
from config import AgentConfig
from network_monitor import collect_listeners
from scanner import run_scan
from software_inventory import collect_software_inventory
from vulnerability_checker import query_osv
from windows_security import collect_windows_security
import backend.app.routes.endpoint as endpoint_routes
from backend.app.ai.context_manager import load_scanner_evidence
from backend.app.models_endpoint import EndpointScanUpload


class Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout, self.returncode, self.stderr = stdout, returncode, ""


def test_windows_security_unknown_and_success(monkeypatch):
    unknown = collect_windows_security(is_windows=True, runner=lambda *a, **k: Result(returncode=1))
    assert unknown["coverage"]["windows_security"] == "unknown"
    payload = {"caption": "Windows Test", "version": "10.0", "build": "1", "defender_available": True,
               "antivirus_enabled": False, "real_time_enabled": True, "signature_age": 1,
               "firewall": [{"Name": "Public", "Enabled": False}], "uac_enabled": True}
    got = collect_windows_security(is_windows=True, runner=lambda *a, **k: Result(json.dumps(payload)))
    assert got["system"]["name"] == "Windows Test"
    assert got["coverage"]["firewall"] == "success"


def test_software_inventory_and_listener_collectors_are_read_only():
    software = collect_software_inventory(is_windows=True, runner=lambda *a, **k: Result(json.dumps([{"name": "Example", "version": "1.0"}])))
    assert software == {"status": "success", "items": [{"name": "Example", "version": "1.0"}]}
    listeners = collect_listeners(is_windows=True, runner=lambda *a, **k: Result(json.dumps([{"local_address": "0.0.0.0", "local_port": 3389, "process_id": 4, "process_name": "rdp"}])))
    assert listeners["items"][0]["local_port"] == 3389
    assert collect_listeners(is_windows=False)["status"] == "unsupported"


def test_osv_exact_match_and_no_package_coordinates():
    class Response:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"vulns": [{"id": "GHSA-test", "aliases": ["CVE-2024-12345"], "summary": "Example issue"}]}
    class Session:
        def post(self, url, **kwargs):
            assert kwargs["json"]["version"] == "1.2.3"
            return Response()
    result = query_osv({"ecosystem": "PyPI", "name": "example", "version": "1.2.3"}, session=Session(), now=100)
    assert result["status"] == "vulnerable"
    assert result["matches"][0]["cve"] == "CVE-2024-12345"
    assert query_osv({"name": "display name", "version": "1"})["status"] == "requires_verification"


def test_scan_risk_and_serialization_are_evidence_based():
    security = {"system": {"name": "Windows Test"}, "coverage": {"defender": "success"},
                "facts": {"antivirus_enabled": False, "real_time_enabled": True, "firewall": [], "uac_enabled": True}}
    report = run_scan(security_collector=lambda: security,
                      software_collector=lambda: {"status": "success", "items": [{"name": "App", "version": "1"}]},
                      network_collector=lambda: {"status": "success", "items": []})
    validated = EndpointScanUpload.model_validate(report)
    assert report["findings"][0]["severity"] == "high"
    assert report["findings"][0]["evidence"] == {"antivirus_enabled": False}
    assert validated.scan_id.startswith("endpoint-")
    assert report["coverage"]["vulnerability_intelligence"] == "requires_verification"


def test_api_client_login_and_upload_use_bearer_and_same_idempotency_key():
    class Response:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"access_token": "jwt", "user": {"user_id": "u"}, "scan_id": "endpoint-abc"}
    class Session:
        def __init__(self): self.posts = []
        def post(self, url, **kwargs): self.posts.append((url, kwargs)); return Response()
    session = Session()
    client = ThreatGuardClient(AgentConfig("https://api.example", 3, True), session=lambda: session)
    client.login("a@example.test", "not-saved")
    payload = {"scan_id": "endpoint-abc"}
    client.upload_scan(payload)
    assert session.posts[0][1]["json"]["password"] == "not-saved"
    assert session.posts[1][1]["headers"]["Authorization"] == "Bearer jwt"
    assert session.posts[1][1]["json"]["scan_id"] == "endpoint-abc"


def test_endpoint_storage_is_idempotent_and_tenant_scoped(monkeypatch):
    user = {"org_id": "org-one", "tenant_id": "tenant-one", "user_id": "user-one", "role": "security_analyst"}
    other = {"org_id": "org-two", "tenant_id": "tenant-two", "user_id": "user-two", "role": "security_analyst"}
    class Collection:
        def __init__(self): self.items = []
        def find_one(self, query, sort=None):
            return next((item for item in self.items if all(item.get(key) == value for key, value in query.items())), None)
        def insert_one(self, document):
            document = dict(document)
            document["_id"] = str(len(self.items) + 1)
            self.items.append(document)
            return SimpleNamespace(inserted_id=document["_id"])
        def count_documents(self, query): return sum(all(item.get(key) == value for key, value in query.items()) for item in self.items)
        def find(self, query): return []
    class DB:
        def __init__(self): self.endpoint_scans = Collection(); self.audit_logs = Collection()
        def __getitem__(self, name): return getattr(self, name)
    test_db = DB()
    monkeypatch.setattr(endpoint_routes, "_db", lambda: test_db)
    payload = EndpointScanUpload(
        scan_id="endpoint-" + "a" * 32, host_id="host-one", os_name="Windows",
        generated_at=datetime.now(timezone.utc), findings=[], coverage={"defender": "unknown"}, inventory={},
    )
    first = endpoint_routes.upload_scan(payload, user)
    second = endpoint_routes.upload_scan(payload, user)
    assert first["scan_id"] == second["scan_id"]
    assert test_db.endpoint_scans.count_documents({"scan_id": payload.scan_id}) == 1
    with pytest.raises(HTTPException) as exc:
        endpoint_routes.get_scan(payload.scan_id, other)
    assert exc.value.status_code == 404
    with pytest.raises(Exception):
        EndpointScanUpload.model_validate({**payload.model_dump(), "surprise": "rejected"})


def test_dashboard_explains_disconnected_agent_without_fake_progress():
    source = (ROOT / "frontend" / "pages" / "07_endpoint_security.py").read_text(encoding="utf-8")
    assert "ThreatGuard Endpoint Agent is not connected. Start the local agent to perform a scan." in source
    assert "Refresh scan status" in source
    assert "running" in source and "completed" in source


def test_chat_retrieval_scopes_endpoint_findings_to_user_and_tenant():
    class Cursor(list):
        def sort(self, *_args): return self
        def limit(self, amount): return self[:amount]
    class Collection:
        def __init__(self, rows): self.rows = rows
        def find(self, query, _projection): return Cursor([row for row in self.rows if all(row.get(k) == v for k, v in query.items())])
    own = {"org_id": "o", "tenant_id": "t", "user_id": "u1", "scan_id": "s1", "created_at": datetime.now(timezone.utc),
           "findings": [{"title": "My evidence", "severity": "high", "evidence": {"enabled": False}}]}
    other = {**own, "user_id": "u2", "scan_id": "s2", "findings": [{"title": "Other user's evidence"}]}
    class DB:
        def __getitem__(self, name):
            return Collection([]) if name == "scan_results" else Collection([own, other])
    result = load_scanner_evidence(DB(), org_id="o", tenant_id="t", user_id="u1")
    assert [item["scan_id"] for item in result] == ["s1"]
    assert result[0]["findings"][0]["title"] == "My evidence"
