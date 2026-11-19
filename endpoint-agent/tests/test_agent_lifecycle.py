from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import requests

AGENT = Path(__file__).resolve().parents[1]
if str(AGENT) not in sys.path:
    sys.path.insert(0, str(AGENT))

import agent_server
from scanner import run_scan


USER = {"user_id": "user-a", "org_id": "org-a", "tenant_id": "tenant-a", "role": "security_analyst"}


class Response:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class BackendSession:
    def __init__(self):
        self.uploaded = []

    def post(self, _url, **kwargs):
        report = kwargs["json"]
        self.uploaded.append(report)
        return Response({"scan_id": report["scan_id"], "scan_request_id": report.get("scan_request_id"),
                         "created_at": datetime.now(timezone.utc).isoformat()})


def _client():
    session = BackendSession()
    client = SimpleNamespace(
        config=SimpleNamespace(backend_url="http://backend.test", timeout_seconds=2, verify_tls=True),
        session=session,
    )
    return client, session


def test_scan_emits_only_real_collection_and_report_stages():
    stages = []
    report = run_scan(
        security_collector=lambda: {"system": {"name": "Test Windows"}, "coverage": {"firewall": "success"}, "facts": {}},
        software_collector=lambda: {"status": "success", "items": [], "packages": [{"name": "pkg", "version": "1", "ecosystem": "PyPI"}]},
        network_collector=lambda: {"status": "success", "items": []},
        osv_checker=lambda _package: {"status": "no_known_match", "matches": []},
        progress_callback=stages.append,
        scan_id="endpoint-" + "a" * 32,
    )

    assert report["scan_id"] == "endpoint-" + "a" * 32
    assert stages == [
        "Collecting Windows security information",
        "Collecting installed software",
        "Inspecting listening TCP ports",
        "Checking vulnerability intelligence",
        "Generating scan report",
    ]


def test_agent_persists_report_generated_upload_completed_and_auth_scope(tmp_path, monkeypatch):
    client, upload_session = _client()
    monkeypatch.setattr(agent_server.requests, "get", lambda *_args, **_kwargs: Response(USER))
    state_path = tmp_path / "scan_states.json"
    scan_started = threading.Event()
    continue_scan = threading.Event()

    def scan_runner(*, scan_id, progress_callback):
        progress_callback("Collecting Windows security information")
        scan_started.set()
        assert continue_scan.wait(timeout=3)
        progress_callback("Generating scan report")
        return {
            "scan_id": scan_id, "host_id": "host-a", "os_name": "Windows",
            "generated_at": datetime.now(timezone.utc).isoformat(), "findings": [],
            "coverage": {"firewall": "success"}, "summary": {"total_findings": 0, "counts": {}},
            "inventory": {},
        }

    server = agent_server.ThreadingHTTPServer(
        ("127.0.0.1", 0), agent_server.create_handler(client, scan_runner=scan_runner, state_path=state_path),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    local = requests.Session()
    local.trust_env = False
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        accepted = local.post(f"{base_url}/scans", headers={"Authorization": "Bearer test-token"}, timeout=3)
        assert accepted.status_code == 202
        scan_id = accepted.json()["scan_id"]
        request_id = accepted.json()["request_id"]
        assert request_id == accepted.json()["scan_request_id"]
        assert request_id != scan_id
        assert scan_started.wait(timeout=2)
        duplicate = local.post(f"{base_url}/scans", headers={"Authorization": "Bearer test-token"}, timeout=3)
        assert duplicate.status_code == 409
        continue_scan.set()

        deadline = time.monotonic() + 3
        state = {}
        while time.monotonic() < deadline:
            state_response = local.get(f"{base_url}/scans/{request_id}", headers={"Authorization": "Bearer test-token"}, timeout=3)
            state = state_response.json()
            if state.get("status") == "completed":
                break
            time.sleep(0.02)

        assert state["status"] == "completed"
        assert state["scan_request_id"] == request_id
        assert state["scan_id"] == scan_id
        assert state["backend_confirmed"] is True
        assert state["backend_scan_id"] == scan_id
        assert state["report_generated"] is True
        assert any(item["stage"] == "Uploading results" for item in state["progress_log"])
        assert upload_session.uploaded[0]["scan_id"] == scan_id
        assert upload_session.uploaded[0]["scan_request_id"] == request_id
        assert json.loads(state_path.read_text(encoding="utf-8"))[request_id]["status"] == "completed"

        monkeypatch.setattr(agent_server.requests, "get", lambda *_args, **_kwargs: Response({**USER, "user_id": "user-b"}))
        hidden = local.get(f"{base_url}/scans/{request_id}", headers={"Authorization": "Bearer other-token"}, timeout=3)
        assert hidden.json()["status"] == "unknown"
    finally:
        continue_scan.set()
        local.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_agent_marks_persisted_active_scan_interrupted_after_restart(tmp_path):
    path = tmp_path / "scan_states.json"
    path.write_text(json.dumps({"endpoint-abc": {"status": "running", "stage": "Inspecting listening TCP ports"}}), encoding="utf-8")

    states = agent_server._load_states(path)

    assert states["endpoint-abc"]["status"] == "interrupted"
    assert states["endpoint-abc"]["stage"] == "Interrupted"
    assert "restarted" in states["endpoint-abc"]["message"]


def test_agent_marks_upload_failure_without_claiming_completion(tmp_path, monkeypatch):
    class FailedResponse:
        def raise_for_status(self):
            raise requests.HTTPError("backend returned HTTP 503")

    class FailedUploadSession:
        def post(self, *_args, **_kwargs):
            return FailedResponse()

    client = SimpleNamespace(
        config=SimpleNamespace(backend_url="http://backend.test", timeout_seconds=2, verify_tls=True),
        session=FailedUploadSession(),
    )
    monkeypatch.setattr(agent_server.requests, "get", lambda *_args, **_kwargs: Response(USER))

    def scan_runner(*, scan_id, progress_callback):
        progress_callback("Generating scan report")
        return {"scan_id": scan_id, "host_id": "host-a", "os_name": "Windows",
                "generated_at": datetime.now(timezone.utc).isoformat(), "findings": [],
                "coverage": {}, "summary": {}, "inventory": {}}

    state_path = tmp_path / "scan_states.json"
    server = agent_server.ThreadingHTTPServer(
        ("127.0.0.1", 0), agent_server.create_handler(client, scan_runner=scan_runner, state_path=state_path),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    local = requests.Session()
    local.trust_env = False
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        accepted = local.post(f"{base_url}/scans", headers={"Authorization": "Bearer test-token"}, timeout=3)
        assert accepted.status_code == 202
        request_id = accepted.json()["request_id"]
        scan_id = accepted.json()["scan_id"]
        deadline = time.monotonic() + 3
        state = {}
        while time.monotonic() < deadline:
            state = local.get(f"{base_url}/scans/{request_id}",
                              headers={"Authorization": "Bearer test-token"}, timeout=3).json()
            if state.get("status") == "upload_failed":
                break
            time.sleep(0.02)
        assert state["status"] == "upload_failed"
        assert state["scan_request_id"] == request_id
        assert state["scan_id"] == scan_id
        assert state["report_generated"] is True
        assert state.get("backend_confirmed") is not True
        assert "503" in state["message"]
    finally:
        local.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
