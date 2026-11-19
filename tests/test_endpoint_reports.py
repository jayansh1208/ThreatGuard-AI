from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
if str(FRONTEND) not in sys.path:
    sys.path.insert(0, str(FRONTEND))

from endpoint_reports import csv_findings, json_report, text_report  # noqa: E402


def _stored_scan(scan_id: str, title: str) -> dict:
    return {
        "scan_id": scan_id,
        "host_id": "demo-host",
        "os_name": "Windows 11",
        "created_at": "2026-11-20T10:00:00+00:00",
        "generated_at": "2026-11-20T09:59:00+00:00",
        "summary": {"total_findings": 1, "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0}},
        "coverage": {"firewall": "success", "software_inventory": "success"},
        "findings": [{
            "finding_id": f"finding-{scan_id}", "severity": "high", "title": title,
            "category": "configuration", "affected_component": "Windows Firewall",
            "evidence": {"profile": "Public", "enabled": False},
            "remediation": "Review the firewall policy.",
        }],
        "inventory": {"listeners": [{"local_port": 3389}]},
    }


def test_exports_are_built_from_the_selected_scan_record():
    selected = _stored_scan("endpoint-selected", "Selected scan finding")
    older = _stored_scan("endpoint-older", "Older scan finding")

    txt = text_report(selected)
    exported_json = json.loads(json_report(selected))
    exported_csv = list(csv.DictReader(io.StringIO(csv_findings(selected))))

    assert "Scan ID: endpoint-selected" in txt
    assert "Selected scan finding" in txt
    assert "Older scan finding" not in txt
    assert exported_json["scan_id"] == selected["scan_id"]
    assert exported_json["findings"][0]["title"] == "Selected scan finding"
    assert exported_csv[0]["finding_id"] == "finding-endpoint-selected"
    assert exported_csv[0]["title"] == "Selected scan finding"
    assert older["scan_id"] not in txt


def test_empty_findings_still_generate_a_real_report_and_csv_header():
    selected = _stored_scan("endpoint-empty", "Unused")
    selected["findings"] = []
    selected["summary"]["total_findings"] = 0

    assert "No findings were reported by this scan." in text_report(selected)
    assert list(csv.DictReader(io.StringIO(csv_findings(selected)))) == []
    assert "finding_id" in csv_findings(selected).splitlines()[0]


def test_endpoint_page_shows_success_only_for_the_matching_backend_scan(monkeypatch):
    import requests
    import app_common
    from streamlit.testing.v1 import AppTest

    scan = _stored_scan("endpoint-selected", "Selected scan finding")
    user = {"user_id": "user-a", "org_id": "org-a", "tenant_id": "tenant-a", "role": "security_analyst"}

    request_id = "request-" + "a" * 32

    class ApiResponse:
        def __init__(self, payload=None, status_code=200):
            self.payload = payload
            self.status_code = status_code
            self.ok = status_code < 400
            self.text = "not found" if status_code == 404 else ""

        def json(self):
            return self.payload

    def api_request(_method, path, **_kwargs):
        if path == "/endpoint/scans":
            return ApiResponse({"items": [scan], "total": 1})
        if path == f"/endpoint/scans/by-request/{request_id}":
            return ApiResponse({**scan, "scan_request_id": request_id})
        if path == f"/endpoint/scans/{scan['scan_id']}":
            return ApiResponse(scan)
        raise AssertionError(f"Unexpected API request: {path}")

    monkeypatch.setattr(app_common, "current_user", lambda: user)
    monkeypatch.setattr(app_common, "api_request", api_request)
    monkeypatch.setattr(requests, "get", lambda url, **_kwargs: ApiResponse(
        {"connected": True} if url.endswith("/health") else {
            "scan_id": scan["scan_id"], "scan_request_id": request_id,
            "backend_scan_id": scan["scan_id"], "status": "completed", "backend_confirmed": True,
            "progress_log": [],
        }
    ))

    app = AppTest.from_file(str(FRONTEND / "pages" / "07_endpoint_security.py"))
    app.session_state["endpoint_scan_request_id"] = request_id
    app.session_state["endpoint_scan_id"] = scan["scan_id"]
    app.session_state["endpoint_scan_state"] = {
        "scan_id": scan["scan_id"], "backend_scan_id": scan["scan_id"],
        "scan_request_id": request_id, "status": "completed", "backend_confirmed": True,
    }
    app.run()

    assert not app.exception
    assert app.session_state["endpoint_success_popup_shown"] == scan["scan_id"]
    source = (FRONTEND / "pages" / "07_endpoint_security.py").read_text(encoding="utf-8-sig")
    assert '"Security Scan Completed Successfully!"' in source
    assert any("Selected report scan ID" in element.value and scan["scan_id"] in element.value for element in app.markdown)
    assert "Download TXT Report" in source
    assert "Download JSON Report" in source
    assert "Download CSV Findings" in source


def test_missing_report_is_bounded_and_retry_does_not_start_a_scan(monkeypatch):
    import requests
    import app_common
    from streamlit.testing.v1 import AppTest

    scan_id = "endpoint-" + "d" * 32
    request_id = "request-" + "e" * 32
    user = {"user_id": "user-a", "org_id": "org-a", "tenant_id": "tenant-a", "role": "security_analyst"}

    class ApiResponse:
        def __init__(self, payload=None, status_code=404):
            self.payload, self.status_code, self.ok = payload, status_code, status_code < 400
            self.text = "not found"
        def json(self): return self.payload

    calls = []
    scan_posts = []
    def api_request(method, path, **_kwargs):
        calls.append((method, path))
        if path == "/endpoint/scans":
            return ApiResponse({"items": [], "total": 0}, status_code=200)
        if path in {f"/endpoint/scans/by-request/{request_id}", f"/endpoint/scans/{scan_id}"}:
            return ApiResponse()
        raise AssertionError(f"Unexpected API request: {path}")

    monkeypatch.setattr(app_common, "current_user", lambda: user)
    monkeypatch.setattr(app_common, "api_request", api_request)
    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: scan_posts.append((args, kwargs)))
    monkeypatch.setattr(requests, "get", lambda url, **_kwargs: ApiResponse(
        {"connected": True} if url.endswith("/health") else {
            "scan_id": scan_id, "backend_scan_id": scan_id, "scan_request_id": request_id,
            "status": "completed", "backend_confirmed": True, "endpoint_id": "host-a",
        }, status_code=200,
    ))

    app = AppTest.from_file(str(FRONTEND / "pages" / "07_endpoint_security.py"))
    app.session_state["endpoint_scan_request_id"] = request_id
    app.session_state["endpoint_scan_id"] = scan_id
    app.session_state["endpoint_scan_state"] = {
        "scan_id": scan_id, "backend_scan_id": scan_id, "scan_request_id": request_id,
        "status": "completed", "backend_confirmed": True,
    }
    app.session_state["endpoint_success_popup_shown"] = None
    app.session_state["endpoint_verify_attempts"] = 14
    app.run()
    assert not app.exception
    assert any("Windows scan completed, but the report has not been received" in element.value for element in app.error)
    assert "Retry Verification" in [button.label for button in app.button]
    assert app.session_state["endpoint_success_popup_shown"] is None
    next(button for button in app.button if button.label == "Retry Verification").click().run()
    assert app.session_state["endpoint_verify_attempts"] == 1
    assert not scan_posts


def test_success_dialog_waits_for_exact_request_mapping(monkeypatch):
    import requests
    import app_common
    from streamlit.testing.v1 import AppTest

    request_id = "request-" + "f" * 32
    scan_id = "endpoint-" + "1" * 32
    scan = _stored_scan(scan_id, "Stored only after delay")
    user = {"user_id": "user-a", "org_id": "org-a", "tenant_id": "tenant-a", "role": "security_analyst"}

    class ApiResponse:
        def __init__(self, payload=None, status_code=404):
            self.payload, self.status_code, self.ok = payload, status_code, status_code < 400
            self.text = "not found"
        def json(self): return self.payload

    responses = [ApiResponse(status_code=404), ApiResponse({**scan, "scan_request_id": request_id}, 200)]
    report_persisted = {"value": False}
    def api_request(_method, path, **_kwargs):
        if path == "/endpoint/scans": return ApiResponse({"items": [scan], "total": 1}, 200)
        if path == f"/endpoint/scans/by-request/{request_id}":
            response = responses.pop(0)
            if response.ok: report_persisted["value"] = True
            return response
        if path == f"/endpoint/scans/{scan_id}":
            return ApiResponse(scan, 200) if report_persisted["value"] else ApiResponse(status_code=404)
        raise AssertionError(path)

    monkeypatch.setattr(app_common, "current_user", lambda: user)
    monkeypatch.setattr(app_common, "api_request", api_request)
    monkeypatch.setattr(requests, "get", lambda url, **_kwargs: ApiResponse(
        {"connected": True} if url.endswith("/health") else {
            "scan_id": scan_id, "backend_scan_id": scan_id, "scan_request_id": request_id,
            "status": "completed", "backend_confirmed": True,
        }, 200,
    ))

    app = AppTest.from_file(str(FRONTEND / "pages" / "07_endpoint_security.py"))
    app.session_state["endpoint_scan_request_id"] = request_id
    app.session_state["endpoint_scan_id"] = scan_id
    app.session_state["endpoint_scan_state"] = {
        "scan_id": scan_id, "backend_scan_id": scan_id, "scan_request_id": request_id,
        "status": "completed", "backend_confirmed": True,
    }
    app.session_state["endpoint_success_popup_shown"] = None
    app.run()
    assert not app.exception
    assert app.session_state["endpoint_success_popup_shown"] is None
    app.run()
    assert not app.exception
    assert app.session_state["endpoint_success_popup_shown"] == scan_id
    assert app.session_state["endpoint_scan_selector"] == scan_id
