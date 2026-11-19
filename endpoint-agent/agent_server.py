from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import requests

from scanner import run_scan


ACTIVE_STATUSES = {"queued", "running", "report_generated"}
TERMINAL_STATUSES = {"completed", "failed", "interrupted", "upload_failed"}
WRITE_ROLES = {"super_admin", "tenant_admin", "security_analyst", "security_operator"}
logger = logging.getLogger(__name__)


def _log(event: str, *, scan_request_id: str, scan_id: str | None = None,
         endpoint_id: str | None = None, **fields: Any) -> None:
    # Structured fields intentionally exclude authorization headers and secrets.
    logger.info(event, extra={"event": event, "scan_request_id": scan_request_id,
                              "scan_id": scan_id, "endpoint_id": endpoint_id, **fields})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state_path() -> Path:
    configured = os.getenv("THREATGUARD_AGENT_STATE_PATH")
    return Path(configured) if configured else Path(__file__).with_name(".cache") / "scan_states.json"


def _load_states(path: Path) -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        payload = {}
    if not isinstance(payload, dict):
        return {}
    states = {str(key): value for key, value in payload.items() if isinstance(value, dict)}
    for scan_id, state in states.items():
        if state.get("status") in ACTIVE_STATUSES:
            state.update({"status": "interrupted", "stage": "Interrupted",
                          "message": "The endpoint agent restarted before this scan was confirmed complete.",
                          "updated_at": _now()})
            progress_log = state.get("progress_log")
            if not isinstance(progress_log, list):
                progress_log = []
                state["progress_log"] = progress_log
            progress_log.append({"at": state["updated_at"], "stage": "Interrupted"})
    return states


def _save_states(path: Path, states: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(states, ensure_ascii=False, default=str, separators=(",", ":"))
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                     prefix="scan-states-", suffix=".tmp", delete=False) as handle:
        handle.write(serialized)
        temporary = Path(handle.name)
    temporary.replace(path)


def create_handler(client: Any, *, scan_runner: Callable[..., dict[str, Any]] = run_scan,
                   state_path: Path | None = None) -> type[BaseHTTPRequestHandler]:
    path = state_path or _state_path()
    states = _load_states(path)
    if states:
        _save_states(path, states)
    lock = threading.Lock()

    def update(scan_id: str, *, stage: str | None = None, **changes: Any) -> None:
        with lock:
            state = states.setdefault(scan_id, {"scan_id": scan_id, "status": "queued", "progress_log": []})
            if stage and state.get("stage") != stage:
                state.setdefault("progress_log", []).append({"at": _now(), "stage": stage})
                state["progress_log"] = state["progress_log"][-40:]
                state["stage"] = stage
            state.update(changes)
            state["updated_at"] = _now()
            _save_states(path, states)

    def authenticated_user(authorization: str) -> dict[str, Any] | None:
        if not authorization.startswith("Bearer "):
            return None
        try:
            response = requests.get(
                f"{client.config.backend_url}/auth/me", headers={"Authorization": authorization},
                timeout=client.config.timeout_seconds, verify=client.config.verify_tls,
            )
            response.raise_for_status()
            user = response.json()
            return user if isinstance(user, dict) else None
        except requests.RequestException:
            return None

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args) -> None:
            return

        def do_GET(self) -> None:
            request_path = urlparse(self.path).path
            if request_path == "/health":
                self._send(200, {"connected": True, "message": "Agent ready"})
                return
            if not request_path.startswith("/scans/"):
                self._send(404, {"detail": "Not found"})
                return
            authorization = self.headers.get("Authorization", "")
            user = authenticated_user(authorization)
            if user is None:
                self._send(401, {"detail": "Sign in to ThreatGuard first"})
                return
            scan_request_id = request_path.rsplit("/", 1)[-1]
            with lock:
                state = states.get(scan_request_id)
                if state and any(state.get(state_key) != user.get(user_key) for state_key, user_key in (
                    ("owner_user_id", "user_id"), ("org_id", "org_id"), ("tenant_id", "tenant_id"),
                )):
                    state = None
                body = dict(state) if state else {"request_id": scan_request_id,
                                                  "scan_request_id": scan_request_id,
                                                  "status": "unknown"}
            self._send(200, body)

        def do_POST(self) -> None:
            if urlparse(self.path).path != "/scans":
                self._send(404, {"detail": "Not found"})
                return
            authorization = self.headers.get("Authorization", "")
            user = authenticated_user(authorization)
            if user is None:
                self._send(401, {"detail": "Sign in to ThreatGuard first"})
                return
            if user.get("role") not in WRITE_ROLES:
                self._send(403, {"detail": "Your role cannot request endpoint scans"})
                return
            with lock:
                if any(state.get("status") in ACTIVE_STATUSES for state in states.values()):
                    self._send(409, {"detail": "A scan is already running"})
                    return
                scan_request_id = f"request-{uuid.uuid4().hex}"
                scan_id = f"endpoint-{uuid.uuid4().hex}"
                state = {"request_id": scan_request_id, "scan_request_id": scan_request_id,
                         "scan_id": scan_id, "status": "queued", "stage": "Queued",
                         "owner_user_id": user.get("user_id"), "org_id": user.get("org_id"),
                         "tenant_id": user.get("tenant_id"),
                         "started_at": _now(), "updated_at": _now(), "progress_log": []}
                states[scan_request_id] = state
                _save_states(path, states)
            _log("endpoint_scan_request_created", scan_request_id=scan_request_id,
                 scan_id=scan_id, user_id=user.get("user_id"), tenant_id=user.get("tenant_id"))

            def run_and_upload() -> None:
                try:
                    _log("endpoint_scan_request_delivered", scan_request_id=scan_request_id, scan_id=scan_id)
                    update(scan_request_id, status="running", stage="Initializing scan")
                    _log("endpoint_scan_started", scan_request_id=scan_request_id, scan_id=scan_id)

                    def report_progress(stage: str) -> None:
                        normalized_stage = str(stage)[:120]
                        update(scan_request_id, status="running", stage=normalized_stage)
                        if normalized_stage == "Generating scan report":
                            _log("endpoint_scan_report_generation_started", scan_request_id=scan_request_id,
                                 scan_id=scan_id)

                    report = scan_runner(scan_id=scan_id, progress_callback=report_progress)
                    if report.get("scan_id") != scan_id:
                        raise ValueError("Generated report scan ID did not match the requested scan ID")
                    endpoint_id = str(report.get("host_id") or "")
                    report["scan_request_id"] = scan_request_id
                    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
                    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
                    _log("endpoint_scan_completed", scan_request_id=scan_request_id,
                         scan_id=scan_id, endpoint_id=endpoint_id)
                    update(scan_request_id, status="report_generated", stage="Report generated",
                           report_generated=True, host_id=report.get("host_id"),
                           endpoint_id=endpoint_id,
                           generated_at=report.get("generated_at"), summary=summary,
                           coverage=coverage, total_findings=len(report.get("findings") or []))
                    update(scan_request_id, status="report_generated", stage="Uploading results", upload_status="running")
                    _log("endpoint_scan_report_upload_started", scan_request_id=scan_request_id,
                         scan_id=scan_id, endpoint_id=endpoint_id)
                    response = client.session.post(
                        f"{client.config.backend_url}/endpoint/scans", json=report,
                        headers={"Authorization": authorization}, timeout=client.config.timeout_seconds,
                        verify=client.config.verify_tls,
                    )
                    response.raise_for_status()
                    stored = response.json()
                    if stored.get("scan_id") != scan_id:
                        raise ValueError("Backend stored a different scan ID than the generated report")
                    if stored.get("scan_request_id") not in (None, scan_request_id):
                        raise ValueError("Backend associated the persisted report with a different scan request")
                    update(scan_request_id, status="completed", stage="Completed", upload_status="completed",
                           backend_confirmed=True, completed_at=_now(), backend_scan_id=stored["scan_id"],
                           backend_created_at=stored.get("created_at"))
                    _log("endpoint_scan_persistence_succeeded", scan_request_id=scan_request_id,
                         scan_id=stored["scan_id"], endpoint_id=endpoint_id, tenant_id=user.get("tenant_id"))
                    _log("endpoint_scan_persisted_id_returned", scan_request_id=scan_request_id,
                         scan_id=stored["scan_id"], endpoint_id=endpoint_id)
                except requests.RequestException as exc:
                    with lock:
                        current = states.get(scan_request_id, {})
                        generated = bool(current.get("report_generated"))
                    _log("endpoint_scan_persistence_failed" if generated else "endpoint_scan_failed",
                         scan_request_id=scan_request_id, scan_id=scan_id,
                         endpoint_id=states.get(scan_request_id, {}).get("endpoint_id"),
                         error_type=type(exc).__name__, error=str(exc)[:300])
                    update(scan_request_id, status="upload_failed" if generated else "failed",
                           stage="Upload failed" if generated else "Scan failed",
                           upload_status="failed" if generated else "not_started",
                           message=f"{type(exc).__name__}: {str(exc)[:400]}")
                except Exception as exc:
                    with lock:
                        current = states.get(scan_request_id, {})
                        generated = bool(current.get("report_generated"))
                    _log("endpoint_scan_persistence_failed" if generated else "endpoint_scan_failed",
                         scan_request_id=scan_request_id, scan_id=scan_id,
                         endpoint_id=states.get(scan_request_id, {}).get("endpoint_id"),
                         error_type=type(exc).__name__, error=str(exc)[:300])
                    update(scan_request_id, status="upload_failed" if generated else "failed",
                           stage="Upload failed" if generated else "Scan failed",
                           upload_status="failed" if generated else "not_started",
                           message=f"{type(exc).__name__}: {str(exc)[:400]}")

            threading.Thread(target=run_and_upload, name=f"endpoint-scan-{scan_request_id}", daemon=True).start()
            self._send(202, {"request_id": scan_request_id, "scan_request_id": scan_request_id,
                             "scan_id": scan_id, "endpoint_id": None, "status": "queued"})

    return Handler


def serve_agent(client: Any, *, host: str | None = None, port: int | None = None,
                scan_runner: Callable[..., dict[str, Any]] = run_scan,
                state_path: Path | None = None) -> ThreadingHTTPServer:
    bind_host = host or os.getenv("THREATGUARD_AGENT_BIND", "0.0.0.0")
    bind_port = port if port is not None else int(os.getenv("THREATGUARD_AGENT_PORT", "8765"))
    server = ThreadingHTTPServer((bind_host, bind_port), create_handler(client, scan_runner=scan_runner,
                                                                        state_path=state_path))
    print(f"ThreatGuard endpoint agent is listening on {bind_host}:{server.server_address[1]}; stop it with Ctrl+C.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAgent stopped.")
    return server
