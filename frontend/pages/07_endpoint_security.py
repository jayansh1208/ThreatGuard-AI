from __future__ import annotations

import os
import logging
from typing import Any

import pandas as pd
import requests
import streamlit as st

from app_common import api_request, can_write, current_user, page_header, show_api_error
from endpoint_reports import csv_findings, json_report, scan_details, text_report

AGENT_URL = os.getenv("ENDPOINT_AGENT_URL", "http://host.docker.internal:8765").rstrip("/")
ACTIVE_STATES = {"queued", "running", "report_generated"}
TERMINAL_STATES = {"completed", "failed", "interrupted", "upload_failed"}
MAX_VERIFY_ATTEMPTS = 15
logger = logging.getLogger(__name__)


def _retry_verification(request_id: str | None, scan_id: str | None) -> None:
    key = request_id or scan_id or "unknown"
    if st.button("Retry Verification", key=f"retry-verify-{key}"):
        st.session_state["endpoint_verify_attempts"] = 0
        st.rerun(scope="app")


def _agent_headers() -> dict[str, str]:
    token = st.session_state.get("access_token", "")
    return {"Authorization": f"Bearer {token}"} if token else {}


@st.dialog("Security Scan Completed Successfully!", width="large")
def _success_dialog(scan: dict[str, Any]) -> None:
    details = scan_details(scan)
    summary = details.get("summary") or {}
    findings = details.get("findings") or []
    counts = summary.get("counts") or {}
    coverage = details.get("coverage") or {}
    total_checks = len(coverage)
    passed = sum(value == "success" for value in coverage.values())
    st.markdown(f"**Scan ID:** `{scan.get('scan_id')}`")
    st.markdown(f"**Device:** {details.get('host') or scan.get('host_id') or 'Unknown'}")
    st.markdown(f"**Completed:** {scan.get('created_at') or scan.get('generated_at') or 'Time unavailable'}")
    st.markdown("**Report generation:** Generated and confirmed stored by the backend")
    metrics = st.columns(4)
    metrics[0].metric("Total checks", total_checks)
    metrics[1].metric("Successful checks", passed)
    metrics[2].metric("Failed / skipped", total_checks - passed)
    metrics[3].metric("Total findings", summary.get("total_findings", len(findings)))
    severities = st.columns(4)
    for col, severity in zip(severities, ("critical", "high", "medium", "low")):
        col.metric(f"{severity.title()} findings", counts.get(severity, 0))
    if st.button("Open detailed report", type="primary", key=f"open-report-{scan.get('scan_id')}"):
        st.session_state["endpoint_scan_selector"] = scan["scan_id"]
        st.session_state["endpoint_last_auto_selected"] = scan["scan_id"]
        st.rerun()


user = current_user()
if user is None:
    st.warning("Your session has expired. Return to the sign-in page.")
    st.stop()

page_header("Endpoint Security", "Run a read-only Windows endpoint scan and review the exact report stored for your account.", "ENDPOINT OPERATIONS")

_query_request_id = st.query_params.get("endpoint_request_id")
_query_legacy_id = st.query_params.get("endpoint_scan_id")
if not _query_request_id and _query_legacy_id and _query_legacy_id.startswith("request-"):
    _query_request_id = _query_legacy_id
_prior_scan_state = st.session_state.get("endpoint_scan_state", {})
_needs_scan_poll = (
    _prior_scan_state.get("status") in ACTIVE_STATES
    or (_prior_scan_state.get("status") == "completed"
        and int(st.session_state.get("endpoint_verify_attempts", 0)) < MAX_VERIFY_ATTEMPTS)
    or (_query_request_id and _prior_scan_state.get("scan_request_id") != _query_request_id)
)

@st.fragment(run_every="2s" if _needs_scan_poll else None)
def render_scan_workspace() -> None:
    try:
        health = requests.get(f"{AGENT_URL}/health", timeout=2)
        agent_ready = health.ok and health.json().get("connected") is True
    except requests.RequestException:
        agent_ready = False

    if agent_ready:
        st.success("ThreatGuard Endpoint Agent is connected.")
    else:
        st.warning("ThreatGuard Endpoint Agent is not connected. Start the local agent to perform a scan.")
        st.code("cd endpoint-agent\npython agent.py --serve", language="powershell")

    previous_state = st.session_state.get("endpoint_scan_state", {})
    request_id = (_query_request_id or st.session_state.get("endpoint_scan_request_id")
                  or previous_state.get("scan_request_id"))
    legacy_id = _query_legacy_id if not request_id else None
    agent_state_id = request_id or legacy_id or st.session_state.get("endpoint_scan_id")
    state: dict[str, Any] = {}
    if agent_state_id:
        try:
            state_response = requests.get(f"{AGENT_URL}/scans/{agent_state_id}", headers=_agent_headers(), timeout=4)
            if state_response.ok:
                state = state_response.json()
            elif state_response.status_code == 401:
                st.warning("Sign in again to view the scan agent status.")
            else:
                st.warning(f"Agent status lookup failed ({state_response.status_code}): {state_response.text[:300]}")
        except requests.RequestException:
            if st.session_state.get("endpoint_scan_state", {}).get("scan_request_id") == request_id:
                state = st.session_state["endpoint_scan_state"]
            st.warning("Agent status is temporarily unavailable. The scan request ID is retained so status can be recovered when the agent reconnects.")
        if state:
            st.session_state["endpoint_scan_state"] = state
            if (state.get("status") in TERMINAL_STATES
                    and previous_state.get("status") in ACTIVE_STATES):
                st.rerun(scope="app")

    active_status = state.get("status")
    busy = active_status in ACTIVE_STATES
    if busy:
        st.info(f"Request {request_id or agent_state_id} · {active_status.replace('_', ' ').title()} · {state.get('stage', 'Waiting for agent')}")
        events = state.get("progress_log") or []
        if events:
            with st.expander("Live scan activity", expanded=True):
                for event in events[-12:]:
                    st.caption(f"{event.get('at', '')} · {event.get('stage', '')}")
    elif active_status == "upload_failed":
        st.error(f"Scan report was generated, but upload failed. It is not stored in scan history. {state.get('message', '')}")
        with st.expander("Partial scan logs", expanded=True):
            for event in state.get("progress_log", []):
                st.caption(f"{event.get('at', '')} · {event.get('stage', '')}")
    elif active_status in {"failed", "interrupted"}:
        st.error(f"Scan {active_status}: {state.get('message', 'The agent stopped before confirming completion.')}")
        with st.expander("Partial scan logs", expanded=True):
            for event in state.get("progress_log", []):
                st.caption(f"{event.get('at', '')} · {event.get('stage', '')}")
    elif active_status == "completed":
        st.caption(f"Agent reports completion for request `{request_id or agent_state_id}`. Verifying the stored backend report…")

    success_record: dict[str, Any] | None = None
    if state.get("status") == "completed":
        expected_scan_id = state.get("backend_scan_id") or state.get("scan_id")
        if expected_scan_id and expected_scan_id.startswith("request-"):
            expected_scan_id = None
        attempts = int(st.session_state.get("endpoint_verify_attempts", 0))
        try:
            if request_id:
                confirmed = api_request("GET", f"/endpoint/scans/by-request/{request_id}", timeout=3)
                # Older agent/backend pairs did not persist the request mapping. Fall back only
                # to the exact scan ID the agent reported, never to the newest history item.
                if confirmed.status_code == 404 and expected_scan_id:
                    exact_scan_response = api_request("GET", f"/endpoint/scans/{expected_scan_id}", timeout=3)
                    if exact_scan_response.ok:
                        exact_record = exact_scan_response.json()
                        if exact_record.get("scan_id") == expected_scan_id:
                            confirmed = exact_scan_response
            elif expected_scan_id:
                confirmed = api_request("GET", f"/endpoint/scans/{expected_scan_id}", timeout=3)
            else:
                confirmed = None
            if confirmed is not None and confirmed.ok:
                record = confirmed.json()
                record_scan_id = record.get("scan_id")
                returned_request_id = record.get("scan_request_id")
                if not record_scan_id or (expected_scan_id and record_scan_id != expected_scan_id):
                    attempts += 1
                    st.session_state["endpoint_verify_attempts"] = attempts
                    logger.error("endpoint_scan_verification_failed", extra={
                        "event": "endpoint_scan_verification_failed", "scan_request_id": request_id,
                        "scan_id": expected_scan_id, "endpoint_id": state.get("endpoint_id"),
                        "reason": "persisted_scan_id_mismatch", "returned_scan_id": record_scan_id,
                    })
                    st.error(f"Backend verification returned scan ID {record_scan_id!r}, expected {expected_scan_id!r}. No success was recorded.")
                elif request_id and returned_request_id not in (None, request_id):
                    attempts += 1
                    st.session_state["endpoint_verify_attempts"] = attempts
                    logger.error("endpoint_scan_verification_failed", extra={
                        "event": "endpoint_scan_verification_failed", "scan_request_id": request_id,
                        "scan_id": record_scan_id, "endpoint_id": record.get("endpoint_id") or record.get("host_id"),
                        "reason": "request_id_mismatch", "returned_request_id": returned_request_id,
                    })
                    st.error(f"Backend report is associated with request {returned_request_id!r}, not {request_id!r}. No success was recorded.")
                else:
                    st.session_state["endpoint_verify_attempts"] = 0
                    st.session_state["endpoint_verified_scan_id"] = record_scan_id
                    st.session_state["endpoint_scan_id"] = record_scan_id
                    if st.session_state.get("endpoint_last_auto_selected") != record_scan_id:
                        st.session_state["endpoint_scan_selector"] = record_scan_id
                        st.session_state["endpoint_last_auto_selected"] = record_scan_id
                    logger.info("endpoint_scan_verification_succeeded", extra={
                        "event": "endpoint_scan_verification_succeeded", "scan_request_id": request_id,
                        "scan_id": record_scan_id, "endpoint_id": record.get("endpoint_id") or record.get("host_id"),
                    })
                    if st.session_state.get("endpoint_success_popup_shown") != record_scan_id:
                        success_record = record
                if attempts >= MAX_VERIFY_ATTEMPTS and success_record is None:
                    st.caption(f"Automatic verification stopped after {MAX_VERIFY_ATTEMPTS} attempts.")
                    _retry_verification(request_id, expected_scan_id)
            elif confirmed is not None and confirmed.status_code == 404:
                attempts += 1
                st.session_state["endpoint_verify_attempts"] = attempts
                if attempts >= MAX_VERIFY_ATTEMPTS:
                    logger.error("endpoint_scan_verification_failed", extra={
                        "event": "endpoint_scan_verification_failed", "scan_request_id": request_id,
                        "scan_id": expected_scan_id, "endpoint_id": state.get("endpoint_id"),
                        "reason": "backend_report_missing", "attempts": attempts,
                    })
                    st.error("Windows scan completed, but the report has not been received by ThreatGuard yet.")
                    st.caption(f"Verification stopped after {MAX_VERIFY_ATTEMPTS} attempts. Request: {request_id or agent_state_id} · Candidate scan: {expected_scan_id or 'not returned'}")
                    _retry_verification(request_id, expected_scan_id)
                else:
                    st.info(f"Windows scan completed; waiting for the backend report (verification {attempts}/{MAX_VERIFY_ATTEMPTS}).")
            elif confirmed is not None:
                attempts += 1
                st.session_state["endpoint_verify_attempts"] = attempts
                logger.error("endpoint_scan_verification_failed", extra={
                    "event": "endpoint_scan_verification_failed", "scan_request_id": request_id,
                    "scan_id": expected_scan_id, "endpoint_id": state.get("endpoint_id"),
                    "status_code": confirmed.status_code,
                })
                show_api_error(confirmed, "The scan completed at the agent, but its report could not be verified in backend history.")
                if attempts >= MAX_VERIFY_ATTEMPTS:
                    st.caption(f"Automatic verification stopped after {MAX_VERIFY_ATTEMPTS} attempts.")
                    _retry_verification(request_id, expected_scan_id)
            else:
                attempts += 1
                st.session_state["endpoint_verify_attempts"] = attempts
                logger.error("endpoint_scan_verification_failed", extra={
                    "event": "endpoint_scan_verification_failed", "scan_request_id": request_id,
                    "scan_id": expected_scan_id, "endpoint_id": state.get("endpoint_id"),
                    "reason": "missing_persisted_scan_id",
                })
                st.error("The agent reported completion, but did not return a persisted scan ID and no request-to-report mapping is available.")
                if attempts >= MAX_VERIFY_ATTEMPTS:
                    _retry_verification(request_id, expected_scan_id)
        except requests.RequestException as exc:
            attempts += 1
            st.session_state["endpoint_verify_attempts"] = attempts
            logger.warning("endpoint_scan_verification_failed", extra={
                "event": "endpoint_scan_verification_failed", "scan_request_id": request_id,
                "scan_id": expected_scan_id, "endpoint_id": state.get("endpoint_id"),
                "error_type": type(exc).__name__, "error": str(exc)[:300],
            })
            if attempts >= MAX_VERIFY_ATTEMPTS:
                st.error(f"Automatic verification stopped after {MAX_VERIFY_ATTEMPTS} attempts. Latest error: {type(exc).__name__}: {str(exc)[:300]}")
                _retry_verification(request_id, expected_scan_id)
            else:
                st.warning(f"Backend verification request failed ({attempts}/{MAX_VERIFY_ATTEMPTS}): {type(exc).__name__}: {str(exc)[:300]}")

    if st.button("Run Security Scan", type="primary", disabled=(not agent_ready or not can_write(user) or busy),
                 use_container_width=True):
        try:
            response = requests.post(f"{AGENT_URL}/scans", headers=_agent_headers(), timeout=5)
        except requests.RequestException:
            st.error("ThreatGuard Endpoint Agent is not connected. Start the local agent to perform a scan.")
        else:
            if response.status_code == 202:
                requested = response.json()
                new_request_id = requested.get("scan_request_id") or requested.get("request_id")
                if not new_request_id:
                    st.error("The agent accepted the request without returning a scan request ID. No completion will be assumed.")
                else:
                    expected_scan_id = requested.get("scan_id")
                    st.session_state["endpoint_scan_request_id"] = new_request_id
                    st.session_state["endpoint_scan_id"] = expected_scan_id
                    st.session_state["endpoint_expected_scan_id"] = expected_scan_id
                    st.session_state["endpoint_scan_state"] = {
                        "scan_request_id": new_request_id, "request_id": new_request_id,
                        "scan_id": expected_scan_id, "status": "queued", "stage": "Queued",
                    }
                    st.session_state["endpoint_verify_attempts"] = 0
                    st.session_state["endpoint_success_popup_shown"] = None
                    st.query_params["endpoint_request_id"] = new_request_id
                    st.query_params.pop("endpoint_scan_id", None)
                    logger.info("endpoint_scan_request_created", extra={
                        "event": "endpoint_scan_request_created", "scan_request_id": new_request_id,
                        "scan_id": expected_scan_id,
                    })
                    st.rerun()
            elif response.status_code == 409:
                st.warning("A scan is already active. Its existing status is being retained.")
            else:
                st.error(f"Scan request failed ({response.status_code}): {response.text[:300]}")

    try:
        history_response = api_request("GET", "/endpoint/scans", params={"page": 1, "page_size": 100})
    except requests.RequestException:
        st.error("The backend is unavailable. Endpoint scan history could not be loaded.")
        return
    if not history_response.ok:
        show_api_error(history_response, "Endpoint scan history could not be loaded.")
        return
    scans = history_response.json().get("items", [])
    scan_by_id = {item["scan_id"]: item for item in scans if item.get("scan_id")}

    if not scans:
        st.info("No endpoint scan has been uploaded for this account yet. Completed reports will appear here automatically.")
        return

    preferred = st.session_state.get("endpoint_scan_selector")
    if preferred not in scan_by_id:
        preferred = scans[0]["scan_id"]
    options = [item["scan_id"] for item in scans]
    if st.session_state.get("endpoint_scan_selector") not in options:
        st.session_state["endpoint_scan_selector"] = preferred
    selected_id = st.selectbox(
        "Scan history · newest first", options,
        format_func=lambda value: next((f"{item.get('created_at', 'Unknown time')} · {value}" for item in scans if item["scan_id"] == value), value),
        key="endpoint_scan_selector",
    )
    try:
        detail_response = api_request("GET", f"/endpoint/scans/{selected_id}", timeout=15)
    except requests.RequestException:
        st.error("The backend is unavailable. The selected scan report could not be loaded.")
        return
    if not detail_response.ok:
        show_api_error(detail_response, "The selected endpoint scan could not be loaded.")
        return
    scan = detail_response.json()
    if scan.get("scan_id") != selected_id:
        st.error("The backend returned a report for a different scan ID. Report controls are disabled to prevent a mismatched download.")
        return

    details = scan_details(scan)
    findings = details.get("findings") or []
    summary = details.get("summary") or {}
    counts = summary.get("counts") or {}
    st.markdown(f"**Selected report scan ID:** `{selected_id}`")
    columns = st.columns(5)
    for col, severity in zip(columns, ("critical", "high", "medium", "low", "informational")):
        col.metric(severity.title(), counts.get(severity, 0))
    coverage = details.get("coverage") or {}
    if counts.get("critical", 0) or counts.get("high", 0):
        overall = "Review required"
    elif counts.get("medium", 0):
        overall = "Warnings found"
    elif not coverage or any(value in {"unknown", "failed", "unsupported", "requires_verification"} for value in coverage.values()):
        overall = "Coverage incomplete"
    else:
        overall = "No configured checks reported issues"
    st.metric("Overall security status", overall)
    st.caption(f"Host: {details.get('host', scan.get('host_id', 'Unknown'))} · Last scan: {details.get('generated_at', scan.get('created_at', 'Unknown'))} · Coverage: {coverage}")

    st.subheader("Latest Scan Report & Logs")
    report_json = json_report(scan)
    txt_report = text_report(scan)
    csv_report = csv_findings(scan)
    downloads = st.columns(3)
    downloads[0].download_button("Download TXT Report", txt_report, file_name=f"threatguard-scan-{selected_id}.txt", mime="text/plain", key=f"txt-{selected_id}")
    downloads[1].download_button("Download JSON Report", report_json, file_name=f"threatguard-scan-{selected_id}.json", mime="application/json", key=f"json-{selected_id}")
    downloads[2].download_button("Download CSV Findings", csv_report, file_name=f"threatguard-scan-{selected_id}-findings.csv", mime="text/csv", key=f"csv-{selected_id}")
    with st.expander("View Full Report"):
        st.json(scan, expanded=False)

    st.subheader("Findings")
    if findings:
        severity_filter = st.multiselect("Filter by severity", ["critical", "high", "medium", "low", "informational"], default=["critical", "high", "medium", "low", "informational"], key=f"finding-filter-{selected_id}")
        visible_findings = [item for item in findings if str(item.get("severity", "unknown")).lower() in severity_filter]
        rows = [{"Severity": item.get("severity", "unknown").title(), "Finding": item.get("title", ""),
                 "Component": item.get("affected_component", ""), "CVE": item.get("related_cve") or "—",
                 "Confidence": item.get("confidence", "unknown"), "Status": item.get("status", "open").title(),
                 "Action": item.get("remediation", "")}
                for item in visible_findings]
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.info("No findings match the selected severity filters.")
        for item in visible_findings:
            with st.expander(f"{item.get('severity', 'unknown').upper()} · {item.get('title', 'Finding')}"):
                st.write(item.get("description", ""))
                st.caption(f"Confidence: {item.get('confidence', 'unknown')} · Source: {item.get('intelligence_source', 'unknown')}")
                st.write("Evidence")
                st.json(item.get("evidence", {}), expanded=False)
                if item.get("rationale"):
                    st.caption(f"Severity rationale: {item['rationale']}")
                st.write(f"Recommended action: {item.get('remediation', 'Review the finding.')}")
    else:
        st.info("This scan returned no findings. Check collection coverage before treating that as assurance.")

    scan_index = next((index for index, item in enumerate(scans) if item.get("scan_id") == selected_id), None)
    if scan_index is not None and scan_index + 1 < len(scans):
        previous = scans[scan_index + 1]
        with st.expander(f"Changes since previous scan ({previous.get('scan_id')})"):
            old_response = api_request("GET", f"/endpoint/scans/{previous['scan_id']}")
            if old_response.ok:
                previous_findings = old_response.json().get("findings") or []
                finding_key = lambda item: (item.get("title"), item.get("affected_component"), item.get("related_cve"))
                current_keys = {finding_key(item) for item in findings}
                previous_keys = {finding_key(item) for item in previous_findings}
                added = current_keys - previous_keys
                resolved = previous_keys - current_keys
                st.write(f"New findings: {len(added)} · No longer present: {len(resolved)}")
                if added:
                    st.markdown("**New**")
                    st.write([key[0] for key in sorted(added, key=str)])
                if resolved:
                    st.markdown("**No longer reported**")
                    st.write([key[0] for key in sorted(resolved, key=str)])
            else:
                st.caption("The previous scan is unavailable for comparison.")

    with st.expander("Collected endpoint inventory"):
        st.json(details.get("inventory") or {}, expanded=False)
    st.subheader("AI Security Assistant")
    st.caption("Open AI Security Assistant and ask ‘Analyze my latest endpoint scan’ or ‘What should I fix first?’")
    if success_record is not None:
        st.session_state["endpoint_success_popup_shown"] = success_record["scan_id"]
        _success_dialog(success_record)


render_scan_workspace()
