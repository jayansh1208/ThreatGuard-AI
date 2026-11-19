from __future__ import annotations

import os

import pandas as pd
import requests
import streamlit as st

from app_common import api_request, can_write, current_user, page_header, show_api_error

AGENT_URL = os.getenv("ENDPOINT_AGENT_URL", "http://host.docker.internal:8765").rstrip("/")
user = current_user()
if user is None:
    st.warning("Your session has expired. Return to the sign-in page.")
    st.stop()

page_header("Endpoint Security", "Review Windows agent connectivity, scan evidence, and recommended defensive actions.", "ENDPOINT OPERATIONS")

try:
    agent = requests.get(f"{AGENT_URL}/health", timeout=2)
    agent_ready = agent.ok and agent.json().get("connected") is True
except requests.RequestException:
    agent_ready = False

if agent_ready:
    st.success("ThreatGuard Endpoint Agent is connected.")
else:
    st.warning("ThreatGuard Endpoint Agent is not connected. Start the local agent to perform a scan.")
    st.code("cd endpoint-agent\npython agent.py --serve", language="powershell")

if st.button("Run Security Scan", type="primary", disabled=(not agent_ready or not can_write(user))):
    try:
        response = requests.post(f"{AGENT_URL}/scans", headers={"Authorization": f"Bearer {st.session_state.get('access_token', '')}"}, timeout=5)
    except requests.RequestException:
        st.error("ThreatGuard Endpoint Agent is not connected. Start the local agent to perform a scan.")
    else:
        if response.status_code == 202:
            st.session_state["endpoint_request_id"] = response.json().get("request_id")
            st.success("Scan started. Use Refresh scan status to check for completion.")
        else:
            st.error(f"Scan request failed ({response.status_code}): {response.text[:300]}")

request_id = st.session_state.get("endpoint_request_id")
if request_id:
    if st.button("Refresh scan status"):
        try:
            progress = requests.get(f"{AGENT_URL}/scans/{request_id}",
                                    headers={"Authorization": f"Bearer {st.session_state.get('access_token', '')}"}, timeout=3).json()
        except requests.RequestException:
            st.warning("Agent status is unavailable. Check that the local agent is still running.")
        else:
            status = progress.get("status", "unknown")
            if status == "completed":
                st.success("Scan complete and findings uploaded.")
                st.session_state.pop("endpoint_request_id", None)
                st.rerun()
            elif status == "running":
                st.info("Scan is running on the local Windows host.")
            elif status == "failed":
                st.error(progress.get("message", "Scan failed."))
                st.session_state.pop("endpoint_request_id", None)

try:
    history_response = api_request("GET", "/endpoint/scans", params={"page": 1, "page_size": 50})
except requests.RequestException:
    st.error("The backend is unavailable. Endpoint scan history could not be loaded.")
    st.stop()
if not history_response.ok:
    show_api_error(history_response, "Endpoint scan history could not be loaded.")
    st.stop()
scans = history_response.json().get("items", [])
if not scans:
    st.info("No endpoint scan has been uploaded for this tenant yet. Start the local agent and run a scan.")
    st.stop()

selected_id = st.selectbox("Scan history", [item["scan_id"] for item in scans],
                           format_func=lambda scan_id: next((f"{item.get('created_at', 'Unknown time')} · {scan_id}" for item in scans if item["scan_id"] == scan_id), scan_id))
detail_response = api_request("GET", f"/endpoint/scans/{selected_id}")
if not detail_response.ok:
    show_api_error(detail_response, "The selected endpoint scan could not be loaded.")
    st.stop()
scan = detail_response.json()
details = scan.get("details") or {key: scan.get(source) for key, source in {
    "host": "host_id", "generated_at": "generated_at", "summary": "summary",
    "coverage": "coverage", "findings": "findings", "inventory": "inventory",
}.items()}
findings = details.get("findings") or []
summary = details.get("summary") or {}
counts = summary.get("counts") or {}
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
st.caption(f"Host: {details.get('host', 'Unknown')} · Last scan: {details.get('generated_at', scan.get('created_at', 'Unknown'))} · Coverage: {details.get('coverage', {})}")

st.subheader("Findings")
if findings:
    severity_filter = st.multiselect("Filter by severity", ["critical", "high", "medium", "low", "informational"], default=["critical", "high", "medium", "low", "informational"])
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
st.caption("Open AI Chatbot and ask ‘Analyze my latest endpoint scan’ or ‘What should I fix first?’")
