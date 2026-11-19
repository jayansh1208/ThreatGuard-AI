from __future__ import annotations

from datetime import datetime

import altair as alt
import pandas as pd
import requests
import streamlit as st

from app_common import api_request, current_user, page_header, show_api_error


user = current_user()
if user is None:
    st.warning("Your session has expired. Return to the sign-in page.")
    st.stop()

page_header("Security overview", "Your tenant's security activity, threat exposure, and investigation workspace.", "COMMAND CENTER")
left, right = st.columns([5, 1])
left.caption(f"Workspace · {user.get('display_name') or user.get('email')}  /  {user.get('role', '').replace('_', ' ').title()}")
if right.button("↻  Refresh", use_container_width=True):
    st.rerun()

try:
    dashboard_response = api_request("GET", "/dashboard/metrics", timeout=20)
except requests.RequestException:
    st.error("The backend is unavailable. Dashboard metrics could not be loaded.")
    st.stop()
if not dashboard_response.ok:
    show_api_error(dashboard_response, "Dashboard metrics could not be loaded.")
    st.stop()

payload = dashboard_response.json()
metrics = payload.get("metrics") or {}
system = payload.get("system_status") or {}
severities = metrics.get("severity_distribution") or {}
critical = int(severities.get("critical", 0) or 0)
high = int(severities.get("high", 0) or 0)

st.markdown("<div class='tg-eyebrow'>TENANT SNAPSHOT</div>", unsafe_allow_html=True)
kpis = st.columns(4)
kpis[0].metric("Threat records", metrics.get("total_threats", 0), help="Threat records stored for this tenant.")
kpis[1].metric("Critical threats", critical, help="Critical severity threat records in your tenant.")
kpis[2].metric("High severity", high, help="High severity threat records in your tenant.")
kpis[3].metric("Scan reports", metrics.get("total_scans", 0), help="Stored scanner reports. This is not a live endpoint count.")

st.subheader("Quick actions")
actions = st.columns(5 if user.get("role") in {"super_admin", "tenant_admin", "security_analyst", "security_operator"} else 4)
actions[0].page_link("pages/07_endpoint_security.py", label="Endpoint scan", icon="🖥️")
actions[1].page_link("pages/06_intelligence_dashboard.py", label="Threat intelligence", icon="🧠")
actions[2].page_link("pages/03_knowledge_base.py", label="Knowledge Base", icon="📚")
actions[3].page_link("pages/02_scanner.py", label="Scan history", icon="🔎")
if len(actions) > 4:
    actions[4].page_link("pages/04_chatbot.py", label="AI assistant", icon="💬")

overview, distribution = st.columns([1.55, 1], gap="large")
with overview:
    st.subheader("Recent scan activity")
    st.caption("Daily scan report volume from stored tenant records")
    recent_scans = payload.get("recent_scans") or []
    points = []
    for scan in recent_scans:
        raw = scan.get("created_at")
        try:
            day = datetime.fromisoformat(str(raw).replace("Z", "+00:00")).date()
            points.append(day)
        except (ValueError, TypeError):
            continue
    if points:
        timeline = pd.Series(points).value_counts().sort_index()
        timeline.index = pd.to_datetime(timeline.index)
        st.area_chart(timeline.rename("Scan reports"), color="#62a7ff", height=250)
    else:
        st.info("No dated scan records are available yet. Scanner activity will appear here after reports are stored.")
with distribution:
    st.subheader("Threat severity")
    st.caption("Severity of stored threat records")
    severity_items = [("Critical", critical), ("High", high),
                      ("Medium", int(severities.get("medium", 0) or 0)),
                      ("Low", int(severities.get("low", 0) or 0))]
    if sum(value for _, value in severity_items):
        chart_data = pd.DataFrame({"Severity": [name for name, _ in severity_items], "Records": [value for _, value in severity_items]})
        donut = alt.Chart(chart_data).mark_arc(innerRadius=58, outerRadius=88, stroke="#111b2d", strokeWidth=3).encode(
            theta=alt.Theta("Records:Q", stack=True),
            color=alt.Color("Severity:N", scale=alt.Scale(
                domain=["Critical", "High", "Medium", "Low"],
                range=["#ef5350", "#fb923c", "#eab308", "#22c55e"],
            ), legend=alt.Legend(title=None, labelColor="#c2cede", labelFontSize=12)),
            tooltip=[alt.Tooltip("Severity:N"), alt.Tooltip("Records:Q")],
        ).properties(height=220, background="transparent")
        st.altair_chart(donut, use_container_width=True)
        st.caption(f"{sum(value for _, value in severity_items):,} threat records")
    else:
        st.info("No threat severity records are available yet.")

st.divider()
activity, endpoint = st.columns([1.35, 1], gap="large")
with activity:
    st.subheader("Recent threat activity")
    threats = payload.get("recent_threats") or []
    if threats:
        threat_rows = [{
            "Threat": item.get("title") or item.get("threat_id") or "Threat record",
            "Severity": str(item.get("severity") or "Unknown").title(),
            "Status": item.get("lifecycle_status") or "—",
            "Source": item.get("source") or "—",
            "Detected": item.get("created_at") or "—",
        } for item in threats]
        st.dataframe(pd.DataFrame(threat_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No threat records have been added for this tenant yet.")

with endpoint:
    st.subheader("Endpoint security")
    st.caption("Stored scan evidence from registered endpoint agents")
    try:
        endpoint_response = api_request("GET", "/endpoint/scans", params={"page": 1, "page_size": 5}, timeout=15)
    except requests.RequestException:
        endpoint_response = None
    if endpoint_response is None:
        st.warning("Endpoint scan history is currently unavailable.")
    elif not endpoint_response.ok:
        show_api_error(endpoint_response, "Endpoint scan history could not be loaded.")
    else:
        endpoint_scans = endpoint_response.json().get("items") or []
        count = endpoint_response.json().get("total", len(endpoint_scans))
        st.metric("Stored endpoint scans", count)
        if endpoint_scans:
            latest = endpoint_scans[0]
            st.markdown(f"**Latest report** · {latest.get('created_at', 'Time unavailable')}")
            st.caption(f"Host: {latest.get('host_id') or latest.get('host') or 'Not recorded'}")
        else:
            st.caption("No endpoint agent reports have been uploaded yet.")
    st.markdown("<div class='tg-panel'><div class='tg-panel-title'>Investigate with AI</div><div class='tg-panel-copy'>Ask evidence grounded questions about stored scan reports, vulnerabilities, and tenant references.</div></div>", unsafe_allow_html=True)

st.divider()
st.subheader("Workspace resources")
resources = st.columns(3)
resources[0].metric("Knowledge documents", metrics.get("kb_document_count", 0))
resources[1].metric("Your AI conversations", metrics.get("chat_session_count", 0))
resources[2].metric("MongoDB", str(system.get("mongo", "unknown")).title())

st.caption("Metrics are loaded from authenticated, tenant-scoped backend records. Endpoint scan storage does not imply the agent is currently connected.")
