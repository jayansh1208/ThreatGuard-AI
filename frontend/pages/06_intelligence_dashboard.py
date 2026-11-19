from __future__ import annotations

import requests
import streamlit as st

from app_common import api_request, can_read, can_write, current_user, page_header, show_api_error
from intelligence_dashboard import fetch_payload, graphviz_source, page_count, safe_source_url, sanitize_evidence, search_params


user = current_user()
if user is None or not can_read(user):
    st.warning("Your session has expired or your role cannot read intelligence records.")
    st.stop()

page_header("Threat Intelligence", "Explore tenant-scoped vulnerability and adversary intelligence, with source evidence and relationships.", "INTELLIGENCE")

with st.spinner("Loading intelligence statistics…"):
    stats, stats_error = fetch_payload(api_request, "/intelligence/statistics")
if stats_error:
    if isinstance(stats_error, requests.RequestException):
        st.error("The backend is unavailable. Intelligence statistics could not be loaded.")
    else:
        show_api_error(stats_error, "Intelligence statistics could not be loaded.")
    counts = {}
    severities = {}
else:
    counts = stats.get("counts") or {}
    severities = stats.get("vulnerabilities_by_severity") or {}

cards = [
    ("Total CVEs", counts.get("cve", 0)), ("Critical", severities.get("critical", 0)),
    ("High", severities.get("high", 0)), ("Medium", severities.get("medium", 0)),
    ("Low", severities.get("low", 0)), ("CISA KEV", stats.get("cisa_kev", 0) if stats else 0),
    ("ATT&CK techniques", counts.get("technique", 0)), ("CAPEC patterns", counts.get("capec", 0)),
    ("Sigma rules", counts.get("sigma", 0)),
]
for start in range(0, len(cards), 3):
    cols = st.columns(3)
    for column, (label, value) in zip(cols, cards[start:start + 3]):
        column.metric(label, value)
if stats is not None:
    st.subheader("Vulnerability severity")
    st.bar_chart({"Severity": ["Critical", "High", "Medium", "Low"],
                  "Records": [severities.get(level, 0) for level in ("critical", "high", "medium", "low")]},
                 x="Severity", y="Records")

st.divider()
st.subheader("Unified intelligence search")
with st.form("intel_search_form"):
    query = st.text_input("Search records", placeholder="CVE identifier, technique, behavior or detection…", max_chars=1000)
    selected_types = st.multiselect("Record types", ["cve", "technique", "capec", "sigma"],
                                    default=["cve", "technique", "capec", "sigma"])
    search_page_size = st.selectbox("Results per page", [10, 20, 50], index=1)
    search_clicked = st.form_submit_button("Search intelligence", type="primary")
if "intel_search_page" not in st.session_state:
    st.session_state.intel_search_page = 1
if search_clicked:
    st.session_state.intel_search_page = 1
    st.session_state.intel_search_query = query.strip()
    st.session_state.intel_search_types = selected_types
    st.session_state.intel_search_page_size = search_page_size

if st.session_state.get("intel_search_query"):
    q = st.session_state.intel_search_query
    page = st.session_state.intel_search_page
    page_size = st.session_state.get("intel_search_page_size", 20)
    filters = st.session_state.get("intel_search_types", [])
    with st.spinner("Searching tenant intelligence…"):
        result, search_error = fetch_payload(api_request, "/intelligence/search",
            params=search_params(q, filters, page, page_size))
    if search_error:
        if isinstance(search_error, requests.RequestException):
            st.error("The backend is unavailable. Search could not run.")
        else:
            show_api_error(search_error, "Intelligence search failed.")
    else:
        items = result.get("items") or []
        st.caption(f"{result.get('total', 0)} matching records · {result.get('search_mode', 'search')} search")
        if not items:
            st.info("No matching intelligence records were found for this tenant.")
        for item in items:
            label = f"{item.get('record_id', 'Unknown')} · {item.get('title') or item.get('name') or item.get('severity') or item.get('record_type')}"
            with st.container(border=True):
                left, right = st.columns([5, 1])
                left.markdown(f"**{label}**")
                left.caption(f"{item.get('record_type', '').upper()} · relevance {item.get('score', 0):.3f}")
                snippet = item.get("description") or "No description was provided by the source."
                left.write(snippet[:650] + ("…" if len(snippet) > 650 else ""))
                if right.button("Details", key=f"intel-details-{item.get('record_type')}-{item.get('record_id')}"):
                    if st.session_state.get("intel_selected") != (item.get("record_type"), item.get("record_id")):
                        st.session_state.intel_relationship_page = 1
                    st.session_state.intel_selected = (item.get("record_type"), item.get("record_id"))
        pages = page_count(result.get("total", 0), page_size)
        before, current, after = st.columns([1, 2, 1])
        if before.button("← Previous", disabled=page <= 1, key="intel-prev"):
            st.session_state.intel_search_page -= 1
            st.rerun()
        current.caption(f"Page {page} of {pages}")
        if after.button("Next →", disabled=page >= pages, key="intel-next"):
            st.session_state.intel_search_page += 1
            st.rerun()

selected = st.session_state.get("intel_selected")
if selected:
    record_type, record_id = selected
    st.divider()
    st.subheader("Record detail and relationships")
    with st.spinner("Loading record evidence…"):
        record, record_error = fetch_payload(api_request, f"/intelligence/records/{record_type}/{record_id}")
    if record_error:
        if isinstance(record_error, requests.RequestException):
            st.error("The backend is unavailable. The record could not be loaded.")
        else:
            show_api_error(record_error, "The intelligence record could not be loaded.")
    elif record is not None:
        st.markdown(f"### {record.get('record_id', record_id)} · {record.get('title') or record.get('name') or record.get('record_type', '').upper()}")
        detail_cols = st.columns(3)
        detail_cols[0].write(f"**Type:** {record.get('record_type', record_type).upper()}")
        detail_cols[1].write(f"**Severity:** {record.get('severity') or 'Not provided'}")
        detail_cols[2].write(f"**Source:** {', '.join(x.get('name', x.get('source_id', '')) for x in record.get('source_provenance', []) if isinstance(x, dict)) or 'Source record'}")
        st.write(record.get("description") or "The source did not provide a description.")
        refs = record.get("references") or []
        provenance = record.get("source_provenance") or []
        urls = []
        for ref in refs:
            url = ref.get("url") if isinstance(ref, dict) else ref
            safe_url = safe_source_url(url)
            if safe_url:
                urls.append(safe_url)
        for source in provenance:
            safe_url = safe_source_url(source.get("url")) if isinstance(source, dict) else None
            if safe_url:
                urls.append(safe_url)
        if urls:
            st.markdown("**References**")
            for url in dict.fromkeys(urls):
                st.markdown(f"- [{url}]({url})")
        with st.expander("Record evidence and source fields"):
            st.json(sanitize_evidence({key: value for key, value in record.items() if key not in {"description", "embedding"}}))
        relation_page = st.session_state.get("intel_relationship_page", 1)
        relation_size = 50
        with st.spinner("Loading linked records…"):
            relationships, relation_error = fetch_payload(api_request,
                f"/intelligence/records/{record_type}/{record_id}/relationships",
                params={"page": relation_page, "page_size": relation_size})
        if relation_error:
            if isinstance(relation_error, requests.RequestException):
                st.error("The backend is unavailable. Relationships could not be loaded.")
            else:
                show_api_error(relation_error, "Relationships could not be loaded.")
        else:
            edges = relationships.get("items") or []
            if not edges:
                st.info("No source documented relationships are available for this record.")
            else:
                st.graphviz_chart(graphviz_source(record, edges), use_container_width=True)
                for edge in edges:
                    origin = edge.get("origin") or ("inferred" if edge.get("inferred") else "official_source")
                    with st.container(border=True):
                        st.markdown(f"**{edge.get('relationship_type') or edge.get('type') or 'Related'}** · {origin.replace('_', ' ').title()}")
                        st.write(sanitize_evidence(edge.get("evidence") or edge.get("description") or "No evidence text was supplied."))
                        for url in edge.get("source_references") or []:
                            safe_url = safe_source_url(url)
                            if safe_url:
                                st.markdown(f"[Source reference]({safe_url})")
            total_pages = page_count(relationships.get("total", 0), relation_size)
            lcol, mcol, rcol = st.columns([1, 2, 1])
            if lcol.button("← Older relationships", disabled=relation_page <= 1, key="intel-rel-prev"):
                st.session_state.intel_relationship_page = relation_page - 1
                st.rerun()
            mcol.caption(f"Page {relation_page} of {total_pages}")
            if rcol.button("More relationships →", disabled=relation_page >= total_pages, key="intel-rel-next"):
                st.session_state.intel_relationship_page = relation_page + 1
                st.rerun()

st.divider()
st.subheader("Data sources and ingestion")
if can_write(user):
    st.caption("Dataset imports are manual. Selecting a source below starts its protected ingestion operation.")
    sources = [("MITRE ATT&CK", "/intelligence/mitre"), ("CAPEC", "/intelligence/capec"),
               ("NVD", "/intelligence/nvd"), ("CISA KEV", "/intelligence/cisa"), ("Sigma", "/intelligence/sigma")]
    cols = st.columns(len(sources))
    for col, (name, endpoint) in zip(cols, sources):
        if col.button(f"Import {name}", key=f"import-{endpoint}"):
            with st.spinner(f"Starting {name} ingestion…"):
                try:
                    response = api_request("POST", endpoint, timeout=180)
                except requests.RequestException:
                    st.error(f"The backend is unavailable. {name} ingestion did not complete.")
                else:
                    if response.ok:
                        payload = response.json()
                        st.success(f"{name}: {payload.get('status', 'submitted')} · {payload.get('record_count', 0)} records")
                    else:
                        show_api_error(response, f"{name} ingestion failed.")
else:
    st.info("Your role can review intelligence but cannot start dataset ingestion.")

source_payload, source_error = fetch_payload(api_request, "/intelligence/sources", params={"page": 1, "page_size": 20})
if source_error:
    if isinstance(source_error, requests.RequestException):
        st.error("The backend is unavailable. Dataset source metadata could not be loaded.")
    else:
        show_api_error(source_error, "Dataset source metadata could not be loaded.")
elif not source_payload or not source_payload.get("items"):
    st.info("No dataset sources have completed ingestion for this tenant.")
else:
    st.dataframe([{"Source": row.get("name"), "Last imported": row.get("last_imported_at"),
                   "Records": (row.get("metadata") or {}).get("total_records") or (row.get("metadata") or {}).get("processed_count") or "—",
                   "URL": safe_source_url(row.get("url"))} for row in source_payload.get("items", [])], use_container_width=True, hide_index=True)

st.subheader("Ingestion job history")
job_page = st.session_state.get("intel_job_page", 1)
job_payload, job_error = fetch_payload(api_request, "/intelligence/jobs",
                                       params={"page": job_page, "page_size": 20})
if job_error:
    if isinstance(job_error, requests.RequestException):
        st.error("The backend is unavailable. Ingestion job history could not be loaded.")
    else:
        show_api_error(job_error, "Ingestion job history could not be loaded.")
elif not job_payload or not job_payload.get("items"):
    st.info("No ingestion jobs have been recorded for this tenant.")
else:
    st.dataframe([{"Started": row.get("started_at"), "Source": row.get("source_id"),
                   "Status": row.get("status"), "Records": row.get("record_count", 0),
                   "Error": sanitize_evidence(row.get("error_message") or "—"), "Job ID": row.get("job_id")} 
                  for row in job_payload.get("items", [])], use_container_width=True, hide_index=True)
    job_total_pages = page_count(job_payload.get("total", 0), job_payload.get("page_size", 20))
    prev, label, nxt = st.columns([1, 2, 1])
    if prev.button("← Newer jobs", disabled=job_page <= 1, key="intel-job-prev"):
        st.session_state.intel_job_page = job_page - 1
        st.rerun()
    label.caption(f"Page {job_page} of {job_total_pages}")
    if nxt.button("Older jobs →", disabled=job_page >= job_total_pages, key="intel-job-next"):
        st.session_state.intel_job_page = job_page + 1
        st.rerun()
