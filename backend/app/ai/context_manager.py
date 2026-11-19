from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pymongo.database import Database

from backend.app.config import CHAT_SCANNER_CONTEXT_LIMIT

SCAN_TERMS = ("scan", "scanner", "finding", "findings", "alert", "host result", "security result",
              "my computer", "my pc", "endpoint", "fix first", "critical vulnerabilit",
              "security risk", "windows defender", "firewall", "vulnerabilit", "cve-",
              "what changed", "applications should i update")


def scanner_context_requested(question: str, explicit: bool = False) -> bool:
    lowered = question.lower()
    return explicit or any(term in lowered for term in SCAN_TERMS)


def load_scanner_evidence(db: Database, *, org_id: str, tenant_id: str, user_id: str | None = None) -> list[dict[str, Any]]:
    """Read only stored scanner records within the authenticated tenant."""
    projection = {"_id": 0, "scan_id": 1, "created_at": 1, "summary": 1, "host_id": 1,
                 "generated_at": 1, "coverage": 1, "findings": 1}
    cursor = (db["scan_results"].find(
        {"org_id": org_id, "tenant_id": tenant_id},
        {"_id": 0, "scan_id": 1, "created_at": 1, "summary": 1, "details.host": 1,
         "details.generated_at": 1, "details.completeness": 1, "details.findings": 1},
    ).sort("created_at", -1).limit(max(1, CHAT_SCANNER_CONTEXT_LIMIT)))
    legacy_records = list(cursor)
    endpoint_records = []
    if user_id:
        endpoint_records = list(db["endpoint_scans"].find(
            {"org_id": org_id, "tenant_id": tenant_id, "user_id": user_id}, projection,
        ).sort("created_at", -1).limit(max(1, CHAT_SCANNER_CONTEXT_LIMIT)))
    def created_rank(item: dict[str, Any]) -> float:
        value = item.get("created_at")
        if not isinstance(value, datetime):
            return 0.0
        return value.replace(tzinfo=value.tzinfo or timezone.utc).timestamp()

    all_records = sorted([*legacy_records, *endpoint_records], key=created_rank, reverse=True)
    records = []
    for item in all_records[:max(1, CHAT_SCANNER_CONTEXT_LIMIT)]:
        details = item.get("details") or item
        # Exclude command lines and other raw host fields. Keep only stored, explicit evidence.
        findings = []
        stored_findings = details.get("findings")
        if not isinstance(stored_findings, list):
            stored_findings = []
        for finding in stored_findings[:50]:
            if not isinstance(finding, dict):
                continue
            findings.append({key: str(finding[key])[:1000] for key in (
                "category", "title", "description", "severity", "confidence", "affected_component",
                "related_cve", "remediation", "intelligence_source", "rationale", "status") if finding.get(key) is not None})
            if isinstance(finding.get("evidence"), dict):
                findings[-1]["evidence"] = {str(key)[:100]: str(value)[:300]
                                              for key, value in list(finding["evidence"].items())[:10]}
        records.append({
            "scan_id": item.get("scan_id"),
            "generated_at": details.get("generated_at") or item.get("created_at"),
            "host": details.get("host") or details.get("host_id"),
            "summary": str(details.get("summary") or item.get("summary") or "")[:1500],
            "completeness": details.get("completeness") or details.get("coverage"),
            "findings": findings,
        })
    return records
