from __future__ import annotations

import csv
import io
import json
from typing import Any


def scan_details(scan: dict[str, Any]) -> dict[str, Any]:
    return scan.get("details") or {key: scan.get(source) for key, source in {
        "host": "host_id", "generated_at": "generated_at", "summary": "summary",
        "coverage": "coverage", "findings": "findings", "inventory": "inventory",
    }.items()}


def text_report(scan: dict[str, Any]) -> str:
    details = scan_details(scan)
    summary = details.get("summary") or {}
    findings = details.get("findings") or []
    lines = [
        "ThreatGuard AI — Endpoint Security Scan Report",
        f"Scan ID: {scan.get('scan_id', 'Unknown')}",
        f"Host: {details.get('host') or scan.get('host_id') or 'Unknown'}",
        f"Operating system: {scan.get('os_name') or 'Unknown'}",
        f"Generated: {details.get('generated_at') or scan.get('generated_at') or scan.get('created_at') or 'Unknown'}",
        f"Report status: {'Stored by backend' if scan.get('scan_id') else 'Unknown'}",
        "",
        "Summary",
        f"Total findings: {summary.get('total_findings', len(findings))}",
    ]
    for severity in ("critical", "high", "medium", "low", "informational"):
        lines.append(f"{severity.title()} findings: {(summary.get('counts') or {}).get(severity, 0)}")
    lines.extend(["", "Check coverage"])
    for name, status in (details.get("coverage") or {}).items():
        lines.append(f"{name}: {status}")
    lines.extend(["", "Findings"])
    if not findings:
        lines.append("No findings were reported by this scan.")
    for index, finding in enumerate(findings, 1):
        lines.extend([
            f"{index}. [{str(finding.get('severity', 'unknown')).upper()}] {finding.get('title', 'Finding')}",
            f"Category: {finding.get('category', 'Unknown')}",
            f"Component: {finding.get('affected_component', 'Unknown')}",
            f"Description: {finding.get('description', '')}",
            f"Evidence: {json.dumps(finding.get('evidence') or {}, ensure_ascii=False, default=str)}",
            f"Recommended action: {finding.get('remediation', 'Review the finding.')}",
            "",
        ])
    lines.extend(["Collected inventory", json.dumps(details.get("inventory") or {}, indent=2, ensure_ascii=False, default=str)])
    return "\n".join(lines)


def json_report(scan: dict[str, Any]) -> str:
    return json.dumps(scan, indent=2, ensure_ascii=False, default=str)


def csv_findings(scan: dict[str, Any]) -> str:
    findings = scan_details(scan).get("findings") or []
    output = io.StringIO(newline="")
    fields = ["finding_id", "severity", "title", "category", "affected_component", "related_cve",
              "confidence", "status", "description", "evidence", "remediation"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for item in findings:
        row = dict(item)
        row["evidence"] = json.dumps(row.get("evidence") or {}, ensure_ascii=False, default=str)
        writer.writerow(row)
    return output.getvalue()
