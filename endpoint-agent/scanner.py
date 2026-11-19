from __future__ import annotations

import platform
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from network_monitor import collect_listeners
from software_inventory import collect_software_inventory
from vulnerability_checker import query_osv
from windows_security import collect_windows_security


def _finding(title: str, description: str, category: str, severity: str, component: str,
             evidence: dict[str, Any], remediation: str, *, confidence: str = "high",
             source: str = "local Windows security check", cve: str | None = None,
             rationale: str = "Severity reflects the directly observed configuration evidence.") -> dict[str, Any]:
    return {"finding_id": f"finding-{uuid.uuid4().hex}", "title": title, "description": description,
            "category": category, "severity": severity, "confidence": confidence,
            "evidence": evidence, "affected_component": component, "related_cve": cve,
            "remediation": remediation, "detected_at": datetime.now(timezone.utc).isoformat(),
            "intelligence_source": source, "rationale": rationale}


def run_scan(*, security_collector=collect_windows_security, software_collector=collect_software_inventory,
             network_collector=collect_listeners, osv_checker=query_osv,
             scan_id: str | None = None,
             progress_callback: Callable[[str], None] | None = None) -> dict[str, Any]:
    def stage(name: str) -> None:
        if progress_callback:
            progress_callback(name)

    stage("Collecting Windows security information")
    try:
        security = (security_collector(progress_callback=progress_callback)
                    if security_collector is collect_windows_security and progress_callback else security_collector())
    except Exception:
        security = {"system": {"name": platform.system()},
                    "coverage": {"windows_security": "failed", "firewall": "failed"}, "facts": {}}
    stage("Collecting installed software")
    try:
        software = software_collector()
    except Exception:
        software = {"status": "failed", "items": [], "packages": []}
    stage("Inspecting listening TCP ports")
    try:
        network = network_collector()
    except Exception:
        network = {"status": "failed", "items": []}
    facts = security.get("facts") or {}
    findings: list[dict[str, Any]] = []
    if facts.get("antivirus_enabled") is False:
        findings.append(_finding("Microsoft Defender antivirus is disabled", "Windows reports that antivirus protection is disabled.",
                                 "antivirus", "high", "Microsoft Defender", {"antivirus_enabled": False},
                                 "Review Windows Security protection settings and enable antivirus if this is not an approved security policy."))
    if facts.get("real_time_enabled") is False:
        findings.append(_finding("Microsoft Defender real-time protection is disabled", "Windows reports that real-time protection is disabled.",
                                 "antivirus", "high", "Microsoft Defender", {"real_time_enabled": False},
                                 "Review Windows Security and enable real-time protection if appropriate."))
    firewall = facts.get("firewall")
    if isinstance(firewall, list):
        for profile in firewall:
            if isinstance(profile, dict) and profile.get("Enabled") is False:
                name = str(profile.get("Name") or "Unknown")
                findings.append(_finding(f"Windows Firewall {name} profile is disabled", f"The {name} firewall profile is disabled.",
                                         "firewall", "high", f"Windows Firewall ({name})", {"profile": name, "enabled": False},
                                         "Review the profile policy and enable Windows Firewall if this is not intentional."))
    if facts.get("uac_enabled") is False:
        findings.append(_finding("User Account Control is disabled", "Windows reports EnableLUA=0, which disables standard UAC consent behavior.",
                                 "configuration", "medium", "User Account Control", {"EnableLUA": 0},
                                 "Review local security policy and enable UAC if compatible with the system's intended configuration."))
    exposed_ports = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "Remote Desktop"}
    if network.get("status") == "success":
        seen: set[tuple[int, str]] = set()
        for listener in network.get("items", []):
            if not isinstance(listener, dict):
                continue
            try:
                port = int(listener.get("local_port"))
            except (TypeError, ValueError):
                continue
            address = str(listener.get("local_address") or "unknown")
            if port in exposed_ports and address in {"0.0.0.0", "::", "*"} and (port, address) not in seen:
                seen.add((port, address))
                findings.append(_finding(f"{exposed_ports[port]} is listening on all interfaces", f"A local {exposed_ports[port]} TCP listener is bound to {address}; this does not prove it is reachable externally.",
                                         "network", "medium" if port in {445, 3389} else "high", f"TCP port {port}",
                                         {"local_address": address, "local_port": port, "process_id": listener.get("process_id"), "process_name": listener.get("process_name")},
                                         "Confirm the service is required, restrict its firewall scope, and disable it if unnecessary.",
                                         rationale="Severity is a review priority based on the service and all-interface binding; external reachability was not tested."))
    coverage = {**security.get("coverage", {}), "software_inventory": software.get("status", "unknown"),
                "listening_ports": network.get("status", "unknown"), "vulnerability_intelligence": "requires_verification"}
    # OSV is queried only for inventory entries with explicit package ecosystem coordinates.
    packages = software.get("packages", [])
    if packages:
        stage("Checking vulnerability intelligence")
    for item in packages:
        check = osv_checker(item)
        coverage["vulnerability_intelligence"] = "success" if check.get("status") in {"vulnerable", "no_known_match"} else "requires_verification"
        for match in check.get("matches", []):
            if not match.get("cve"):
                continue
            findings.append(_finding(f"{item.get('name')} is affected by {match['cve']}", match.get("summary") or "OSV matched this exact package version.",
                                     "software_vulnerability", match.get("severity", "informational"), str(item.get("name")),
                                     {"version": item.get("version"), "osv_id": match.get("id"), "cvss_score": match.get("cvss_score"), "retrieved_at": match.get("retrieved_at")},
                                     "Update to a version that the package maintainer documents as fixed; verify the applicable release before changing software.",
                                     source="OSV", cve=match["cve"], rationale="OSV returned a match for the exact package ecosystem, name, and installed version."))
    stage("Generating scan report")
    counts = {severity: sum(item["severity"] == severity for item in findings) for severity in ("critical", "high", "medium", "low", "informational")}
    return {"scan_id": scan_id or f"endpoint-{uuid.uuid4().hex}", "host_id": platform.node()[:128] or "unknown-host",
            "os_name": str(security.get("system", {}).get("name") or platform.system())[:200],
            "generated_at": datetime.now(timezone.utc).isoformat(), "findings": findings, "coverage": coverage,
            "summary": {"total_findings": len(findings), "counts": counts},
            "inventory": {
                "software": [{key: item.get(key) for key in ("name", "version", "publisher") if item.get(key)}
                             for item in software.get("items", [])[:500]],
                "listeners": [{key: item.get(key) for key in ("local_address", "local_port", "process_id", "process_name") if item.get(key) is not None}
                              for item in network.get("items", [])[:500] if isinstance(item, dict)],
                "adapters": [{key: item.get(key) for key in ("Name", "Status", "LinkSpeed") if item.get(key) is not None}
                             for item in facts.get("adapters", [])[:100] if isinstance(item, dict)],
                "windows_security": {key: facts.get(key) for key in (
                    "antivirus_enabled", "real_time_enabled", "signature_age", "firewall", "uac_enabled", "bitlocker") if facts.get(key) is not None},
            }}
