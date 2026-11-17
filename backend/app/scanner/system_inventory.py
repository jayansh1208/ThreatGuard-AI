"""Bounded, read-only Windows inventory collectors for the host scan report."""
from __future__ import annotations

import logging
from typing import Any

from backend.app.scanner.collector_utils import run_powershell_collector, scan_timestamp

MAX_INVENTORY_ITEMS = 500
logger = logging.getLogger(__name__)


def _identity(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for item in items[:MAX_INVENTORY_ITEMS]:
        key = str(item.get("id") or item.get("name") or item.get("path") or repr(item))
        unique.setdefault(key.lower(), item)
    return list(unique.values())


def _collect(name: str, command: str) -> dict[str, Any]:
    return run_powershell_collector(name, command, _identity, timeout_seconds=20)


def scan_process_inventory() -> dict[str, Any]:
    return _collect("process_inventory", """$p=Get-CimInstance Win32_Process | Select-Object -First 500; $cpu=@{}; Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue | ForEach-Object {$cpu[[string]$_.IDProcess]=$_.PercentProcessorTime}; $proc=@{}; Get-Process | ForEach-Object {$proc[[string]$_.Id]=$_}; $rows=foreach($x in $p){$g=$proc[[string]$x.ProcessId]; [pscustomobject]@{id=[string]$x.ProcessId;name=$x.Name;path=$x.ExecutablePath;cpu_percent=$cpu[[string]$x.ProcessId];cpu_seconds=if($g){[math]::Round($g.CPU,2)}else{$null};memory_mb=if($g){[math]::Round($g.WorkingSet64/1MB,1)}else{$null}}}; ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress""")


def scan_service_inventory() -> dict[str, Any]:
    return _collect("services", "ConvertTo-Json -InputObject @(Get-CimInstance Win32_Service | Select-Object -First 500 Name,DisplayName,State,StartMode,PathName) -Depth 3 -Compress")


def scan_scheduled_tasks() -> dict[str, Any]:
    return _collect("scheduled_tasks", "ConvertTo-Json -InputObject @(Get-ScheduledTask | Select-Object -First 500 TaskPath,TaskName,State,@{n='Actions';e={($_.Actions | ForEach-Object {($_.Execute+' '+$_.Arguments).Trim()}) -join '; '}}) -Depth 4 -Compress")


def scan_installed_applications() -> dict[str, Any]:
    return _collect("installed_applications", """$roots=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); $rows=Get-ItemProperty $roots -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object -First 500 @{n='id';e={$_.PSChildName}},@{n='name';e={$_.DisplayName}},DisplayVersion,Publisher,InstallDate; ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress""")


def scan_suspicious_file_metadata(paths: list[str]) -> dict[str, Any]:
    """Hash and inspect only unique executable paths already observed in this scan."""
    normalized = list(dict.fromkeys(path for path in paths if isinstance(path, str) and path.lower().endswith((".exe", ".dll", ".scr", ".sys"))))[:100]
    if not normalized:
        return {"collector_name": "file_metadata", "status": "success", "items_collected": 0,
                "error_code": None, "error_message": None, "scanned_at": scan_timestamp(), "items": [], "findings": []}
    # Pass paths through a temporary JSON string encoded as Base64 to avoid PowerShell quoting/injection.
    import base64, json
    encoded = base64.b64encode(json.dumps(normalized).encode("utf-8")).decode("ascii")
    command = f"""$paths=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}') ) | ConvertFrom-Json; $rows=foreach($p in $paths){{if(Test-Path -LiteralPath $p -PathType Leaf){{$f=Get-Item -LiteralPath $p -ErrorAction SilentlyContinue;if($f){{$sig=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue; $h=Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction SilentlyContinue;[pscustomobject]@{{path=$f.FullName;size_bytes=$f.Length;created_at=$f.CreationTimeUtc.ToString('o');modified_at=$f.LastWriteTimeUtc.ToString('o');sha256=$h.Hash;signature_status=[string]$sig.Status;signer=if($sig.SignerCertificate){{$sig.SignerCertificate.Subject}}else{{$null}}}}}}}}}};ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress"""
    def detect(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings = []
        for item in items:
            path = str(item.get("path") or "")
            lowered = path.lower().replace("/", "\\")
            unsigned = str(item.get("signature_status") or "").lower() == "notsigned"
            user_writable = any(marker in lowered for marker in ("\\appdata\\", "\\temp\\", "\\downloads\\"))
            if unsigned and user_writable:
                findings.append({
                    "severity": "medium", "category": "file_metadata",
                    "evidence_status": "suspicious_indicator",
                    "title": "Unsigned executable in a user-writable location",
                    "description": f"An executable at {path} has no digital signature and is in a user-writable location. This is an indicator for review, not proof of malware.",
                })
        return findings

    return run_powershell_collector("file_metadata", command, _identity, detector=detect, timeout_seconds=20)


def scan_antivirus_detections() -> dict[str, Any]:
    return _collect("antivirus_detections", """$rows=Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 100 @{n='id';e={$_.ThreatID}},ThreatID,DetectionTime,ActionSuccess,Resources; ConvertTo-Json -InputObject @($rows) -Depth 3 -Compress""")


def inventory_collectors(file_paths: list[str]) -> list[dict[str, Any]]:
    results = []
    for collector in (scan_process_inventory, scan_service_inventory, scan_scheduled_tasks,
                      scan_installed_applications, lambda: scan_suspicious_file_metadata(file_paths),
                      scan_antivirus_detections):
        try:
            results.append(collector())
        except Exception as exc:
            name = getattr(collector, "__name__", "file_metadata")
            logger.exception("Unexpected scanner collector failure: %s", name)
            results.append({"collector_name": name, "status": "failed", "items_collected": 0,
                            "error_code": "COLLECTOR_ERROR", "error_message": "Collector failed unexpectedly.",
                            "scanned_at": scan_timestamp(), "items": [], "findings": []})
    return results
