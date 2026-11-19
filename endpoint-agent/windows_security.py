from __future__ import annotations

import json
import os
import platform
import subprocess
from typing import Any, Callable


def collect_windows_security(*, runner=subprocess.run, is_windows: bool | None = None,
                            progress_callback: Callable[[str], None] | None = None) -> dict[str, Any]:
    if is_windows is None:
        is_windows = os.name == "nt"
    system = {"name": platform.system(), "version": platform.version(), "release": platform.release(), "build": platform.version()}
    if not is_windows:
        return {"system": system, "coverage": {"windows_security": "unsupported"}, "facts": {}}
    script = r"""$os=Get-CimInstance Win32_OperatingSystem; $mp=Get-MpComputerStatus -ErrorAction SilentlyContinue; $fw=@(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled); $uac=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue; $adapters=@(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name,Status,LinkSpeed); $bl=@(Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint,VolumeStatus,ProtectionStatus); $out=[ordered]@{caption=$os.Caption;version=$os.Version;build=$os.BuildNumber;defender_available=($null -ne $mp);antivirus_enabled=$mp.AntivirusEnabled;real_time_enabled=$mp.RealTimeProtectionEnabled;signature_age=$mp.AntivirusSignatureAge;firewall=$fw;uac_enabled=$uac.EnableLUA;adapters=$adapters;bitlocker=$bl}; ConvertTo-Json -InputObject $out -Compress -Depth 4"""
    try:
        if progress_callback:
            progress_callback("Checking firewall configuration")
        result = runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=25, check=False)
        if result.returncode != 0:
            return {"system": system, "coverage": {"windows_security": "unknown"}, "facts": {}}
        facts = json.loads(result.stdout)
        coverage = {"windows_security": "success", "updates": "unknown", "bitlocker": "unknown", "security_center": "unknown"}
        coverage["defender"] = "success" if facts.get("defender_available") else "unknown"
        coverage["firewall"] = "success" if isinstance(facts.get("firewall"), list) and facts["firewall"] else "unknown"
        coverage["network_adapters"] = "success" if isinstance(facts.get("adapters"), list) and facts["adapters"] else "unknown"
        coverage["bitlocker"] = "success" if isinstance(facts.get("bitlocker"), list) and facts["bitlocker"] else "unknown"
        return {"system": {"name": facts.get("caption") or system["name"], "version": facts.get("version") or system["version"], "build": facts.get("build") or system["build"]}, "coverage": coverage, "facts": facts}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {"system": system, "coverage": {"windows_security": "unknown"}, "facts": {}}
