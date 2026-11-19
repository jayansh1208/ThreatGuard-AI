from __future__ import annotations

import json
import os
import subprocess
from typing import Any


def collect_software_inventory(*, runner=subprocess.run, is_windows: bool | None = None) -> dict[str, Any]:
    if is_windows is None:
        is_windows = os.name == "nt"
    if not is_windows:
        return {"status": "unsupported", "items": []}
    script = r"""$paths=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'); $apps=foreach($p in $paths){Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object @{n='name';e={$_.DisplayName}},@{n='version';e={$_.DisplayVersion}},@{n='publisher';e={$_.Publisher}},@{n='install_date';e={$_.InstallDate}}}; ConvertTo-Json -InputObject @($apps) -Compress"""
    try:
        result = runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=25, check=False)
        if result.returncode != 0:
            return {"status": "unknown", "items": []}
        items = json.loads(result.stdout or "[]")
        if isinstance(items, dict):
            items = [items]
        cleaned = [{key: str(item[key])[:300] for key in ("name", "version", "publisher", "install_date") if item.get(key)}
                   for item in items if isinstance(item, dict)]
        return {"status": "success", "items": cleaned[:2000]}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {"status": "unknown", "items": []}
