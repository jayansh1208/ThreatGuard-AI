from __future__ import annotations

import json
import os
import subprocess
from typing import Any


def collect_listeners(*, runner=subprocess.run, is_windows: bool | None = None) -> dict[str, Any]:
    if is_windows is None:
        is_windows = os.name == "nt"
    if not is_windows:
        return {"status": "unsupported", "items": []}
    script = """$rows=Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; [pscustomobject]@{local_address=$_.LocalAddress;local_port=$_.LocalPort;process_id=$_.OwningProcess;process_name=$p.ProcessName}}; ConvertTo-Json -InputObject @($rows) -Compress"""
    try:
        result = runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=20, check=False)
        if result.returncode != 0:
            return {"status": "unknown", "items": []}
        data = json.loads(result.stdout or "[]")
        return {"status": "success", "items": data if isinstance(data, list) else [data]}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {"status": "unknown", "items": []}
