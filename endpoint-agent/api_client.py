from __future__ import annotations

import time
from typing import Any

import requests

from config import AgentConfig


class ThreatGuardClient:
    def __init__(self, config: AgentConfig | None = None, *, session: Any = requests.Session):
        self.config = config or AgentConfig()
        self.session = session()
        self.token: str | None = None

    def check_connection(self) -> bool:
        response = self.session.get(f"{self.config.backend_url}/health", timeout=self.config.timeout_seconds,
                                    verify=self.config.verify_tls)
        response.raise_for_status()
        return response.json().get("status") == "ok"

    def login(self, email: str, password: str, *, org_id: str | None = None, tenant_id: str | None = None) -> dict[str, Any]:
        payload = {"email": email, "password": password}
        if org_id and tenant_id:
            payload.update(org_id=org_id, tenant_id=tenant_id)
        response = self.session.post(f"{self.config.backend_url}/auth/login", json=payload,
                                     timeout=self.config.timeout_seconds, verify=self.config.verify_tls)
        response.raise_for_status()
        data = response.json()
        self.token = data["access_token"]
        return data["user"]

    def upload_scan(self, report: dict[str, Any]) -> dict[str, Any]:
        if not self.token:
            raise RuntimeError("Authenticate before uploading a scan")
        headers = {"Authorization": f"Bearer {self.token}"}
        for attempt in range(3):
            try:
                response = self.session.post(f"{self.config.backend_url}/endpoint/scans", json=report,
                                             headers=headers, timeout=self.config.timeout_seconds,
                                             verify=self.config.verify_tls)
            except requests.RequestException:
                if attempt < 2:
                    time.sleep(0.5 * (2 ** attempt))
                    continue
                raise
            if response.status_code == 401:
                self.token = None
                raise PermissionError("Authentication expired; sign in again before retrying.")
            if response.status_code not in {429, 500, 502, 503, 504}:
                response.raise_for_status()
                return response.json()
            if attempt < 2:
                time.sleep(0.5 * (2 ** attempt))
        response.raise_for_status()
        return {}
