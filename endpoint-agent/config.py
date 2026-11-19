from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))


@dataclass(frozen=True)
class AgentConfig:
    backend_url: str = os.getenv("THREATGUARD_URL", "http://127.0.0.1:8000").rstrip("/")
    timeout_seconds: int = max(3, min(60, int(os.getenv("THREATGUARD_TIMEOUT", "15"))))
    verify_tls: bool = os.getenv("THREATGUARD_VERIFY_TLS", "true").lower() == "true"

    def __post_init__(self) -> None:
        parsed = urlparse(self.backend_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("THREATGUARD_URL must be an HTTP(S) URL")
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and parsed.hostname not in local_hosts:
            raise ValueError("Remote ThreatGuard backends must use HTTPS")
        if parsed.hostname not in local_hosts and not self.verify_tls:
            raise ValueError("TLS verification cannot be disabled for a remote backend")
