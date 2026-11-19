from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EndpointFinding(BaseModel):
    finding_id: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(min_length=1, max_length=2000)
    category: str = Field(min_length=1, max_length=80)
    severity: Literal["critical", "high", "medium", "low", "informational"]
    confidence: Literal["high", "medium", "low"]
    status: Literal["open", "acknowledged", "resolved"] = "open"
    evidence: dict[str, str | int | float | bool | None] = Field(default_factory=dict, max_length=20)
    affected_component: str = Field(default="Windows host", max_length=240)
    related_cve: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$", max_length=32)
    remediation: str = Field(min_length=1, max_length=2000)
    detected_at: datetime
    intelligence_source: str = Field(default="local check", max_length=300)
    rationale: str = Field(default="", max_length=1000)
    model_config = ConfigDict(extra="forbid")

    @field_validator("evidence")
    @classmethod
    def evidence_values_are_bounded(cls, value: dict) -> dict:
        if any(len(str(key)) > 100 or (isinstance(item, str) and len(item) > 1000) for key, item in value.items()):
            raise ValueError("Evidence fields exceed the allowed size")
        return value


class EndpointScanUpload(BaseModel):
    scan_id: str = Field(pattern=r"^endpoint-[a-f0-9]{32}$")
    scan_request_id: str | None = Field(default=None, pattern=r"^request-[a-f0-9]{32}$")
    host_id: str = Field(min_length=1, max_length=128)
    os_name: str = Field(min_length=1, max_length=200)
    generated_at: datetime
    findings: list[EndpointFinding] = Field(max_length=500)
    coverage: dict[str, Literal["success", "unknown", "unsupported", "failed", "requires_verification"]] = Field(max_length=30)
    inventory: dict[str, object] = Field(default_factory=dict)
    summary: dict[str, object] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid")

    @field_validator("inventory")
    @classmethod
    def inventory_is_bounded(cls, value: dict[str, object]) -> dict[str, object]:
        if set(value) - {"software", "listeners", "adapters", "windows_security"}:
            raise ValueError("Unsupported endpoint inventory category")
        if len(json.dumps(value, default=str)) > 500_000:
            raise ValueError("Endpoint inventory exceeds the allowed size")
        for name in ("software", "listeners", "adapters"):
            rows = value.get(name, [])
            if not isinstance(rows, list) or len(rows) > 500:
                raise ValueError("Endpoint inventory row count exceeds the allowed size")
        if not isinstance(value.get("windows_security", {}), dict):
            raise ValueError("Windows security observations must be an object")
        return value


class EndpointAgentStatus(BaseModel):
    connected: bool
    message: str
