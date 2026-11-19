from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

import backend.app.database.connection as db_connection
from backend.app.database.repositories import AuditLogRepository, serialize_document
from backend.app.models_endpoint import EndpointScanUpload
from backend.app.security import enforce_permission, get_current_user

router = APIRouter(prefix="/endpoint", tags=["endpoint-security"])


def _db():
    return db_connection.get_db()


def _owned_query(user: dict[str, Any]) -> dict[str, str]:
    return {"org_id": user["org_id"], "tenant_id": user["tenant_id"], "user_id": user["user_id"]}


@router.post("/scans", status_code=201)
def upload_scan(payload: EndpointScanUpload, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    enforce_permission(user, "write_threats")
    collection = _db()["endpoint_scans"]
    query = {**_owned_query(user), "scan_id": payload.scan_id}
    existing = collection.find_one(query)
    if existing:
        return serialize_document(existing)
    findings = [item.model_dump(mode="json") for item in payload.findings]
    counts = Counter(item["severity"] for item in findings)
    highest = next((level for level in ("critical", "high", "medium", "low", "informational") if counts[level]), "informational")
    now = datetime.now(timezone.utc)
    summary = {
        "severity": highest, "total_findings": len(findings),
        "counts": dict(counts),
        "summary": f"Endpoint scan completed with {len(findings)} finding(s).",
    }
    record = {
        **query, "scan_id": payload.scan_id, "status": "completed", "host_id": payload.host_id,
        "os_name": payload.os_name, "generated_at": payload.generated_at,
        "summary": summary, "findings": findings, "coverage": payload.coverage,
        "inventory": payload.inventory, "created_at": now,
    }
    try:
        collection.insert_one(record)
    except Exception:
        # A concurrent retry with this scan ID is safe; return the already stored record.
        existing = collection.find_one(query)
        if existing is None:
            raise
        return serialize_document(existing)
    AuditLogRepository(_db()).log(
        org_id=user["org_id"], tenant_id=user["tenant_id"], actor_id=user["user_id"],
        action="endpoint_scan_uploaded", resource_type="endpoint_scan", resource_id=payload.scan_id,
        details={"finding_count": len(findings), "host_id": payload.host_id},
    )
    return serialize_document(record)


@router.get("/scans")
def list_scans(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
               user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    enforce_permission(user, "read_threats")
    collection = _db()["endpoint_scans"]
    query = _owned_query(user)
    total = collection.count_documents(query)
    projection = {"_id": 0, "scan_id": 1, "status": 1, "created_at": 1, "host_id": 1, "os_name": 1, "summary": 1}
    cursor = collection.find(query, projection).sort("created_at", -1).skip((page - 1) * page_size).limit(page_size)
    return {"items": [serialize_document(item) for item in cursor], "page": page, "page_size": page_size, "total": total}


@router.get("/scans/latest")
def latest_scan(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    enforce_permission(user, "read_threats")
    result = _db()["endpoint_scans"].find_one(_owned_query(user), sort=[("created_at", -1)])
    if result is None:
        raise HTTPException(status_code=404, detail="No endpoint scan exists for this tenant")
    return serialize_document(result)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    enforce_permission(user, "read_threats")
    result = _db()["endpoint_scans"].find_one({**_owned_query(user), "scan_id": scan_id})
    if result is None:
        raise HTTPException(status_code=404, detail="Endpoint scan not found for this tenant")
    return serialize_document(result)
