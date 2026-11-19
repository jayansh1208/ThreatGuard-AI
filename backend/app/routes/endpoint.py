from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

import backend.app.database.connection as db_connection
from backend.app.database.repositories import AuditLogRepository, serialize_document
from backend.app.models_endpoint import EndpointScanUpload
from backend.app.security import enforce_permission, get_current_user

router = APIRouter(prefix="/endpoint", tags=["endpoint-security"])
logger = logging.getLogger(__name__)


def _db():
    return db_connection.get_db()


def _owned_query(user: dict[str, Any]) -> dict[str, str]:
    return {"org_id": user["org_id"], "tenant_id": user["tenant_id"], "user_id": user["user_id"]}


@router.post("/scans", status_code=201)
def upload_scan(payload: EndpointScanUpload, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    enforce_permission(user, "write_threats")
    logger.info("endpoint_scan_upload_received", extra={
        "event": "endpoint_scan_upload_received", "scan_request_id": payload.scan_request_id,
        "scan_id": payload.scan_id, "endpoint_id": payload.host_id,
        "tenant_id": user.get("tenant_id"), "user_id": user.get("user_id"),
    })
    collection = _db()["endpoint_scans"]
    query = {**_owned_query(user), "scan_id": payload.scan_id}
    existing = collection.find_one(query)
    if existing:
        if payload.scan_request_id and existing.get("scan_request_id") not in (None, payload.scan_request_id):
            raise HTTPException(status_code=409, detail="This scan ID is already associated with another scan request")
        logger.info("endpoint_scan_persistence_succeeded", extra={
            "event": "endpoint_scan_persistence_succeeded", "scan_request_id": payload.scan_request_id,
            "scan_id": existing.get("scan_id"), "endpoint_id": existing.get("endpoint_id") or existing.get("host_id"),
            "tenant_id": user.get("tenant_id"), "user_id": user.get("user_id"), "idempotent": True,
        })
        return serialize_document(existing)
    if payload.scan_request_id:
        request_query = {**_owned_query(user), "scan_request_id": payload.scan_request_id}
        existing_request = collection.find_one(request_query)
        if existing_request:
            if existing_request.get("scan_id") != payload.scan_id:
                raise HTTPException(status_code=409, detail="This scan request is already associated with a different persisted scan ID")
            return serialize_document(existing_request)
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
        "scan_request_id": payload.scan_request_id, "endpoint_id": payload.host_id,
        "os_name": payload.os_name, "generated_at": payload.generated_at,
        "summary": summary, "findings": findings, "coverage": payload.coverage,
        "inventory": payload.inventory, "created_at": now,
    }
    try:
        collection.insert_one(record)
    except Exception:
        # A concurrent retry with this scan ID is safe; return the already stored record.
        existing = collection.find_one(query)
        if existing is not None:
            return serialize_document(existing)
        if payload.scan_request_id:
            existing_request = collection.find_one({
                **_owned_query(user), "scan_request_id": payload.scan_request_id,
            })
            if existing_request is not None:
                if existing_request.get("scan_id") != payload.scan_id:
                    raise HTTPException(status_code=409, detail="This scan request is already associated with a different persisted scan ID")
                return serialize_document(existing_request)
        logger.exception("endpoint_scan_persistence_failed", extra={
            "event": "endpoint_scan_persistence_failed", "scan_request_id": payload.scan_request_id,
            "scan_id": payload.scan_id, "endpoint_id": payload.host_id,
            "tenant_id": user.get("tenant_id"),
        })
        raise
    AuditLogRepository(_db()).log(
        org_id=user["org_id"], tenant_id=user["tenant_id"], actor_id=user["user_id"],
        action="endpoint_scan_uploaded", resource_type="endpoint_scan", resource_id=payload.scan_id,
        details={"finding_count": len(findings), "host_id": payload.host_id},
    )
    logger.info("endpoint_scan_persistence_succeeded", extra={
        "event": "endpoint_scan_persistence_succeeded", "scan_request_id": payload.scan_request_id,
        "scan_id": payload.scan_id, "endpoint_id": payload.host_id,
        "tenant_id": user.get("tenant_id"), "user_id": user.get("user_id"), "idempotent": False,
    })
    return serialize_document(record)


@router.get("/scans/by-request/{scan_request_id}")
def get_scan_by_request(scan_request_id: str, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """Resolve a request to its persisted report inside the caller's own account scope."""
    enforce_permission(user, "read_threats")
    result = _db()["endpoint_scans"].find_one({
        **_owned_query(user), "scan_request_id": scan_request_id,
    })
    if result is None:
        logger.info("endpoint_scan_request_report_missing", extra={
            "event": "endpoint_scan_request_report_missing", "scan_request_id": scan_request_id,
            "tenant_id": user.get("tenant_id"), "user_id": user.get("user_id"),
        })
        raise HTTPException(
            status_code=404,
            detail="Windows scan completed, but the report has not been received by ThreatGuard yet.",
        )
    logger.info("endpoint_scan_request_report_resolved", extra={
        "event": "endpoint_scan_request_report_resolved", "scan_request_id": scan_request_id,
        "scan_id": result.get("scan_id"), "endpoint_id": result.get("endpoint_id") or result.get("host_id"),
        "tenant_id": user.get("tenant_id"),
    })
    return serialize_document(result)


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
