"""Intelligence ingestion API routes"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from backend.app.security import enforce_permission, get_current_user
from backend.app.intelligence.ingestion import (
    ingest_capec,
    ingest_cisa_kev,
    ingest_mitre_attack,
    ingest_nvd,
    ingest_sigma,
)
from backend.app.intelligence.config import (
    CAPEC_URL,
    CISA_KEV_URL,
    MITRE_ATTACK_URL,
    NVD_API_URL,
    NVD_API_KEY,
    NVD_INITIAL_MAX_RECORDS,
    NVD_PAGE_SIZE,
    SIGMA_BRANCH,
    SIGMA_MAX_RULES,
    SIGMA_REPOSITORY,
)
from backend.app.database.connection import get_db
from backend.app.intelligence.search import (
    get_intelligence_record,
    intelligence_statistics,
    list_relationships,
    search_intelligence,
)
from backend.app.intelligence.urls import safe_source_url
from backend.app.intelligence.config import INTEL_DATASET_SOURCES, INTEL_INGESTION_JOBS

router = APIRouter(prefix="/intelligence", tags=["intelligence"])


def _tenant_context(current_user: dict) -> tuple[str, str]:
    return current_user["org_id"], current_user["tenant_id"]


@router.get("/search", summary="Search intelligence records")
def search_records(
    q: str = Query(..., min_length=1, max_length=1000),
    record_type: list[str] | None = Query(default=None),
    page: int = Query(default=1, ge=1, le=100),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
) -> dict:
    enforce_permission(current_user, "read_threats")
    org_id, tenant_id = _tenant_context(current_user)
    return search_intelligence(get_db(), org_id=org_id, tenant_id=tenant_id,
                               query=q, record_types=record_type,
                               page=page, page_size=page_size)


@router.get("/records/{record_type}/{record_id}", summary="Get an intelligence record")
def get_record(record_type: str, record_id: str,
               current_user: dict = Depends(get_current_user)) -> dict:
    enforce_permission(current_user, "read_threats")
    org_id, tenant_id = _tenant_context(current_user)
    record = get_intelligence_record(get_db(), org_id=org_id, tenant_id=tenant_id,
                                     record_type=record_type, record_id=record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Intelligence record not found")
    return record


@router.get("/records/{record_type}/{record_id}/relationships", summary="List record relationships")
def get_record_relationships(
    record_type: str,
    record_id: str,
    page: int = Query(default=1, ge=1, le=100),
    page_size: int = Query(default=20, ge=1, le=100),
    inferred: bool | None = Query(default=None),
    current_user: dict = Depends(get_current_user),
) -> dict:
    enforce_permission(current_user, "read_threats")
    org_id, tenant_id = _tenant_context(current_user)
    return list_relationships(get_db(), org_id=org_id, tenant_id=tenant_id,
                             record_type=record_type, record_id=record_id,
                             page=page, page_size=page_size, inferred=inferred)


@router.get("/statistics", summary="Get intelligence record counts")
def get_statistics(current_user: dict = Depends(get_current_user)) -> dict:
    enforce_permission(current_user, "read_threats")
    org_id, tenant_id = _tenant_context(current_user)
    return intelligence_statistics(get_db(), org_id=org_id, tenant_id=tenant_id)


@router.get("/jobs", summary="List tenant intelligence ingestion jobs")
def list_ingestion_jobs(
    page: int = Query(default=1, ge=1, le=10000),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
) -> dict:
    enforce_permission(current_user, "read_threats")
    org_id, tenant_id = _tenant_context(current_user)
    collection = get_db()[INTEL_INGESTION_JOBS]
    scope = {"org_id": org_id, "tenant_id": tenant_id}
    total = int(collection.count_documents(scope))
    rows = list(collection.find(scope, {"_id": 0}).sort("started_at", -1)
                 .skip((page - 1) * page_size).limit(page_size))
    return {"items": rows, "page": page, "page_size": page_size, "total": total}


@router.get("/sources", summary="List tenant intelligence data sources")
def list_dataset_sources(
    page: int = Query(default=1, ge=1, le=10000),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
) -> dict:
    enforce_permission(current_user, "read_threats")
    org_id, tenant_id = _tenant_context(current_user)
    collection = get_db()[INTEL_DATASET_SOURCES]
    scope = {"org_id": org_id, "tenant_id": tenant_id}
    total = int(collection.count_documents(scope))
    rows = list(collection.find(scope, {"_id": 0}).sort("name", 1)
                 .skip((page - 1) * page_size).limit(page_size))
    for row in rows:
        if "url" in row:
            row["url"] = safe_source_url(row["url"])
    return {"items": rows, "page": page, "page_size": page_size, "total": total}


@router.post("/mitre", summary="Ingest MITRE ATT&CK dataset")
def trigger_mitre_ingestion(
    url: str | None = Query(default=None, description="Override MITRE ATT&CK URL"),
    current_user: dict = Depends(get_current_user),
) -> dict:
    enforce_permission(current_user, "write_threats")
    org_id, tenant_id = _tenant_context(current_user)
    source_url = url or MITRE_ATTACK_URL
    try:
        result = ingest_mitre_attack(org_id, tenant_id, source_url)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="MITRE ATT&CK ingestion failed.") from exc
    return result


@router.post("/capec", summary="Ingest CAPEC dataset")
def trigger_capec_ingestion(
    url: str | None = Query(default=None, description="Override CAPEC URL"),
    current_user: dict = Depends(get_current_user),
) -> dict:
    enforce_permission(current_user, "write_threats")
    org_id, tenant_id = _tenant_context(current_user)
    source_url = url or CAPEC_URL
    try:
        result = ingest_capec(org_id, tenant_id, source_url)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="CAPEC ingestion failed.") from exc
    return result


@router.post("/nvd", summary="Ingest NVD CVE dataset")
def trigger_nvd_ingestion(
    url: str | None = Query(default=None, description="Override NVD API URL"),
    api_key: str | None = Header(default=None, alias="X-NVD-API-Key", description="Optional NVD API key; never send credentials in a URL"),
    page_size: int = Query(default=NVD_PAGE_SIZE, ge=1, le=200, description="NVD page size"),
    max_records: int = Query(default=NVD_INITIAL_MAX_RECORDS, ge=1, le=5000,
                             description="Maximum CVE records to process in this explicit import"),
    last_modified_after: datetime | None = Query(default=None, description="Start of an incremental NVD modification window"),
    last_modified_before: datetime | None = Query(default=None, description="End of an incremental NVD modification window"),
    current_user: dict = Depends(get_current_user),
) -> dict:
    enforce_permission(current_user, "write_threats")
    org_id, tenant_id = _tenant_context(current_user)
    source_url = url or NVD_API_URL
    if bool(last_modified_after) != bool(last_modified_before):
        raise HTTPException(status_code=422, detail="Both NVD modification window timestamps are required.")
    if last_modified_after and last_modified_before:
        if (last_modified_after.tzinfo is None or last_modified_before.tzinfo is None
                or last_modified_after >= last_modified_before):
            raise HTTPException(status_code=422, detail="NVD modification timestamps must be timezone-aware and ordered.")
        start = last_modified_after.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        end = last_modified_before.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    else:
        start = end = None
    try:
        result = ingest_nvd(
            org_id,
            tenant_id,
            url=source_url,
            api_key=api_key or NVD_API_KEY,
            page_size=page_size,
            max_records=max_records,
            last_modified_after=start,
            last_modified_before=end,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail="NVD ingestion failed.") from exc
    return result


@router.post("/cisa", summary="Ingest CISA KEV catalog")
def trigger_cisa_ingestion(
    url: str | None = Query(default=None, description="Override CISA KEV URL"),
    current_user: dict = Depends(get_current_user),
) -> dict:
    enforce_permission(current_user, "write_threats")
    org_id, tenant_id = _tenant_context(current_user)
    source_url = url or CISA_KEV_URL
    try:
        result = ingest_cisa_kev(org_id, tenant_id, source_url)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="CISA KEV ingestion failed.") from exc
    return result


@router.post("/sigma", summary="Ingest Sigma detection rules")
def trigger_sigma_ingestion(
    repository: str | None = Query(default=None, description="Override Sigma repository"),
    branch: str | None = Query(default=None, description="Override Sigma branch"),
    max_rules: int = Query(default=SIGMA_MAX_RULES, ge=1, le=500,
                            description="Upper cap for imported Sigma rules"),
    current_user: dict = Depends(get_current_user),
) -> dict:
    enforce_permission(current_user, "write_threats")
    org_id, tenant_id = _tenant_context(current_user)
    try:
        result = ingest_sigma(
            org_id,
            tenant_id,
            repository=repository or SIGMA_REPOSITORY,
            branch=branch or SIGMA_BRANCH,
            max_rules=max_rules,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Sigma ingestion failed.") from exc
    return result
