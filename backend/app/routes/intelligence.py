"""Intelligence ingestion API routes"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
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
        raise HTTPException(status_code=500, detail=str(exc)) from exc
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
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result


@router.post("/nvd", summary="Ingest NVD CVE dataset")
def trigger_nvd_ingestion(
    url: str | None = Query(default=None, description="Override NVD API URL"),
    api_key: str | None = Query(default=None, description="Optional NVD API key"),
    page_size: int | None = Query(default=None, description="NVD page size"),
    current_user: dict = Depends(get_current_user),
) -> dict:
    enforce_permission(current_user, "write_threats")
    org_id, tenant_id = _tenant_context(current_user)
    source_url = url or NVD_API_URL
    try:
        result = ingest_nvd(
            org_id,
            tenant_id,
            url=source_url,
            api_key=api_key or NVD_API_KEY,
            page_size=page_size or NVD_PAGE_SIZE,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
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
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result


@router.post("/sigma", summary="Ingest Sigma detection rules")
def trigger_sigma_ingestion(
    repository: str | None = Query(default=None, description="Override Sigma repository"),
    branch: str | None = Query(default=None, description="Override Sigma branch"),
    max_rules: int | None = Query(default=None, description="Upper cap for imported Sigma rules"),
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
            max_rules=max_rules or SIGMA_MAX_RULES,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result
