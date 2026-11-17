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

router = APIRouter(prefix="/intelligence", tags=["intelligence"])


def _tenant_context(current_user: dict) -> tuple[str, str]:
    return current_user["org_id"], current_user["tenant_id"]


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
