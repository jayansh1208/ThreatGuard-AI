# Intelligence ingestion service
"""Functions to ingest MITRE ATT&CK and CAPEC data into MongoDB.
Idempotent upserts are performed in batches defined by
`INGESTION_BATCH_SIZE`. Import status is recorded in the
`dataset_sources` and `ingestion_jobs` collections.
"""

import datetime
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterable, List

import httpx
import yaml
from pymongo import UpdateOne

from backend.app.database.connection import get_db
from backend.app.intelligence.config import (
    CISA_KEV_URL,
    INGESTION_BATCH_SIZE,
    INGESTION_TIMEOUT_SECONDS,
    INTEL_ATTACK_PATTERNS,
    INTEL_ATTACK_TECHNIQUES,
    INTEL_DATASET_SOURCES,
    INTEL_DETECTION_RULES,
    INTEL_INGESTION_JOBS,
    INTEL_VULNERABILITIES,
    NVD_API_KEY,
    NVD_API_URL,
    NVD_PAGE_SIZE,
    NVD_REQUEST_DELAY,
    SIGMA_BRANCH,
    SIGMA_MAX_RULES,
    SIGMA_REPOSITORY,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _now() -> datetime.datetime:
    return datetime.datetime.utcnow()


def _upsert_bulk(collection_name: str, operations: List[UpdateOne]):
    if not operations:
        return 0
    db = get_db()
    result = db[collection_name].bulk_write(operations, ordered=False)
    return result.upserted_count + result.modified_count


def _record_dataset_source(source_id: str, name: str, url: str, metadata: Dict[str, Any] | None = None) -> None:
    db = get_db()
    db[INTEL_DATASET_SOURCES].update_one(
        {"source_id": source_id},
        {"$set": {"name": name, "url": url, "last_imported_at": _now(), "metadata": metadata or {}}},
        upsert=True,
    )


def _finalize_job(job_id: str, status: str, record_count: int = 0, error_message: str | None = None, **extra: Any) -> None:
    db = get_db()
    update = {"$set": {"status": status, "completed_at": _now(), "record_count": record_count}}
    if error_message is not None:
        update["$set"]["error_message"] = error_message
    for key, value in extra.items():
        update["$set"][key] = value
    db[INTEL_INGESTION_JOBS].update_one({"job_id": job_id}, update)


def _get_source_name(source_id: str) -> str:
    names = {
        "nvd": "NVD",
        "cisa_kev": "CISA KEV",
        "sigma": "Sigma",
        "mitre_attack": "MITRE ATT&CK",
        "capec": "CAPEC",
    }
    return names.get(source_id, source_id)


def _parse_iso_datetime(value: Any) -> datetime.datetime | None:
    if not value:
        return None
    if isinstance(value, datetime.datetime):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.datetime.fromisoformat(text)
        except ValueError:
            return None
    return None


def _merge_unique_list(existing: List[Any] | None, incoming: Iterable[Any] | None) -> List[Any]:
    merged = list(existing or [])
    for item in incoming or []:
        if item is None:
            continue
        if item not in merged:
            merged.append(item)
    return merged



def _merge_vulnerability_document(existing: Dict[str, Any] | None, incoming: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(existing or {})
    incoming = dict(incoming)

    for key, value in incoming.items():
        if key in {"_id", "org_id", "tenant_id", "cve_id", "created_at"}:
            continue

        if key in {"references", "affected_products", "cpe", "source_provenance"}:
            merged[key] = _merge_unique_list(
                (existing or {}).get(key),
                value
            )
            continue

        if key == "description":
            merged[key] = (existing or {}).get("description") or value or ""
            continue

        if key == "severity":
            merged[key] = (existing or {}).get("severity") or value or "unknown"
            continue

        if key in {"published_date", "last_modified_date"}:
            merged[key] = (existing or {}).get(key) or value
            continue

        if value is not None and (
            key not in merged or merged.get(key) in (None, "", [], {})
        ):
            merged[key] = value

    if incoming.get("source_provenance"):
        merged["source_provenance"] = _merge_unique_list(
            (existing or {}).get("source_provenance"),
            incoming.get("source_provenance")
        )

    # Preserve the original creation timestamp.
    # Add one when inserting a new vulnerability.
    merged["created_at"] = (
        (existing or {}).get("created_at")
        or incoming.get("created_at")
        or _now()
    )

    merged["updated_at"] = _now()

    return merged


# ---------------------------------------------------------------------------
# MITRE ATT&CK ingestion
# ---------------------------------------------------------------------------

def _process_mitre_objects(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract technique records from MITRE ATT&CK STIX bundle.
    Returns a list of dicts ready for upsert into `attack_techniques`.
    """
    records = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        external_refs = obj.get("external_references", [])
        technique_id = None
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        if not technique_id:
            continue
        record = {
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": [phase.get("phase_name") for phase in obj.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"],
            "platforms": obj.get("x_mitre_platforms", []),
            "references": [ref.get("url") for ref in external_refs if ref.get("url")],
            "created_at": _now(),
            "updated_at": _now(),
        }
        records.append(record)
    return records


def ingest_mitre_attack(org_id: str, tenant_id: str, url: str) -> Dict[str, Any]:
    """Ingest MITRE ATT&CK data for a tenant.
    Returns a dict with job summary.
    """
    db = get_db()
    job_id = str(uuid.uuid4())
    job_doc = {
        "job_id": job_id,
        "source_id": "mitre_attack",
        "status": "running",
        "started_at": _now(),
        "record_count": 0,
        "error_message": None,
    }
    db[INTEL_INGESTION_JOBS].insert_one(job_doc)

    try:
        with httpx.Client(timeout=INGESTION_TIMEOUT_SECONDS) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
        objects = data.get("objects", [])
        techniques = _process_mitre_objects(objects)
        total = len(techniques)
        ops = []
        for tech in techniques:
            filter_ = {"org_id": org_id, "tenant_id": tenant_id, "technique_id": tech["technique_id"]}
            update = {"$set": tech, "$setOnInsert": {"org_id": org_id, "tenant_id": tenant_id}}
            ops.append(UpdateOne(filter_, update, upsert=True))
            if len(ops) >= INGESTION_BATCH_SIZE:
                _upsert_bulk(INTEL_ATTACK_TECHNIQUES, ops)
                ops.clear()
        if ops:
            _upsert_bulk(INTEL_ATTACK_TECHNIQUES, ops)
        source_filter = {"source_id": "mitre_attack"}
        db[INTEL_DATASET_SOURCES].update_one(
            source_filter,
            {"$set": {"name": "MITRE ATT&CK", "url": url, "last_imported_at": _now()}},
            upsert=True,
        )
        db[INTEL_INGESTION_JOBS].update_one(
            {"job_id": job_id},
            {"$set": {"status": "completed", "completed_at": _now(), "record_count": total}},
        )
        return {"job_id": job_id, "status": "completed", "record_count": total}
    except Exception as exc:
        logger.exception("MITRE ATT&CK ingestion failed")
        db[INTEL_INGESTION_JOBS].update_one(
            {"job_id": job_id},
            {"$set": {"status": "failed", "completed_at": _now(), "error_message": str(exc)}},
        )
        return {"job_id": job_id, "status": "failed", "error": str(exc)}

# ---------------------------------------------------------------------------
# CAPEC ingestion
# ---------------------------------------------------------------------------

def _process_capec_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    records = []
    for item in items:
        capec_id = item.get("capec-id")
        if not capec_id:
            continue
        record = {
            "pattern_id": f"CAPEC-{capec_id}",
            "name": item.get("name", ""),
            "description": item.get("summary", ""),
            "technique_ids": [],
            "references": [],
            "created_at": _now(),
            "updated_at": _now(),
        }
        records.append(record)
    return records


def ingest_capec(org_id: str, tenant_id: str, url: str) -> Dict[str, Any]:
    db = get_db()
    job_id = str(uuid.uuid4())
    job_doc = {
        "job_id": job_id,
        "source_id": "capec",
        "status": "running",
        "started_at": _now(),
        "record_count": 0,
        "error_message": None,
    }
    db[INTEL_INGESTION_JOBS].insert_one(job_doc)
    try:
        with httpx.Client(timeout=INGESTION_TIMEOUT_SECONDS) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
        items = data.get("attack-patterns", [])
        patterns = _process_capec_items(items)
        total = len(patterns)
        ops = []
        for pat in patterns:
            filter_ = {"org_id": org_id, "tenant_id": tenant_id, "pattern_id": pat["pattern_id"]}
            update = {"$set": pat, "$setOnInsert": {"org_id": org_id, "tenant_id": tenant_id}}
            ops.append(UpdateOne(filter_, update, upsert=True))
            if len(ops) >= INGESTION_BATCH_SIZE:
                _upsert_bulk(INTEL_ATTACK_PATTERNS, ops)
                ops.clear()
        if ops:
            _upsert_bulk(INTEL_ATTACK_PATTERNS, ops)
        db[INTEL_DATASET_SOURCES].update_one(
            {"source_id": "capec"},
            {"$set": {"name": "CAPEC", "url": url, "last_imported_at": _now()}},
            upsert=True,
        )
        db[INTEL_INGESTION_JOBS].update_one(
            {"job_id": job_id},
            {"$set": {"status": "completed", "completed_at": _now(), "record_count": total}},
        )
        return {"job_id": job_id, "status": "completed", "record_count": total}
    except Exception as exc:
        logger.exception("CAPEC ingestion failed")
        db[INTEL_INGESTION_JOBS].update_one(
            {"job_id": job_id},
            {"$set": {"status": "failed", "completed_at": _now(), "error_message": str(exc)}},
        )
        return {"job_id": job_id, "status": "failed", "error": str(exc)}

# ---------------------------------------------------------------------------
# NVD CVE ingestion
# ---------------------------------------------------------------------------

def _extract_nvd_cvss(cve_item: Dict[str, Any]) -> Dict[str, Any]:
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"): 
        entries = metrics.get(key, [])
        if not entries:
            continue
        entry = entries[0]
        cvss_data = entry.get("cvssData", {}) if isinstance(entry, dict) else {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or entry.get("baseSeverity")
        version = cvss_data.get("version") or entry.get("version")
        return {
            "score": float(score) if score is not None else None,
            "severity": severity,
            "version": version,
        }
    return {"score": None, "severity": None, "version": None}


def _extract_nvd_description(cve_item: Dict[str, Any]) -> str:
    descriptions = cve_item.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value") or ""
    if descriptions:
        return descriptions[0].get("value") or ""
    return ""


def _extract_cpe_uris(cve_item: Dict[str, Any]) -> List[str]:
    cpes = []
    for config in cve_item.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria")
                if criteria:
                    cpes.append(criteria)
    return sorted(set(cpes))


def _extract_affected_products(cpe_uris: List[str]) -> List[str]:
    products = []
    for uri in cpe_uris:
        parts = uri.split(":")
        if len(parts) >= 5:
            vendor = parts[3]
            product = parts[4]
            if vendor not in {"", "*"} and product not in {"", "*"}:
                products.append(f"{vendor}:{product}")
    return sorted(set(products))


def _build_nvd_record(org_id: str, tenant_id: str, cve_item: Dict[str, Any], source_url: str) -> Dict[str, Any]:
    cve_id = cve_item.get("id") or cve_item.get("cve_id")
    if not cve_id:
        raise ValueError("NVD record missing CVE identifier")
    cvss = _extract_nvd_cvss(cve_item)
    cpe_uris = _extract_cpe_uris(cve_item)
    source_provenance = [{"source_id": "nvd", "name": "NVD", "url": source_url}]
    doc = {
        "org_id": org_id,
        "tenant_id": tenant_id,
        "cve_id": cve_id,
        "description": _extract_nvd_description(cve_item),
        "severity": cvss["severity"] or "unknown",
        "published_date": _parse_iso_datetime(cve_item.get("published")),
        "last_modified_date": _parse_iso_datetime(cve_item.get("lastModified")),
        "cvss_score": cvss["score"],
        "cvss_version": cvss["version"],
        "affected_products": _extract_affected_products(cpe_uris),
        "cpe": cpe_uris,
        "references": [ref.get("url") for ref in cve_item.get("references", []) if ref.get("url")],
        "source_id": "nvd",
        "source_url": source_url,
        "source_provenance": source_provenance,
        "created_at": _now(),
        "updated_at": _now(),
    }
    return doc


def ingest_nvd(
    org_id: str,
    tenant_id: str,
    url: str | None = None,
    api_key: str | None = None,
    page_size: int | None = None,
    request_delay: float | None = None,
    last_modified_after: str | None = None,
    max_records: int | None = None,
) -> Dict[str, Any]:
    db = get_db()
    job_id = str(uuid.uuid4())
    db[INTEL_INGESTION_JOBS].insert_one({
        "job_id": job_id,
        "source_id": "nvd",
        "status": "running",
        "started_at": _now(),
        "record_count": 0,
        "error_message": None,
    })
    source_url = url or NVD_API_URL
    api_key_value = api_key if api_key is not None else NVD_API_KEY
    page_size_value = int(page_size or NVD_PAGE_SIZE)
    request_delay_value = float(request_delay if request_delay is not None else NVD_REQUEST_DELAY)
    params: Dict[str, Any] = {"resultsPerPage": page_size_value, "startIndex": 0}
    if last_modified_after:
        params["lastModStartDate"] = last_modified_after
    stream_count = 0
    processed_count = 0
    updated_count = 0
    inserted_count = 0
    skipped_count = 0
    limited = False
    operations: List[UpdateOne] = []
    start_index = 0

    try:
        with httpx.Client(timeout=INGESTION_TIMEOUT_SECONDS) as client:
            headers = {"apiKey": api_key_value} if api_key_value else None
            while True:
                page_params = dict(params)
                page_params["startIndex"] = start_index
                response = client.get(source_url, params=page_params, headers=headers)
                if response.status_code in {403, 429}:
                    raise RuntimeError("NVD API rate limit or authorization rejected")
                response.raise_for_status()
                payload = response.json()
                items = payload.get("vulnerabilities", [])
                if not items:
                    break
                for item in items:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    if not cve_id:
                        skipped_count += 1
                        continue
                    if max_records is not None and processed_count >= max_records:
                        limited = True
                        break
                    record = _build_nvd_record(org_id, tenant_id, cve, source_url)
                    filter_ = {"org_id": org_id, "tenant_id": tenant_id, "cve_id": cve_id}
                    existing = db[INTEL_VULNERABILITIES].find_one(filter_)
                    merged = _merge_vulnerability_document(existing, record)
                    operations.append(UpdateOne(filter_, {"$set": merged}, upsert=True))
                    processed_count += 1
                    if len(operations) >= INGESTION_BATCH_SIZE:
                        _upsert_bulk(INTEL_VULNERABILITIES, operations)
                        operations.clear()
                        inserted_count += len([op for op in operations if op is not None])
                if limited:
                    break
                if len(items) < page_size_value:
                    break
                start_index += len(items)
                if request_delay_value > 0:
                    time.sleep(request_delay_value)
                if max_records is not None and processed_count >= max_records:
                    limited = True
                    break
            if operations:
                _upsert_bulk(INTEL_VULNERABILITIES, operations)
        if processed_count == 0:
            updated_count = 0
            inserted_count = 0
        _record_dataset_source("nvd", "NVD", source_url, {"page_size": page_size_value, "limited": limited, "processed_count": processed_count})
        _finalize_job(job_id, "completed", record_count=processed_count, inserted_count=inserted_count, updated_count=updated_count, skipped_count=skipped_count, limited=limited)
        return {"job_id": job_id, "status": "completed", "record_count": processed_count, "inserted": inserted_count, "updated": updated_count, "skipped": skipped_count, "limited": limited}
    except Exception as exc:
        logger.exception("NVD ingestion failed")
        _finalize_job(job_id, "failed", record_count=processed_count, error_message=str(exc), skipped_count=skipped_count, limited=limited)
        return {"job_id": job_id, "status": "failed", "error": str(exc), "record_count": processed_count, "skipped": skipped_count, "limited": limited}

# ---------------------------------------------------------------------------
# CISA KEV ingestion
# ---------------------------------------------------------------------------

def _build_cisa_record(org_id: str, tenant_id: str, item: Dict[str, Any], source_url: str) -> Dict[str, Any]:
    cve_id = item.get("cveID") or item.get("cve_id")
    if not cve_id:
        raise ValueError("CISA KEV record missing CVE identifier")
    doc = {
        "org_id": org_id,
        "tenant_id": tenant_id,
        "cve_id": cve_id,
        "description": item.get("shortDescription") or item.get("vulnerabilityName") or "",
        "severity": item.get("severity") or "unknown",
        "published_date": _parse_iso_datetime(item.get("dateAdded")) or _parse_iso_datetime(item.get("knownRansomwareCampaignUse")),
        "last_modified_date": _parse_iso_datetime(item.get("dateAdded")),
        "affected_products": [f"{item.get('vendorProject')}:{item.get('product')}" ] if item.get("vendorProject") and item.get("product") else [],
        "references": [item.get("url")] if item.get("url") else [],
        "source_id": "cisa_kev",
        "source_url": source_url,
        "required_action": item.get("requiredAction"),
        "due_date": _parse_iso_datetime(item.get("dueDate")),
        "known_ransomware_campaign_use": bool(item.get("knownRansomwareCampaignUse")),
        "vendor": item.get("vendorProject"),
        "product": item.get("product"),
        "source_provenance": [{"source_id": "cisa_kev", "name": "CISA KEV", "url": source_url}],
        "created_at": _now(),
        "updated_at": _now(),
    }
    return doc


def ingest_cisa_kev(org_id: str, tenant_id: str, url: str | None = None) -> Dict[str, Any]:
    db = get_db()
    job_id = str(uuid.uuid4())
    db[INTEL_INGESTION_JOBS].insert_one({
        "job_id": job_id,
        "source_id": "cisa_kev",
        "status": "running",
        "started_at": _now(),
        "record_count": 0,
        "error_message": None,
    })
    source_url = url or CISA_KEV_URL
    operations: List[UpdateOne] = []
    inserted_count = 0
    updated_count = 0
    skipped_count = 0
    processed_count = 0
    try:
        with httpx.Client(timeout=INGESTION_TIMEOUT_SECONDS) as client:
            response = client.get(source_url)
            response.raise_for_status()
            payload = response.json()
        items = payload.get("vulnerabilities", [])
        for item in items:
            cve_id = item.get("cveID")
            if not cve_id:
                skipped_count += 1
                continue
            record = _build_cisa_record(org_id, tenant_id, item, source_url)
            filter_ = {"org_id": org_id, "tenant_id": tenant_id, "cve_id": cve_id}
            existing = db[INTEL_VULNERABILITIES].find_one(filter_)
            merged = _merge_vulnerability_document(existing, record)
            operations.append(UpdateOne(filter_, {"$set": merged}, upsert=True))
            processed_count += 1
            if len(operations) >= INGESTION_BATCH_SIZE:
                result = _upsert_bulk(INTEL_VULNERABILITIES, operations)
                updated_count += result
                operations.clear()
        if operations:
            result = _upsert_bulk(INTEL_VULNERABILITIES, operations)
            updated_count += result
        _record_dataset_source("cisa_kev", "CISA KEV", source_url, {"total_records": processed_count})
        _finalize_job(job_id, "completed", record_count=processed_count, inserted_count=inserted_count, updated_count=updated_count, skipped_count=skipped_count)
        return {"job_id": job_id, "status": "completed", "record_count": processed_count, "inserted": inserted_count, "updated": updated_count, "skipped": skipped_count}
    except Exception as exc:
        logger.exception("CISA KEV ingestion failed")
        _finalize_job(job_id, "failed", record_count=processed_count, error_message=str(exc), skipped_count=skipped_count)
        return {"job_id": job_id, "status": "failed", "error": str(exc), "record_count": processed_count, "skipped": skipped_count}

# ---------------------------------------------------------------------------
# Sigma ingestion
# ---------------------------------------------------------------------------

def _discover_sigma_files(repo: str, branch: str, max_rules: int | None = None) -> List[str]:
    url = f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
    with httpx.Client(timeout=INGESTION_TIMEOUT_SECONDS) as client:
        response = client.get(url, headers={"Accept": "application/vnd.github+json"})
        response.raise_for_status()
        payload = response.json()
    tree = payload.get("tree", [])
    files = []
    for item in tree:
        path = item.get("path")
        if not path or item.get("type") != "blob":
            continue
        lower = path.lower()
        if lower.endswith((".yml", ".yaml")) and ("/rules/" in lower or lower.startswith("rules/")):
            files.append(path)
    if max_rules is not None:
        return files[:max_rules]
    return files

import textwrap
def _parse_sigma_rule(raw_text: str, source_path: str, source_url: str, org_id: str, tenant_id: str) -> Dict[str, Any] | None:
    raw_text = textwrap.dedent(raw_text).strip()
    try:
        data = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    rule_id = data.get("id") or data.get("title") or None
    title = data.get("title") or rule_id or "Untitled Sigma Rule"
    description = data.get("description") or ""
    if not rule_id or not description:
        return None
    tags = data.get("tags") or []
    technique_refs = []
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("attack.t"):
            technique_refs.append(tag)
    detection = data.get("detection")
    log_source = data.get("logsource") or {}
    record = {
        "org_id": org_id,
        "tenant_id": tenant_id,
        "rule_id": str(rule_id),
        "title": str(title),
        "description": str(description),
        "status": data.get("status", "experimental"),
        "logsource": log_source,
        "detection": detection,
        "level": data.get("level"),
        "tags": tags,
        "technique_refs": technique_refs,
        "source_path": source_path,
        "source_url": source_url,
        "source_repo": SIGMA_REPOSITORY,
        "source_branch": SIGMA_BRANCH,
        "sigma": raw_text,
        "created_at": _now(),
        "updated_at": _now(),
    }
    return record


def ingest_sigma(
    org_id: str,
    tenant_id: str,
    repository: str | None = None,
    branch: str | None = None,
    max_rules: int | None = None,
) -> Dict[str, Any]:
    db = get_db()
    job_id = str(uuid.uuid4())
    db[INTEL_INGESTION_JOBS].insert_one({
        "job_id": job_id,
        "source_id": "sigma",
        "status": "running",
        "started_at": _now(),
        "record_count": 0,
        "error_message": None,
    })
    repo_name = repository or SIGMA_REPOSITORY
    branch_name = branch or SIGMA_BRANCH
    max_rule_cap = int(max_rules) if max_rules is not None else SIGMA_MAX_RULES
    inserted_count = 0
    updated_count = 0
    skipped_count = 0
    processed_count = 0
    limit_hit = False
    operations: List[UpdateOne] = []
    try:
        files = _discover_sigma_files(repo_name, branch_name, max_rule_cap)
        for source_path in files:
            if max_rule_cap is not None and processed_count >= max_rule_cap:
                limit_hit = True
                break
            raw_url = f"https://raw.githubusercontent.com/{repo_name}/{branch_name}/{source_path}"
            with httpx.Client(timeout=INGESTION_TIMEOUT_SECONDS) as client:
                response = client.get(raw_url)
                if response.status_code >= 400:
                    skipped_count += 1
                    continue
                payload = response.text
            rule = _parse_sigma_rule(payload, source_path, raw_url, org_id, tenant_id)
            if rule is None:
                skipped_count += 1
                continue
            filter_ = {"org_id": org_id, "tenant_id": tenant_id, "rule_id": rule["rule_id"]}
            existing = db[INTEL_DETECTION_RULES].find_one(filter_)
            merged = dict(existing or {})
            for key, value in rule.items():
                if key in {"_id", "org_id", "tenant_id", "rule_id", "created_at"}:
                    continue
                if value is not None and (key not in merged or merged.get(key) in (None, "", [], {})):
                    merged[key] = value
            merged["updated_at"] = _now()
            if existing is None:
                merged.setdefault("created_at", _now())
            operations.append(UpdateOne(filter_, {"$set": merged}, upsert=True))
            processed_count += 1
            if len(operations) >= INGESTION_BATCH_SIZE:
                result = _upsert_bulk(INTEL_DETECTION_RULES, operations)
                updated_count += result
                operations.clear()
        if operations:
            result = _upsert_bulk(INTEL_DETECTION_RULES, operations)
            updated_count += result
        _record_dataset_source("sigma", "Sigma", f"https://github.com/{repo_name}", {"branch": branch_name, "cap": max_rule_cap, "files_seen": len(files), "limit_hit": limit_hit})
        _finalize_job(job_id, "completed", record_count=processed_count, inserted_count=inserted_count, updated_count=updated_count, skipped_count=skipped_count, limited=limit_hit)
        return {"job_id": job_id, "status": "completed", "record_count": processed_count, "inserted": inserted_count, "updated": updated_count, "skipped": skipped_count, "limited": limit_hit, "complete": not limit_hit}
    except Exception as exc:
        logger.exception("Sigma ingestion failed")
        _finalize_job(job_id, "failed", record_count=processed_count, error_message=str(exc), skipped_count=skipped_count, limited=limit_hit)
        return {"job_id": job_id, "status": "failed", "error": str(exc), "record_count": processed_count, "skipped": skipped_count, "limited": limit_hit}
