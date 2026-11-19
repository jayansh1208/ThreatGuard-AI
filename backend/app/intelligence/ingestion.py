# Intelligence ingestion service
"""Functions to ingest MITRE ATT&CK and CAPEC data into MongoDB.
Idempotent upserts are performed in batches defined by
`INGESTION_BATCH_SIZE`. Import status is recorded in the
`dataset_sources` and `ingestion_jobs` collections.
"""

import datetime
import io
import logging
import os
import re
import tempfile
import time
import uuid
import zipfile
from contextlib import ExitStack
from typing import Any, Dict, Iterable, List
from xml.etree import ElementTree

import httpx
import yaml
from pymongo import UpdateOne

from backend.app.database.connection import get_db
from backend.app.intelligence.urls import safe_source_url
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
    NVD_INITIAL_MAX_RECORDS,
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


def _safe_error_message(error: Exception) -> str:
    """Avoid returning URL query parameters that may contain caller credentials."""
    message = str(error)
    return re.sub(r"https?://[^\s\"'<>]+", lambda match: match.group(0).split("?", 1)[0] + ("?[redacted]" if "?" in match.group(0) else ""), message)[:1000]


def _upsert_bulk_counts(collection_name: str, operations: List[UpdateOne]) -> tuple[int, int]:
    if not operations:
        return 0, 0
    db = get_db()
    result = db[collection_name].bulk_write(operations, ordered=False)
    return result.upserted_count, result.modified_count


def _record_dataset_source(source_id: str, name: str, url: str, org_id: str, tenant_id: str,
                           metadata: Dict[str, Any] | None = None) -> None:
    db = get_db()
    db[INTEL_DATASET_SOURCES].update_one(
        {"source_id": source_id, "org_id": org_id, "tenant_id": tenant_id},
        {"$set": {"name": name, "url": safe_source_url(url), "org_id": org_id, "tenant_id": tenant_id,
                   "last_imported_at": _now(), "metadata": metadata or {}}},
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

        incoming_source = incoming.get("source_id")
        if incoming_source == "nvd" and key in {
            "description", "severity", "published_date", "last_modified_date",
            "cvss_score", "cvss_version", "affected_products", "cpe",
        }:
            if value is not None and value != "":
                merged[key] = value
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

    if incoming.get("source_id") == "cisa_kev":
        # CISA's Unknown value must clear legacy bool("Unknown") data on re-import.
        merged["known_ransomware_campaign_use"] = incoming.get("known_ransomware_campaign_use")
        merged["ransomware_campaign_use_source_value"] = incoming.get("ransomware_campaign_use_source_value")
        if incoming.get("cisa_date_added") is not None:
            merged["cisa_date_added"] = incoming["cisa_date_added"]

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
            "revoked": bool(obj.get("revoked", False)),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
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
        "org_id": org_id,
        "tenant_id": tenant_id,
        "status": "running",
        "started_at": _now(),
        "record_count": 0,
        "error_message": None,
    }
    db[INTEL_INGESTION_JOBS].insert_one(job_doc)

    total = inserted_count = updated_count = skipped_count = 0
    try:
        with httpx.Client(timeout=INGESTION_TIMEOUT_SECONDS) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
        objects = data.get("objects", [])
        techniques = _process_mitre_objects(objects)
        unique_techniques = {}
        for technique in techniques:
            if technique["technique_id"] in unique_techniques:
                continue
            unique_techniques[technique["technique_id"]] = technique
        techniques = list(unique_techniques.values())
        total = len(techniques)
        skipped_count = sum(1 for obj in objects if isinstance(obj, dict) and obj.get("type") == "attack-pattern") - len(techniques)
        inserted_count = 0
        updated_count = 0
        ops = []
        for tech in techniques:
            filter_ = {"org_id": org_id, "tenant_id": tenant_id, "technique_id": tech["technique_id"]}
            record = dict(tech)
            created_at = record.pop("created_at", _now())
            update = {"$set": record, "$setOnInsert": {"org_id": org_id, "tenant_id": tenant_id, "created_at": created_at}}
            ops.append(UpdateOne(filter_, update, upsert=True))
            if len(ops) >= INGESTION_BATCH_SIZE:
                inserted, updated = _upsert_bulk_counts(INTEL_ATTACK_TECHNIQUES, ops)
                inserted_count += inserted
                updated_count += updated
                ops.clear()
        if ops:
            inserted, updated = _upsert_bulk_counts(INTEL_ATTACK_TECHNIQUES, ops)
            inserted_count += inserted
            updated_count += updated
        source_filter = {"source_id": "mitre_attack", "org_id": org_id, "tenant_id": tenant_id}
        db[INTEL_DATASET_SOURCES].update_one(
            source_filter,
            {"$set": {"name": "MITRE ATT&CK", "url": safe_source_url(url), "last_imported_at": _now(),
                       "org_id": org_id, "tenant_id": tenant_id,
                       "metadata": {"processed_count": total, "inserted_count": inserted_count,
                                    "updated_count": updated_count, "skipped_count": skipped_count}}},
            upsert=True,
        )
        db[INTEL_INGESTION_JOBS].update_one(
            {"job_id": job_id},
            {"$set": {"status": "completed", "completed_at": _now(), "record_count": total,
                       "inserted_count": inserted_count, "updated_count": updated_count,
                       "skipped_count": skipped_count}},
        )
        return {"job_id": job_id, "status": "completed", "record_count": total,
                "inserted": inserted_count, "updated": updated_count, "skipped": skipped_count}
    except Exception as exc:
        logger.error("MITRE ATT&CK ingestion failed: %s", _safe_error_message(exc))
        db[INTEL_INGESTION_JOBS].update_one(
            {"job_id": job_id},
            {"$set": {"status": "failed", "completed_at": _now(), "error_message": _safe_error_message(exc),
                       "record_count": total, "inserted_count": inserted_count,
                       "updated_count": updated_count, "skipped_count": skipped_count}},
        )
        return {"job_id": job_id, "status": "failed", "error": _safe_error_message(exc),
                "record_count": total, "inserted": inserted_count, "updated": updated_count,
                "skipped": skipped_count}

# ---------------------------------------------------------------------------
# CAPEC ingestion
# ---------------------------------------------------------------------------

def _process_capec_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    records = []
    for item in items:
        capec_id = item.get("capec-id")
        if not capec_id:
            continue
        # Keep technique links only when the imported CAPEC item explicitly
        # supplies them. CAPEC datasets vary in their field naming.
        raw_techniques = next((item.get(key) for key in (
            "technique_ids", "technique-ids", "attack_technique_ids", "related_techniques",
        ) if item.get(key) is not None), [])
        if isinstance(raw_techniques, dict):
            raw_techniques = raw_techniques.get("technique", raw_techniques.get("items", []))
        if not isinstance(raw_techniques, list):
            raw_techniques = [raw_techniques]
        technique_ids = []
        for value in raw_techniques:
            candidate = value.get("technique_id") or value.get("external_id") or value.get("id") if isinstance(value, dict) else value
            if isinstance(candidate, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", candidate, re.IGNORECASE):
                technique_ids.append(candidate.upper())
        raw_references = item.get("references") or item.get("external_references") or []
        references = []
        if isinstance(raw_references, list):
            for reference in raw_references:
                url_value = reference.get("url") if isinstance(reference, dict) else reference
                if isinstance(url_value, str) and url_value.startswith(("https://", "http://")):
                    references.append(url_value)
        record = {
            "pattern_id": f"CAPEC-{capec_id}",
            "name": item.get("name", ""),
            "description": item.get("summary", ""),
            "technique_ids": list(dict.fromkeys(technique_ids)),
            "references": list(dict.fromkeys(references)),
            "created_at": _now(),
            "updated_at": _now(),
        }
        records.append(record)
    return records


def _capec_xml_items(payload: bytes) -> list[dict[str, Any]]:
    """Extract attack patterns and explicit ATT&CK mappings from CAPEC's official XML archive."""
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            xml_name = next((name for name in archive.namelist() if name.lower().endswith(".xml")), None)
            if not xml_name:
                raise ValueError("CAPEC archive contains no XML catalog")
            root = ElementTree.fromstring(archive.read(xml_name))
    except (zipfile.BadZipFile, ElementTree.ParseError, StopIteration) as exc:
        raise ValueError("CAPEC returned an invalid XML archive") from exc
    if not root.tag.endswith("Attack_Pattern_Catalog"):
        raise ValueError("CAPEC XML has an unexpected catalog root")

    items: list[dict[str, Any]] = []
    for pattern in root.findall(".//{*}Attack_Pattern"):
        if (pattern.get("Status") or "").casefold() == "deprecated":
            continue
        capec_id = pattern.get("ID")
        if not capec_id:
            continue
        technique_ids = []
        for mapping in pattern.findall(".//{*}Taxonomy_Mapping"):
            taxonomy = (mapping.get("Taxonomy_Name") or "").casefold()
            if "attack" not in taxonomy:
                continue
            entry_id = mapping.findtext("{*}Entry_ID") or ""
            normalized_id = entry_id.strip().upper()
            if re.fullmatch(r"T?\d{4}(?:\.\d{3})?", normalized_id):
                technique_ids.append(normalized_id if normalized_id.startswith("T") else f"T{normalized_id}")
        items.append({
            "capec-id": capec_id,
            "name": pattern.get("Name", ""),
            "summary": pattern.findtext("{*}Description") or "",
            "technique_ids": list(dict.fromkeys(technique_ids)),
            "references": [f"https://capec.mitre.org/data/definitions/{capec_id}.html"],
        })
    return items


def ingest_capec(org_id: str, tenant_id: str, url: str) -> Dict[str, Any]:
    db = get_db()
    job_id = str(uuid.uuid4())
    job_doc = {
        "job_id": job_id,
        "source_id": "capec",
        "org_id": org_id,
        "tenant_id": tenant_id,
        "status": "running",
        "started_at": _now(),
        "record_count": 0,
        "error_message": None,
    }
    db[INTEL_INGESTION_JOBS].insert_one(job_doc)
    total = inserted_count = updated_count = skipped_count = 0
    try:
        with httpx.Client(timeout=INGESTION_TIMEOUT_SECONDS) as client:
            resp = client.get(url)
            resp.raise_for_status()
            content = getattr(resp, "content", None)
            response_json = None if content is not None else resp.json()
        if content is not None and content.startswith(b"PK"):
            items = _capec_xml_items(content)
        else:
            try:
                data = response_json if response_json is not None else __import__("json").loads(content)
            except (ValueError, TypeError) as exc:
                raise ValueError("CAPEC returned an unsupported catalog format") from exc
            items = data.get("attack-patterns", []) if isinstance(data, dict) else []
            if not isinstance(items, list):
                raise ValueError("CAPEC returned an invalid attack-pattern list")
        patterns = _process_capec_items(items)
        unique_patterns = {}
        for pattern in patterns:
            if pattern["pattern_id"] in unique_patterns:
                continue
            unique_patterns[pattern["pattern_id"]] = pattern
        patterns = list(unique_patterns.values())
        total = len(patterns)
        skipped_count = len(items) - total
        inserted_count = 0
        updated_count = 0
        ops = []
        for pat in patterns:
            filter_ = {"org_id": org_id, "tenant_id": tenant_id, "pattern_id": pat["pattern_id"]}
            record = dict(pat)
            created_at = record.pop("created_at", _now())
            update = {"$set": record, "$setOnInsert": {"org_id": org_id, "tenant_id": tenant_id, "created_at": created_at}}
            ops.append(UpdateOne(filter_, update, upsert=True))
            if len(ops) >= INGESTION_BATCH_SIZE:
                inserted, updated = _upsert_bulk_counts(INTEL_ATTACK_PATTERNS, ops)
                inserted_count += inserted
                updated_count += updated
                ops.clear()
        if ops:
            inserted, updated = _upsert_bulk_counts(INTEL_ATTACK_PATTERNS, ops)
            inserted_count += inserted
            updated_count += updated
        db[INTEL_DATASET_SOURCES].update_one(
            {"source_id": "capec", "org_id": org_id, "tenant_id": tenant_id},
            {"$set": {"name": "CAPEC", "url": safe_source_url(url), "org_id": org_id, "tenant_id": tenant_id,
                       "last_imported_at": _now(),
                       "metadata": {"processed_count": total, "inserted_count": inserted_count,
                                    "updated_count": updated_count, "skipped_count": skipped_count}}},
            upsert=True,
        )
        db[INTEL_INGESTION_JOBS].update_one(
            {"job_id": job_id},
            {"$set": {"status": "completed", "completed_at": _now(), "record_count": total,
                       "inserted_count": inserted_count, "updated_count": updated_count,
                       "skipped_count": skipped_count}},
        )
        return {"job_id": job_id, "status": "completed", "record_count": total,
                "inserted": inserted_count, "updated": updated_count, "skipped": skipped_count}
    except Exception as exc:
        logger.error("CAPEC ingestion failed: %s", _safe_error_message(exc))
        db[INTEL_INGESTION_JOBS].update_one(
            {"job_id": job_id},
            {"$set": {"status": "failed", "completed_at": _now(), "error_message": _safe_error_message(exc),
                       "record_count": total, "inserted_count": inserted_count,
                       "updated_count": updated_count, "skipped_count": skipped_count}},
        )
        return {"job_id": job_id, "status": "failed", "error": _safe_error_message(exc),
                "record_count": total, "inserted": inserted_count, "updated": updated_count,
                "skipped": skipped_count}

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
    public_source_url = safe_source_url(source_url)
    source_provenance = [{"source_id": "nvd", "name": "NVD", "url": public_source_url}]
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
        "source_url": public_source_url,
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
    last_modified_before: str | None = None,
    max_records: int | None = None,
) -> Dict[str, Any]:
    db = get_db()
    job_id = str(uuid.uuid4())
    db[INTEL_INGESTION_JOBS].insert_one({
        "job_id": job_id,
        "source_id": "nvd",
        "org_id": org_id,
        "tenant_id": tenant_id,
        "status": "running",
        "started_at": _now(),
        "record_count": 0,
        "error_message": None,
    })
    source_url = url or NVD_API_URL
    api_key_value = api_key if api_key is not None else NVD_API_KEY
    page_size_value = min(int(page_size or NVD_PAGE_SIZE), 2000)
    request_delay_value = float(request_delay if request_delay is not None else NVD_REQUEST_DELAY)
    max_records_value = int(max_records if max_records is not None else NVD_INITIAL_MAX_RECORDS)
    if (page_size_value < 1 or max_records_value < 1 or request_delay_value < 0
            or bool(last_modified_after) != bool(last_modified_before)):
        _finalize_job(job_id, "failed", error_message="Invalid NVD ingestion bounds.")
        return {"job_id": job_id, "status": "failed", "error": "Invalid NVD ingestion bounds.",
                "record_count": 0, "inserted": 0, "updated": 0, "skipped": 0}
    params: Dict[str, Any] = {"resultsPerPage": page_size_value, "startIndex": 0}
    if last_modified_after:
        params["lastModStartDate"] = last_modified_after
        params["lastModEndDate"] = last_modified_before
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
                if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities", []), list):
                    raise ValueError("NVD returned an invalid response payload")
                items = payload.get("vulnerabilities", [])
                if not items:
                    break
                total_results = int(payload.get("totalResults", start_index + len(items)))
                for page_offset, item in enumerate(items):
                    cve = item.get("cve", {}) if isinstance(item, dict) else {}
                    cve_id = cve.get("id")
                    if not cve_id:
                        skipped_count += 1
                        continue
                    try:
                        record = _build_nvd_record(org_id, tenant_id, cve, source_url)
                    except (TypeError, ValueError, AttributeError):
                        skipped_count += 1
                        continue
                    filter_ = {"org_id": org_id, "tenant_id": tenant_id, "cve_id": cve_id}
                    existing = db[INTEL_VULNERABILITIES].find_one(filter_)
                    merged = _merge_vulnerability_document(existing, record)
                    operations.append(UpdateOne(filter_, {"$set": merged}, upsert=True))
                    processed_count += 1
                    if len(operations) >= INGESTION_BATCH_SIZE:
                        inserted, updated = _upsert_bulk_counts(INTEL_VULNERABILITIES, operations)
                        inserted_count += inserted
                        updated_count += updated
                        operations.clear()
                    if processed_count >= max_records_value:
                        limited = start_index + page_offset + 1 < total_results
                        break
                if limited:
                    break
                if len(items) < page_size_value:
                    break
                start_index += len(items)
                if request_delay_value > 0:
                    time.sleep(request_delay_value)
            if operations:
                inserted, updated = _upsert_bulk_counts(INTEL_VULNERABILITIES, operations)
                inserted_count += inserted
                updated_count += updated
        _record_dataset_source("nvd", "NVD", source_url, org_id, tenant_id,
                               {"page_size": page_size_value, "max_records": max_records_value,
                                "last_modified_after": last_modified_after,
                                "last_modified_before": last_modified_before,
                                "limited": limited, "processed_count": processed_count,
                                "inserted_count": inserted_count, "updated_count": updated_count,
                                "skipped_count": skipped_count})
        _finalize_job(job_id, "completed", record_count=processed_count, inserted_count=inserted_count, updated_count=updated_count, skipped_count=skipped_count, limited=limited)
        return {"job_id": job_id, "status": "completed", "record_count": processed_count, "inserted": inserted_count, "updated": updated_count, "skipped": skipped_count, "limited": limited}
    except Exception as exc:
        logger.error("NVD ingestion failed: %s", _safe_error_message(exc))
        _finalize_job(job_id, "failed", record_count=processed_count, error_message=_safe_error_message(exc),
                      inserted_count=inserted_count, updated_count=updated_count,
                      skipped_count=skipped_count, limited=limited)
        return {"job_id": job_id, "status": "failed", "error": _safe_error_message(exc), "record_count": processed_count, "skipped": skipped_count, "limited": limited}

# ---------------------------------------------------------------------------
# CISA KEV ingestion
# ---------------------------------------------------------------------------

def _build_cisa_record(org_id: str, tenant_id: str, item: Dict[str, Any], source_url: str) -> Dict[str, Any]:
    public_source_url = safe_source_url(source_url)
    cve_id = item.get("cveID") or item.get("cve_id")
    if not cve_id:
        raise ValueError("CISA KEV record missing CVE identifier")
    doc = {
        "org_id": org_id,
        "tenant_id": tenant_id,
        "cve_id": cve_id,
        "description": item.get("shortDescription") or item.get("vulnerabilityName") or "",
        "severity": item.get("severity") or "unknown",
        "cisa_date_added": _parse_iso_datetime(item.get("dateAdded")),
        "affected_products": [f"{item.get('vendorProject')}:{item.get('product')}" ] if item.get("vendorProject") and item.get("product") else [],
        "references": [item.get("url")] if item.get("url") else [],
        "source_id": "cisa_kev",
        "source_url": public_source_url,
        "required_action": item.get("requiredAction"),
        "due_date": _parse_iso_datetime(item.get("dueDate")),
        "known_ransomware_campaign_use": _parse_ransomware_campaign_use(item.get("knownRansomwareCampaignUse")),
        "ransomware_campaign_use_source_value": item.get("knownRansomwareCampaignUse"),
        "vendor": item.get("vendorProject"),
        "product": item.get("product"),
        "source_provenance": [{"source_id": "cisa_kev", "name": "CISA KEV", "url": public_source_url}],
        "created_at": _now(),
        "updated_at": _now(),
    }
    return doc


def _parse_ransomware_campaign_use(value: Any) -> bool | None:
    """Normalize the CISA boolean/enumerated field without treating Unknown as true."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"known", "yes", "true", "1"}:
            return True
        if normalized in {"no", "false", "0"}:
            return False
    return None


def ingest_cisa_kev(org_id: str, tenant_id: str, url: str | None = None) -> Dict[str, Any]:
    db = get_db()
    job_id = str(uuid.uuid4())
    db[INTEL_INGESTION_JOBS].insert_one({
        "job_id": job_id,
        "source_id": "cisa_kev",
        "org_id": org_id,
        "tenant_id": tenant_id,
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
            try:
                record = _build_cisa_record(org_id, tenant_id, item, source_url)
            except (TypeError, ValueError, AttributeError):
                skipped_count += 1
                continue
            filter_ = {"org_id": org_id, "tenant_id": tenant_id, "cve_id": cve_id}
            existing = db[INTEL_VULNERABILITIES].find_one(filter_)
            merged = _merge_vulnerability_document(existing, record)
            operations.append(UpdateOne(filter_, {"$set": merged}, upsert=True))
            processed_count += 1
            if len(operations) >= INGESTION_BATCH_SIZE:
                inserted, updated = _upsert_bulk_counts(INTEL_VULNERABILITIES, operations)
                inserted_count += inserted
                updated_count += updated
                operations.clear()
        if operations:
            inserted, updated = _upsert_bulk_counts(INTEL_VULNERABILITIES, operations)
            inserted_count += inserted
            updated_count += updated
        _record_dataset_source("cisa_kev", "CISA KEV", source_url, org_id, tenant_id,
                               {"total_records": processed_count, "inserted_count": inserted_count,
                                "updated_count": updated_count, "skipped_count": skipped_count})
        _finalize_job(job_id, "completed", record_count=processed_count, inserted_count=inserted_count, updated_count=updated_count, skipped_count=skipped_count)
        return {"job_id": job_id, "status": "completed", "record_count": processed_count, "inserted": inserted_count, "updated": updated_count, "skipped": skipped_count}
    except Exception as exc:
        logger.error("CISA KEV ingestion failed: %s", _safe_error_message(exc))
        _finalize_job(job_id, "failed", record_count=processed_count, error_message=_safe_error_message(exc),
                      inserted_count=inserted_count, updated_count=updated_count, skipped_count=skipped_count)
        return {"job_id": job_id, "status": "failed", "error": _safe_error_message(exc),
                "record_count": processed_count, "inserted": inserted_count, "updated": updated_count,
                "skipped": skipped_count}

# ---------------------------------------------------------------------------
# Sigma ingestion
# ---------------------------------------------------------------------------

def _discover_sigma_files(repo: str, branch: str, max_rules: int | None = None) -> List[str]:
    url = f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
    with httpx.Client(timeout=INGESTION_TIMEOUT_SECONDS) as client:
        response = client.get(url, headers={"Accept": "application/vnd.github+json"})
        response.raise_for_status()
        payload = response.json()
    if payload.get("truncated"):
        raise RuntimeError("GitHub returned a truncated Sigma rules tree; import was stopped to avoid an incomplete catalog")
    tree = payload.get("tree", [])
    files = []
    for item in tree:
        path = item.get("path")
        if not path or item.get("type") != "blob":
            continue
        lower = path.lower()
        if lower.endswith((".yml", ".yaml")) and lower.startswith("rules/"):
            files.append(path)
    if max_rules is not None:
        return files[:max_rules]
    return files


def _download_sigma_archive(repo: str, branch: str, max_rules: int | None) -> tuple[str, str, List[str]]:
    """Use GitHub's official codeload archive when its unauthenticated tree API is rate-limited."""
    url = f"https://codeload.github.com/{repo}/zip/refs/heads/{branch}"
    path = ""
    try:
        with tempfile.NamedTemporaryFile(prefix="threatguard-sigma-", suffix=".zip", delete=False) as file:
            path = file.name
            total_bytes = 0
            with httpx.stream("GET", url, timeout=INGESTION_TIMEOUT_SECONDS, follow_redirects=True) as response:
                response.raise_for_status()
                for chunk in response.iter_bytes(256 * 1024):
                    total_bytes += len(chunk)
                    if total_bytes > 50 * 1024 * 1024:
                        raise ValueError("Sigma source archive exceeded the 50 MiB safety limit")
                    file.write(chunk)
        with zipfile.ZipFile(path) as archive:
            archive_names = archive.namelist()
            root = archive_names[0].split("/", 1)[0] if archive_names else ""
            yaml_entries = sorted(
                name for name in archive_names
                if name.lower().endswith((".yml", ".yaml"))
                and name[len(root) + 1:].lower().startswith("rules/")
            )
            if not yaml_entries:
                raise ValueError("Sigma source archive contained no rule files")
            relative_paths = [name[len(root) + 1:] for name in yaml_entries]
            if max_rules is not None:
                relative_paths = relative_paths[:max_rules]
        return path, root, relative_paths
    except Exception:
        if path and os.path.exists(path):
            os.unlink(path)
        raise

import textwrap
def _parse_sigma_rule(raw_text: str, source_path: str, source_url: str, org_id: str, tenant_id: str) -> Dict[str, Any] | None:
    raw_text = textwrap.dedent(raw_text).strip()
    try:
        data = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    rule_id = data.get("id")
    title = data.get("title")
    description = data.get("description") or ""
    if not isinstance(rule_id, str) or not rule_id.strip() or not isinstance(title, str) or not title.strip() or not description:
        return None
    tags = data.get("tags") or []
    if not isinstance(tags, list):
        return None
    technique_refs = []
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("attack.t"):
            technique_refs.append(tag)
    detection = data.get("detection")
    log_source = data.get("logsource") or {}
    if (not isinstance(detection, dict) or not detection
            or "condition" not in detection
            or not any(key != "condition" for key in detection)
            or not isinstance(log_source, dict) or not log_source):
        return None
    references = data.get("references") or []
    if not isinstance(references, list):
        return None
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
        "references": references,
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
        "org_id": org_id,
        "tenant_id": tenant_id,
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
    archive_path = None
    archive_root = None
    try:
        try:
            files = _discover_sigma_files(repo_name, branch_name, max_rule_cap)
        except (httpx.HTTPStatusError, RuntimeError) as discovery_error:
            status_code = getattr(getattr(discovery_error, "response", None), "status_code", None)
            if status_code not in {403, 429} and "truncated Sigma rules tree" not in str(discovery_error):
                raise
            archive_path, archive_root, files = _download_sigma_archive(repo_name, branch_name, max_rule_cap)
        limit_hit = bool(max_rule_cap is not None and max_rule_cap > 0 and len(files) >= max_rule_cap)
        with ExitStack() as stack:
            archive = stack.enter_context(zipfile.ZipFile(archive_path)) if archive_path else None
            client = None if archive_path else stack.enter_context(httpx.Client(timeout=INGESTION_TIMEOUT_SECONDS))
            for source_path in files:
                if max_rule_cap is not None and processed_count >= max_rule_cap:
                    limit_hit = True
                    break
                raw_url = f"https://raw.githubusercontent.com/{repo_name}/{branch_name}/{source_path}"
                if archive is not None:
                    payload = archive.read(f"{archive_root}/{source_path}").decode("utf-8")
                else:
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
                record = dict(rule)
                created_at = record.pop("created_at", _now())
                record.pop("org_id", None)
                record.pop("tenant_id", None)
                operations.append(UpdateOne(filter_, {
                    "$set": record,
                    "$setOnInsert": {"org_id": org_id, "tenant_id": tenant_id, "created_at": created_at},
                }, upsert=True))
                processed_count += 1
                if len(operations) >= INGESTION_BATCH_SIZE:
                    inserted, updated = _upsert_bulk_counts(INTEL_DETECTION_RULES, operations)
                    inserted_count += inserted
                    updated_count += updated
                    operations.clear()
        if operations:
            inserted, updated = _upsert_bulk_counts(INTEL_DETECTION_RULES, operations)
            inserted_count += inserted
            updated_count += updated
        _record_dataset_source("sigma", "Sigma", f"https://github.com/{repo_name}", org_id, tenant_id, {"branch": branch_name, "cap": max_rule_cap, "files_seen": len(files), "limit_hit": limit_hit})
        _finalize_job(job_id, "completed", record_count=processed_count, inserted_count=inserted_count, updated_count=updated_count, skipped_count=skipped_count, limited=limit_hit)
        return {"job_id": job_id, "status": "completed", "record_count": processed_count, "inserted": inserted_count, "updated": updated_count, "skipped": skipped_count, "limited": limit_hit, "complete": not limit_hit}
    except Exception as exc:
        logger.error("Sigma ingestion failed: %s", _safe_error_message(exc))
        _finalize_job(job_id, "failed", record_count=processed_count, error_message=_safe_error_message(exc),
                      inserted_count=inserted_count, updated_count=updated_count,
                      skipped_count=skipped_count, limited=limit_hit)
        return {"job_id": job_id, "status": "failed", "error": _safe_error_message(exc),
                "record_count": processed_count, "inserted": inserted_count, "updated": updated_count,
                "skipped": skipped_count, "limited": limit_hit}
    finally:
        if archive_path and os.path.exists(archive_path):
            os.unlink(archive_path)
