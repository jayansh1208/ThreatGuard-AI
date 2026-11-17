"""Tenant-scoped hybrid search and evidence-backed intelligence relationships."""
from __future__ import annotations

import re
import logging
from typing import Any, Iterable

import numpy as np
from pymongo import UpdateOne

from backend.app.intelligence.config import (
    INTEL_ATTACK_PATTERNS, INTEL_ATTACK_TECHNIQUES, INTEL_DETECTION_RULES,
    INTEL_THREAT_RELATIONS, INTEL_VULNERABILITIES,
)
from backend.app.config import CHAT_RAG_MIN_SIMILARITY

logger = logging.getLogger(__name__)

COLLECTIONS = {
    "cve": (INTEL_VULNERABILITIES, "cve_id", "vulnerability"),
    "technique": (INTEL_ATTACK_TECHNIQUES, "technique_id", "technique"),
    "capec": (INTEL_ATTACK_PATTERNS, "pattern_id", "attack_pattern"),
    "sigma": (INTEL_DETECTION_RULES, "rule_id", "detection_rule"),
}
SEARCH_FIELDS = {
    "cve": ("cve_id", "description", "severity", "affected_products"),
    "technique": ("technique_id", "name", "description", "tactics", "platforms"),
    "capec": ("pattern_id", "name", "description", "technique_ids"),
    "sigma": ("rule_id", "title", "description", "tags", "technique_refs"),
}


def _plain(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return " ".join(_plain(item) for item in value)
    if isinstance(value, dict):
        return " ".join(_plain(item) for item in value.values())
    return str(value or "")


def _record_text(record: dict[str, Any], kind: str) -> str:
    return " ".join(_plain(record.get(field)) for field in SEARCH_FIELDS[kind])


def _record_id(record: dict[str, Any], kind: str) -> str:
    return str(record.get(COLLECTIONS[kind][1], ""))


def _format_record(record: dict[str, Any], kind: str, score: float, keyword_score: float,
                   semantic_score: float | None) -> dict[str, Any]:
    _, _, record_type = COLLECTIONS[kind]
    result = {key: value for key, value in record.items() if key != "_id" and key not in {"embedding"}}
    result.update({"record_type": kind, "record_id": _record_id(record, kind),
                   "record_kind": record_type, "score": round(float(score), 6),
                   "keyword_score": round(float(keyword_score), 6),
                   "semantic_score": round(float(semantic_score), 6) if semantic_score is not None else None})
    return result


def _cosine(a: Iterable[float], b: Iterable[float]) -> float | None:
    left = np.asarray(list(a), dtype=np.float32)
    right = np.asarray(list(b), dtype=np.float32)
    if left.ndim != 1 or right.shape != left.shape or left.size == 0:
        return None
    denom = float(np.linalg.norm(left) * np.linalg.norm(right))
    return float(np.clip(np.dot(left, right) / denom, -1.0, 1.0)) if denom else None


def search_intelligence(db: Any, *, org_id: str, tenant_id: str, query: str,
                        record_types: list[str] | None = None, page: int = 1,
                        page_size: int = 20, provider: Any = None) -> dict[str, Any]:
    if not org_id or not tenant_id:
        raise ValueError("Authenticated organization and tenant context are required.")
    query = query.strip()
    if not query:
        raise ValueError("Search query cannot be empty.")
    if page < 1 or page > 100 or page_size < 1 or page_size > 100:
        raise ValueError("page must be between 1 and 100 and page_size between 1 and 100.")
    kinds = record_types or list(COLLECTIONS)
    if any(kind not in COLLECTIONS for kind in kinds):
        raise ValueError("Unsupported intelligence record type.")
    try:
        if provider is None:
            from backend.app.knowledge.embeddings import get_embedding_provider
            provider = get_embedding_provider()
        query_vector = provider.embed([query])[0]
    except Exception:
        # Keyword search remains available in offline installations without a local model.
        provider = None
        query_vector = None

    terms = [term for term in re.findall(r"[\w.-]+", query.casefold()) if term]
    candidates: list[dict[str, Any]] = []
    total = 0
    keep = min((page - 1) * page_size + page_size, 10000)
    tenant_filter = {"org_id": org_id, "tenant_id": tenant_id}
    for kind in kinds:
        collection_name = COLLECTIONS[kind][0]
        cursor = db[collection_name].find(tenant_filter, {"embedding": 1, "embedding_model": 1,
            **{field: 1 for field in SEARCH_FIELDS[kind]}, "_id": 0}).batch_size(128)
        batch: list[dict[str, Any]] = []

        def consume(rows: list[dict[str, Any]]) -> None:
            if not rows:
                return
            vectors: list[list[float] | None] = [row.get("embedding") for row in rows]
            if provider is not None and query_vector is not None:
                for index, row in enumerate(rows):
                    if row.get("embedding_model") not in (None, provider.model_name):
                        vectors[index] = None
                missing = [i for i, vector in enumerate(vectors) if not vector]
                # Embed only the current bounded cursor batch; documents are not cached in RAM.
                cache_ops = []
                for start in range(0, len(missing), 32):
                    positions = missing[start:start + 32]
                    try:
                        embedded = provider.embed([_record_text(rows[i], kind) for i in positions])
                    except Exception:
                        logger.exception("Intelligence record embedding failed for %s batch", kind)
                        continue
                    for position, vector in zip(positions, embedded):
                        normalized = [float(value) for value in vector]
                        vectors[position] = normalized
                        identity_field = COLLECTIONS[kind][1]
                        identity = rows[position].get(identity_field)
                        if identity:
                            cache_ops.append(UpdateOne(
                                {"org_id": org_id, "tenant_id": tenant_id, identity_field: identity},
                                {"$set": {"embedding": normalized,
                                           "embedding_model": provider.model_name,
                                           "embedding_dimension": provider.dimension}},
                            ))
                if cache_ops:
                    collection = db[collection_name]
                    # Lightweight fakes and read-only adapters can still serve search.
                    bulk_write = getattr(collection, "bulk_write", None)
                    if callable(bulk_write):
                        try:
                            bulk_write(cache_ops, ordered=False)
                        except Exception:
                            # The current request can still use its batch vectors.
                            logger.exception("Unable to cache %s intelligence embeddings", kind)
            for row, vector in zip(rows, vectors):
                corpus_text = _record_text(row, kind).casefold()
                matches = sum(1 for term in terms if term in corpus_text)
                keyword_score = matches / max(1, len(terms))
                semantic_score = _cosine(query_vector, vector) if query_vector is not None and vector else None
                # Reciprocal rank style blend keeps lexical exact IDs competitive with semantic similarity.
                normalized_semantic = max(0.0, semantic_score or 0.0)
                score = 0.55 * keyword_score + 0.45 * normalized_semantic
                if keyword_score or (semantic_score is not None and semantic_score >= CHAT_RAG_MIN_SIMILARITY):
                    nonlocal total
                    total += 1
                    candidates.append(_format_record(row, kind, score, keyword_score, semantic_score))
                    candidates.sort(key=lambda item: (-item["score"], item["record_type"], item["record_id"]))
                    del candidates[keep:]

        for record in cursor:
            batch.append(record)
            if len(batch) >= 128:
                consume(batch)
                batch = []
        consume(batch)

    offset = (page - 1) * page_size
    return {"items": candidates[offset:offset + page_size], "page": page,
            "page_size": page_size, "total": total, "query": query,
            "search_mode": "hybrid" if provider is not None else "keyword"}


def get_intelligence_record(db: Any, *, org_id: str, tenant_id: str,
                            record_type: str, record_id: str) -> dict[str, Any] | None:
    if record_type not in COLLECTIONS:
        raise ValueError("Unsupported intelligence record type.")
    collection, id_field, _ = COLLECTIONS[record_type]
    record = db[collection].find_one({"org_id": org_id, "tenant_id": tenant_id, id_field: record_id})
    if record is None:
        return None
    record.pop("embedding", None)
    record.pop("_id", None)
    record.update({"record_type": record_type, "record_id": record_id})
    return record


def _derived_relationships(db: Any, org_id: str, tenant_id: str,
                           record_type: str, record_id: str) -> list[dict[str, Any]]:
    """Return only direct identifier references present in source records."""
    relations: list[dict[str, Any]] = []
    if record_type == "sigma":
        source = db[COLLECTIONS["sigma"][0]].find_one({"org_id": org_id, "tenant_id": tenant_id, "rule_id": record_id}) or {}
        for raw_ref in source.get("technique_refs", []):
            match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(raw_ref), re.IGNORECASE)
            if not match:
                continue
            target_id = match.group(1).upper()
            target = db[COLLECTIONS["technique"][0]].find_one({"org_id": org_id, "tenant_id": tenant_id, "technique_id": target_id})
            if target:
                source_references = [source.get("source_url")] if source.get("source_url") else []
                relations.append({"source": {"type": "sigma", "id": record_id},
                    "target": {"type": "technique", "id": target_id, "name": target.get("name")},
                    "relationship_type": "detects", "origin": "official_source",
                    "inferred": False, "source_references": source_references,
                    "evidence": {"field": "technique_refs", "value": raw_ref,
                                 "source_references": source_references}})
    elif record_type == "capec":
        source = db[COLLECTIONS["capec"][0]].find_one({"org_id": org_id, "tenant_id": tenant_id, "pattern_id": record_id}) or {}
        for target_id in source.get("technique_ids", []):
            target_id = str(target_id).upper()
            target = db[COLLECTIONS["technique"][0]].find_one({"org_id": org_id, "tenant_id": tenant_id, "technique_id": target_id})
            if target:
                source_references = source.get("references", [])
                relations.append({"source": {"type": "capec", "id": record_id},
                    "target": {"type": "technique", "id": target_id, "name": target.get("name")},
                    "relationship_type": "maps_to", "origin": "official_source",
                    "inferred": False, "source_references": source_references,
                    "evidence": {"field": "technique_ids", "value": target_id,
                                 "source_references": source_references}})
    elif record_type == "technique":
        scope = {"org_id": org_id, "tenant_id": tenant_id}
        technique_tag = f"attack.{record_id.lower()}"
        for rule in db[COLLECTIONS["sigma"][0]].find(
                {**scope, "technique_refs": technique_tag},
                {"rule_id": 1, "source_url": 1, "technique_refs": 1, "_id": 0}).limit(500):
            source_references = [rule.get("source_url")] if rule.get("source_url") else []
            relations.append({"source": {"type": "sigma", "id": rule["rule_id"]},
                "target": {"type": "technique", "id": record_id},
                "relationship_type": "detects", "origin": "official_source", "inferred": False,
                "source_references": source_references,
                "evidence": {"field": "technique_refs", "value": technique_tag,
                             "source_references": source_references}})
        for pattern in db[COLLECTIONS["capec"][0]].find(
                {**scope, "technique_ids": record_id},
                {"pattern_id": 1, "references": 1, "_id": 0}).limit(500):
            source_references = pattern.get("references", [])
            relations.append({"source": {"type": "capec", "id": pattern["pattern_id"]},
                "target": {"type": "technique", "id": record_id},
                "relationship_type": "maps_to", "origin": "official_source", "inferred": False,
                "source_references": source_references,
                "evidence": {"field": "technique_ids", "value": record_id,
                             "source_references": source_references}})
    return relations


def list_relationships(db: Any, *, org_id: str, tenant_id: str, record_type: str,
                       record_id: str, page: int = 1, page_size: int = 20,
                       inferred: bool | None = None) -> dict[str, Any]:
    if record_type not in COLLECTIONS:
        raise ValueError("Unsupported intelligence record type.")
    if page < 1 or page > 100 or page_size < 1 or page_size > 100:
        raise ValueError("page must be between 1 and 100 and page_size between 1 and 100.")
    query = {"org_id": org_id, "tenant_id": tenant_id,
             "$or": [{"source_record_id": record_id}, {"target_record_id": record_id}]}
    if inferred is not None:
        query["inferred"] = inferred
    relation_collection = db[INTEL_THREAT_RELATIONS]
    persisted_total = int(relation_collection.count_documents(query))
    offset = (page - 1) * page_size
    persisted = list(relation_collection.find(query).sort("relationship_id", 1)
                      .limit(min(offset + page_size, 10000)))
    items = []
    for row in persisted:
        item = {key: value for key, value in row.items() if key != "_id"}
        item["origin"] = "inferred" if item.get("inferred", False) else "official_source"
        item.setdefault("evidence", item.get("description"))
        item.setdefault("source_references", [])
        items.append(item)
    derived = []
    if inferred is None or inferred is False:
        derived = _derived_relationships(db, org_id, tenant_id, record_type, record_id)
    total = persisted_total + len(derived)
    items.extend(derived)
    items.sort(key=lambda item: (item.get("relationship_id", "~"), item.get("relationship_type", "")))
    return {"items": items[offset:offset + page_size], "page": page,
            "page_size": page_size, "total": total}


def intelligence_statistics(db: Any, *, org_id: str, tenant_id: str) -> dict[str, Any]:
    scope = {"org_id": org_id, "tenant_id": tenant_id}
    counts = {kind: int(db[collection].count_documents(scope)) for kind, (collection, _, _) in COLLECTIONS.items()}
    counts["relationships"] = int(db[INTEL_THREAT_RELATIONS].count_documents(scope))
    return {"counts": counts, "total_records": sum(counts.values())}
