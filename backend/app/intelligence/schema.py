# Intelligence schema definitions for Cyber Threat Intelligence Engine

from typing import Dict, Any, Sequence
from pymongo import ASCENDING

# Validators for each new collection
INTEL_SCHEMA_MAP: Dict[str, Dict[str, Any]] = {
    "threat_records": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "record_id", "title", "description", "severity", "source", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "record_id": {"bsonType": "string"},
            "title": {"bsonType": "string"},
            "description": {"bsonType": "string"},
            "severity": {"bsonType": "string", "enum": ["low", "medium", "high", "critical"]},
            "source": {"bsonType": ["string", "null"]},
            "tags": {"bsonType": ["array", "null"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "attack_techniques": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "technique_id", "name", "description", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "technique_id": {"bsonType": "string"},
            "name": {"bsonType": "string"},
            "description": {"bsonType": "string"},
            "tactics": {"bsonType": ["array", "null"]},
            "platforms": {"bsonType": ["array", "null"]},
            "embedding": {"bsonType": "array", "items": {"bsonType": "double"}},
            "embedding_model": {"bsonType": ["string", "null"]},
            "embedding_dimension": {"bsonType": ["int", "null"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "attack_patterns": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "pattern_id", "name", "description", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "pattern_id": {"bsonType": "string"},
            "name": {"bsonType": "string"},
            "description": {"bsonType": "string"},
            "technique_ids": {"bsonType": ["array", "null"]},
            "embedding": {"bsonType": "array", "items": {"bsonType": "double"}},
            "embedding_model": {"bsonType": ["string", "null"]},
            "embedding_dimension": {"bsonType": ["int", "null"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "vulnerabilities": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "cve_id", "description", "severity", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "cve_id": {"bsonType": "string"},
            "description": {"bsonType": "string"},
            "severity": {"bsonType": "string"},
            "published_date": {"bsonType": ["date", "null"]},
            "references": {"bsonType": ["array", "null"]},
            "embedding": {"bsonType": "array", "items": {"bsonType": "double"}},
            "embedding_model": {"bsonType": ["string", "null"]},
            "embedding_dimension": {"bsonType": ["int", "null"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "detection_rules": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "rule_id", "title", "description", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "rule_id": {"bsonType": "string"},
            "title": {"bsonType": "string"},
            "description": {"bsonType": "string"},
            "sigma": {"bsonType": ["string", "null"]},
            "technique_refs": {"bsonType": ["array", "null"]},
            "embedding": {"bsonType": "array", "items": {"bsonType": "double"}},
            "embedding_model": {"bsonType": ["string", "null"]},
            "embedding_dimension": {"bsonType": ["int", "null"]},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "threat_relationships": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "relationship_id", "source_record_id", "target_record_id", "type", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "relationship_id": {"bsonType": "string"},
            "source_record_id": {"bsonType": "string"},
            "target_record_id": {"bsonType": "string"},
            "type": {"bsonType": "string"},
            "description": {"bsonType": ["string", "null"]},
            "inferred": {"bsonType": "bool"},
            "evidence": {"bsonType": ["object", "string", "null"]},
            "source_references": {"bsonType": ["array", "null"], "items": {"bsonType": "string"}},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "knowledge_chunks": {
        "bsonType": "object",
        "required": ["org_id", "tenant_id", "chunk_id", "doc_id", "content", "chunk_index", "created_at"],
        "properties": {
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "chunk_id": {"bsonType": "string"},
            "doc_id": {"bsonType": "string"},
            "content": {"bsonType": "string"},
            "chunk_index": {"bsonType": "int"},
            "page_number": {"bsonType": ["int", "null"]},
            "embedding": {"bsonType": "array", "items": {"bsonType": "double"}},
            "embedding_model": {"bsonType": "string"},
            "embedding_dimension": {"bsonType": "int"},
            "created_at": {"bsonType": "date"},
            "updated_at": {"bsonType": ["date", "null"]},
        },
    },
    "dataset_sources": {
        "bsonType": "object",
        "required": ["source_id", "org_id", "tenant_id", "name", "url", "last_imported_at"],
        "properties": {
            "source_id": {"bsonType": "string"},
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "name": {"bsonType": "string"},
            "url": {"bsonType": "string"},
            "last_imported_at": {"bsonType": ["date", "null"]},
            "version": {"bsonType": ["string", "null"]},
            "metadata": {"bsonType": ["object", "null"]},
        },
    },
    "ingestion_jobs": {
        "bsonType": "object",
        "required": ["job_id", "source_id", "org_id", "tenant_id", "status", "started_at"],
        "properties": {
            "job_id": {"bsonType": "string"},
            "source_id": {"bsonType": "string"},
            "org_id": {"bsonType": "string"},
            "tenant_id": {"bsonType": "string"},
            "status": {"bsonType": "string", "enum": ["pending", "running", "completed", "failed"]},
            "started_at": {"bsonType": "date"},
            "completed_at": {"bsonType": ["date", "null"]},
            "record_count": {"bsonType": "int"},
            "error_message": {"bsonType": ["string", "null"]},
        },
    },
}

# Index definitions for the intelligence collections
INTEL_INDEX_DEFINITIONS: Dict[str, Sequence[Sequence[Any]]] = {
    "threat_records": [
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("record_id", ASCENDING), {"unique": True}],
        [("severity", ASCENDING)],
    ],
    "attack_techniques": [
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("technique_id", ASCENDING), {"unique": True}],
        [("name", ASCENDING)],
    ],
    "attack_patterns": [
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("pattern_id", ASCENDING), {"unique": True}],
        [("technique_ids", ASCENDING)],
    ],
    "vulnerabilities": [
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("cve_id", ASCENDING), {"unique": True}],
        [("severity", ASCENDING)],
    ],
    "detection_rules": [
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("rule_id", ASCENDING), {"unique": True}],
        [("technique_refs", ASCENDING)],
    ],
    "threat_relationships": [
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("relationship_id", ASCENDING), {"unique": True}],
        [("source_record_id", ASCENDING), ("target_record_id", ASCENDING)],
    ],
    "knowledge_chunks": [
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("doc_id", ASCENDING), ("chunk_index", ASCENDING)],
        [("embedding_model", ASCENDING)],
    ],
    "dataset_sources": [
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("source_id", ASCENDING), {"unique": True}],
    ],
    "ingestion_jobs": [
        [("job_id", ASCENDING), {"unique": True}],
        [("org_id", ASCENDING), ("tenant_id", ASCENDING), ("started_at", ASCENDING)],
    ],
}
