from __future__ import annotations

import os
import sys
from typing import Dict, Optional

from pymongo.database import Database

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BACKEND_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for candidate in (PROJECT_ROOT, BACKEND_ROOT):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from backend.app.config import MONGO_DB, MONGO_URI
from backend.app.database.connection import get_db
from backend.app.database.schema import apply_all_schema_and_indexes


def initialize_database(db: Optional[Database] = None) -> Dict[str, object]:
    """Initialize all required collections, schemas, and indexes.

    This function now also sets up the Cyber Threat Intelligence engine collections
    defined in ``backend.app.intelligence.schema``.
    """
    target_db = db if db is not None else get_db()
    # Core collections from the original schema
    required_collections = [
        "organizations",
        "tenants",
        "users",
        "threats",
        "scan_results",
        "endpoint_scans",
        "mitigations",
        "kb_documents",
        "kb_chunks",
        "chat_sessions",
        "audit_logs",
        "revoked_tokens",
        "metrics_snapshots",
    ]
    # Apply the base schema definitions and indexes
    verification = apply_all_schema_and_indexes(target_db)
    # ---------------------------------------------------------------------
    # Cyber Threat Intelligence collections
    # ---------------------------------------------------------------------
    try:
        from backend.app.intelligence.schema import INTEL_SCHEMA_MAP, INTEL_INDEX_DEFINITIONS
        from backend.app.database.schema import create_or_update_collection, apply_indexes
    except ImportError as exc:
        raise RuntimeError("Intelligence schema modules could not be imported.") from exc
    # Create/validate each intelligence collection
    for collection_name, validator in INTEL_SCHEMA_MAP.items():
        create_or_update_collection(target_db, collection_name, validator)
        verification[collection_name] = collection_name in target_db.list_collection_names()
    # Dataset source metadata is tenant-owned now. Remove the legacy global
    # source_id uniqueness constraint so each tenant can maintain its own row.
    sources = target_db["dataset_sources"]
    for index in sources.list_indexes():
        if index.get("key") == {"source_id": 1} and index.get("unique"):
            sources.drop_index(index["name"])
    # Apply indexes for intelligence collections
    for collection_name, index_specs in INTEL_INDEX_DEFINITIONS.items():
        collection = target_db[collection_name]
        apply_indexes(collection, index_specs)
    # ---------------------------------------------------------------------
    # Verify any missing core collections (they may have been created above)
    existing = set(target_db.list_collection_names())
    for collection_name in required_collections:
        if collection_name not in existing:
            verification[collection_name] = False
    # ---------------------------------------------------------------------
    report = {
        "database": target_db.name,
        "collections_verified": all(verification.get(name, False) for name in required_collections + list(INTEL_SCHEMA_MAP.keys())),
        "collections": sorted(target_db.list_collection_names()),
    }
    return report



if __name__ == "__main__":
    result = initialize_database(get_db())
    print(f"Database: {result['database']}")
    print(f"Collections verified: {result['collections_verified']}")
    print(f"Collections: {', '.join(result['collections'])}")
    print("ThreatGuard initialization complete.")
