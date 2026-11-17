"""Manually initialize the configured ThreatGuard database.

This is an operator command, not a pytest module. It is deliberately guarded
so test discovery or importing this file never connects to or changes MongoDB.
Run ``python init_test.py`` only when database initialization is intended.
"""

from __future__ import annotations

import os
import sys


def main() -> None:
    project_root = os.path.abspath(os.path.dirname(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from backend.app.database.connection import get_db
    from backend.app.database.init_db import initialize_database

    result = initialize_database(get_db())
    print(f"Database initialized: {result['database']}")
    print(f"Collections verified: {result['collections_verified']}")


if __name__ == "__main__":
    main()
