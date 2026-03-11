"""Local embedded vulnerability database — SQLite for offline scanning and fast lookups.

Phase 1 (issue #606): schema, sync from OSV bulk exports, fast local lookup.
Phase 2: --offline scan integration (bypass API calls, use DB only).

DB location: ~/.agent-bom/db/vulns.db (configurable via AGENT_BOM_DB_PATH).
"""

from agent_bom.db.lookup import VulnDB, lookup_package
from agent_bom.db.schema import DB_PATH, init_db
from agent_bom.db.sync import sync_db

__all__ = [
    "DB_PATH",
    "VulnDB",
    "init_db",
    "lookup_package",
    "sync_db",
]
