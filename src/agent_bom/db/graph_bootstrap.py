"""SQLite graph startup repair and read initialization."""

import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path


def backfill_edge_metadata(conn: sqlite3.Connection) -> None:
    """Keep empty legacy values repairable without scanning normalized edges."""
    for column, source in (("valid_from", "first_seen"), ("source_scan_id", "scan_id")):
        predicate = f"{column} = '' OR {column} IS NULL"
        conn.execute(f"CREATE INDEX IF NOT EXISTS idx_ge_backfill_{column} ON graph_edges({column}) WHERE {predicate}")  # nosec B608 - column and source come from the fixed internal tuple
        conn.execute(f"UPDATE graph_edges SET {column} = {source} WHERE {predicate}")  # nosec B608 - column and source come from the fixed internal tuple


_SCHEMA_INIT_LOCK = threading.Lock()
_INITIALIZED_FILES: dict[str, tuple[int, int]] = {}


def ensure_read_schema(path: Path, initialize: Callable[[], sqlite3.Connection], refresh: Callable[[sqlite3.Connection], None]) -> None:
    """Initialize once per physical file, retaining read concurrency in WAL mode."""
    key = str(path.resolve())
    metadata = path.stat()
    identity = (metadata.st_dev, metadata.st_ino)
    if _INITIALIZED_FILES.get(key) == identity:
        return
    with _SCHEMA_INIT_LOCK:
        if _INITIALIZED_FILES.get(key) == identity:
            return
        # Retire the old identity before attempting replacement initialization:
        # a failed replacement may otherwise leave a reusable inode cached.
        _INITIALIZED_FILES.pop(key, None)
        conn = initialize()
        try:
            refresh(conn)
            _INITIALIZED_FILES[key] = identity
        finally:
            conn.close()
