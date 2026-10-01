"""Separate write ownership from the identity of each committed graph revision."""

import sqlite3
import uuid
from typing import Any


def revision_tokens(write_generation: str) -> tuple[str, str]:
    return write_generation or uuid.uuid4().hex, uuid.uuid4().hex


def ensure_sqlite_revisions(conn: sqlite3.Connection, columns: set[str]) -> None:
    for column in ("snapshot_generation", "read_revision"):
        if column not in columns:
            conn.execute(f"ALTER TABLE graph_snapshots ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")  # nosec B608 - fixed internal column names
        conn.execute(f"UPDATE graph_snapshots SET {column} = lower(hex(randomblob(16))) WHERE {column} = ''")  # nosec B608 - fixed internal column names


def ensure_postgres_read_revision(conn: Any) -> None:
    conn.execute("ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS snapshot_generation TEXT NOT NULL DEFAULT ''")
    conn.execute("ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS read_revision TEXT NOT NULL DEFAULT ''")
    conn.execute("UPDATE graph_snapshots SET read_revision = replace(gen_random_uuid()::text, '-', '') WHERE read_revision = ''")


def read_snapshot_identity(conn: Any, tenant: str, scan: str, for_paging: bool, marker: str) -> tuple[str, str]:
    """Read the owner or committed revision using the same tenant-scoped query."""
    if marker not in {"?", "%s"}:
        raise ValueError("Unsupported graph query placeholder")
    sql = f"SELECT scan_id, snapshot_generation, read_revision FROM graph_snapshots WHERE tenant_id = {marker} "  # nosec B608 - placeholder allowlisted above; tenant and scan remain bound values
    if scan:
        row = conn.execute(sql + f"AND scan_id = {marker}", (tenant, scan)).fetchone()  # nosec B608 - fixed SQL and validated placeholder
    else:
        row = conn.execute(sql + "AND snapshot_kind = 'scan' ORDER BY created_at DESC, scan_id DESC LIMIT 1", (tenant,)).fetchone()  # nosec B608 - fixed SQL and validated placeholder
    return (str(row[0]), str(row[2] if for_paging else row[1])) if row else (scan, "")
