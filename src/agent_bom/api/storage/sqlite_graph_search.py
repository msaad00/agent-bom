"""SQLite graph search indexing; scope is an optimization, never authorization."""

from __future__ import annotations

import re
import sqlite3

_CREATE_SEARCH = """CREATE VIRTUAL TABLE IF NOT EXISTS graph_node_search USING fts5(
    tenant_id, scan_id, node_id UNINDEXED, entity_type, severity,
    compliance_tags, data_sources, search_text
)"""
_SEARCH_COLUMNS = "rowid, tenant_id, scan_id, node_id, entity_type, severity, compliance_tags, data_sources, search_text"


def ensure_search_index(conn: sqlite3.Connection) -> None:
    """Upgrade the derived index within the caller's reserved write transaction.

    Columns and their contents stay compatible with older writers. Rebuild the
    FTS postings atomically; an interrupted copy/drop/rename must roll back with
    the transaction. This may require substantial startup time and spare disk.
    """
    if not conn.in_transaction:
        raise RuntimeError("Search index initialization requires a write transaction")
    row = conn.execute("SELECT sql FROM sqlite_master WHERE name = 'graph_node_search'").fetchone()
    if row is None:
        conn.execute(_CREATE_SEARCH)
    elif re.search(r"\b(?:tenant_id|scan_id)\s+UNINDEXED\b", row[0], re.IGNORECASE):
        rebuild_search_index(conn, scoped=True)


def rebuild_search_index(conn: sqlite3.Connection, *, scoped: bool) -> None:
    """Rebuild postings without changing rows; caller commits or rolls back.

    Use ``scoped=False`` offline before starting older readers on rollback.
    Mixed reader versions otherwise search different sets of FTS columns.
    """
    if not conn.in_transaction:
        raise RuntimeError("Search index rebuild requires a write transaction")
    statement = _CREATE_SEARCH.replace("IF NOT EXISTS ", "").replace("graph_node_search", "graph_node_search_upgrade")
    if not scoped:
        statement = statement.replace("tenant_id, scan_id,", "tenant_id UNINDEXED, scan_id UNINDEXED,")
    conn.execute(statement)
    conn.execute(f"INSERT INTO graph_node_search_upgrade ({_SEARCH_COLUMNS}) SELECT {_SEARCH_COLUMNS} FROM graph_node_search")  # nosec B608 - fixed internal column names only
    conn.execute("DROP TABLE graph_node_search")
    conn.execute("ALTER TABLE graph_node_search_upgrade RENAME TO graph_node_search")


def scoped_search_expression(query: str, *, tenant_id: str, scan_id: str) -> str:
    """Restrict postings before fetching matches; exact SQL predicates remain.

    Keep user text restricted to the previously searchable columns. FTS scope
    tokens are case/diacritic/punctuation normalized and cannot replace exact
    tenant/snapshot equality. Skip the optimization without a known token:
    opaque punctuation-only, non-ASCII and NUL-containing identifiers remain
    supported by SQL without changing prefix/AND matching into LIKE fallback.
    """
    clauses = [f"{{entity_type severity compliance_tags data_sources search_text}}: ({query})"]
    for column, value in (("tenant_id", tenant_id), ("scan_id", scan_id)):
        if "\x00" not in value and re.search(r"[A-Za-z0-9]", value):
            literal = value.replace('"', '""')
            clauses.append(f'{column}: "{literal}"')
    return " AND ".join(clauses)
