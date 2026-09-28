"""Serialize finding mutations in the caller's database transaction."""

from __future__ import annotations

from typing import Any

from agent_bom.api.storage.sql import Dialect, SqlSession, connection_session
from agent_bom.core.tenancy import require_explicit_tenant_id


def finding_write_session(conn: Any, dialect: Dialect, tenant_id: str) -> SqlSession:
    tenant = require_explicit_tenant_id(tenant_id)
    tx = connection_session(conn, dialect)
    if dialect == "sqlite":
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
    else:
        # Row locks alone cannot serialize two first observations of a new key.
        # Every hub mutation uses this tenant lock before acquiring row locks.
        tx.execute("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", ("hub-findings:" + tenant,))
    return tx
