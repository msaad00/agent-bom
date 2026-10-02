"""Control-plane readiness checks for orchestrator probes."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass

from agent_bom import config
from agent_bom.api.durable_store import default_state_db_path, postgres_configured
from agent_bom.api.middleware import clustered_control_plane_required


@dataclass(frozen=True)
class ReadinessStatus:
    ready: bool
    reason: str = ""

    def as_dict(self) -> dict[str, str]:
        if self.ready:
            return {"status": "ready"}
        return {"status": "not_ready", "reason": self.reason}


def _graph_readiness() -> ReadinessStatus:
    # Neptune has no bounded readiness contract yet. Do not initialize a
    # Gremlin client or report readiness based only on another database.
    if config.GRAPH_BACKEND.strip().lower() == "neptune":
        return ReadinessStatus(ready=False, reason="graph_readiness_unsupported")
    try:
        from agent_bom.api.stores import _get_graph_store

        _get_graph_store().check_readiness()
    except Exception:  # noqa: BLE001 — readiness must not leak storage details
        return ReadinessStatus(ready=False, reason="graph_storage_unavailable")
    return ReadinessStatus(ready=True)


def evaluate_control_plane_readiness() -> ReadinessStatus:
    """Return whether the API can safely accept routed traffic."""
    from agent_bom.demo_estate.boot_seed import demo_estate_seeding

    if demo_estate_seeding():
        return ReadinessStatus(ready=False, reason="demo_estate_seeding")
    if clustered_control_plane_required() and not postgres_configured():
        return ReadinessStatus(
            ready=False,
            reason="shared_postgres_required",
        )

    if postgres_configured():
        try:
            from agent_bom.api.postgres_common import _get_pool

            with _get_pool().connection() as conn:
                conn.execute("SELECT 1")
        except Exception:  # noqa: BLE001 — readiness must not leak secrets
            return ReadinessStatus(ready=False, reason="database_unavailable")
        from agent_bom.api.shared_auth_state import PostgresAuthState, get_auth_state

        auth_state = get_auth_state()
        if not isinstance(auth_state, PostgresAuthState) or not auth_state.is_available():
            return ReadinessStatus(ready=False, reason="shared_auth_state_unavailable")
        return _graph_readiness()

    db_path = os.environ.get("AGENT_BOM_DB", "").strip() or default_state_db_path()
    if db_path and db_path != ":memory:":
        try:
            sqlite_conn = sqlite3.connect(db_path, timeout=1.0)
            try:
                sqlite_conn.execute("SELECT 1")
            finally:
                sqlite_conn.close()
        except (sqlite3.Error, OSError, ValueError):
            return ReadinessStatus(ready=False, reason="database_unavailable")

    return _graph_readiness()
