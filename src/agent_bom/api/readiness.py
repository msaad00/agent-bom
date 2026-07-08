"""Control-plane readiness checks for orchestrator probes."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass

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


def evaluate_control_plane_readiness() -> ReadinessStatus:
    """Return whether the API can safely accept routed traffic."""
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
        return ReadinessStatus(ready=True)

    db_path = os.environ.get("AGENT_BOM_DB", "").strip() or default_state_db_path()
    if db_path and db_path != ":memory:":
        try:
            conn = sqlite3.connect(db_path, timeout=1.0)
            try:
                conn.execute("SELECT 1")
            finally:
                conn.close()
        except Exception:  # noqa: BLE001
            return ReadinessStatus(ready=False, reason="database_unavailable")

    return ReadinessStatus(ready=True)
