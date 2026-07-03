"""Shared analytics growth caps for local mirrors and runtime observations."""

from __future__ import annotations

import os
import sqlite3
from typing import Any, Protocol

_DEFAULT_ANALYTICS_MAX_EVENTS = 50_000


class _ObservationCapConnection(Protocol):
    def execute(self, query: str, params: Any = ()) -> Any: ...


def _runtime_observation_queries(placeholder: str) -> tuple[str, str, str]:
    if placeholder == "%s":
        return (
            "SELECT COUNT(*) FROM runtime_observations WHERE tenant_id = %s",
            """
            SELECT observation_id FROM runtime_observations
            WHERE tenant_id = %s
            ORDER BY observed_at ASC
            LIMIT %s
            """,
            "DELETE FROM runtime_observations WHERE tenant_id = %s AND observation_id = %s",
        )
    if placeholder == "?":
        return (
            "SELECT COUNT(*) FROM runtime_observations WHERE tenant_id = ?",
            """
            SELECT observation_id FROM runtime_observations
            WHERE tenant_id = ?
            ORDER BY observed_at ASC
            LIMIT ?
            """,
            "DELETE FROM runtime_observations WHERE tenant_id = ? AND observation_id = ?",
        )
    raise ValueError("unsupported SQL placeholder")


def analytics_max_events() -> int:
    """Return the retained analytics event cap. ``<= 0`` disables pruning."""
    raw = os.environ.get("AGENT_BOM_ANALYTICS_MAX_EVENTS")
    if raw is None:
        try:
            from agent_bom.config import ANALYTICS_MAX_EVENTS

            return int(ANALYTICS_MAX_EVENTS)
        except (ImportError, TypeError, ValueError):
            return _DEFAULT_ANALYTICS_MAX_EVENTS
    try:
        return int(raw)
    except ValueError:
        return _DEFAULT_ANALYTICS_MAX_EVENTS


def prune_local_scan_runs(conn: sqlite3.Connection, *, max_events: int | None = None) -> int:
    """Drop oldest ``scan_runs`` rows when the mirror exceeds the cap."""
    cap = analytics_max_events() if max_events is None else max_events
    if cap <= 0:
        return 0
    count = int(conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0])
    if count <= cap:
        return 0
    excess = count - cap
    stale = conn.execute(
        "SELECT run_id FROM scan_runs ORDER BY generated_at ASC, recorded_at ASC LIMIT ?",
        (excess,),
    ).fetchall()
    if not stale:
        return 0
    run_ids = [str(row[0]) for row in stale]
    conn.executemany("DELETE FROM scan_runs WHERE run_id = ?", ((run_id,) for run_id in run_ids))
    return len(run_ids)


def prune_runtime_observations_for_tenant(
    conn: _ObservationCapConnection,
    tenant_id: str,
    *,
    max_events: int | None = None,
    placeholder: str = "?",
) -> int:
    """Drop oldest runtime observations for one tenant when over the cap."""
    cap = analytics_max_events() if max_events is None else max_events
    if cap <= 0:
        return 0
    count_query, stale_query, delete_query = _runtime_observation_queries(placeholder)
    count_row = conn.execute(
        count_query,
        (tenant_id,),
    ).fetchone()
    count = int(count_row[0])
    if count <= cap:
        return 0
    excess = count - cap
    stale = conn.execute(
        stale_query,
        (tenant_id, excess),
    ).fetchall()
    if not stale:
        return 0
    observation_ids = [str(row[0]) for row in stale]
    for observation_id in observation_ids:
        conn.execute(delete_query, (tenant_id, observation_id))
    return len(observation_ids)
