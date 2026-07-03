"""Shared analytics growth caps for local mirrors and runtime observations."""

from __future__ import annotations

import os
import sqlite3
from typing import Any, Protocol

_DEFAULT_ANALYTICS_MAX_EVENTS = 50_000


class _ObservationCapConnection(Protocol):
    def execute(self, query: str, params: Any = ()) -> Any: ...


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
    count_row = conn.execute(
        f"SELECT COUNT(*) FROM runtime_observations WHERE tenant_id = {placeholder}",
        (tenant_id,),
    ).fetchone()
    count = int(count_row[0])
    if count <= cap:
        return 0
    excess = count - cap
    stale = conn.execute(
        f"""
        SELECT observation_id FROM runtime_observations
        WHERE tenant_id = {placeholder}
        ORDER BY observed_at ASC
        LIMIT {placeholder}
        """,
        (tenant_id, excess),
    ).fetchall()
    if not stale:
        return 0
    observation_ids = [str(row[0]) for row in stale]
    conn.executemany(
        f"DELETE FROM runtime_observations WHERE tenant_id = {placeholder} AND observation_id = {placeholder}",
        [(tenant_id, observation_id) for observation_id in observation_ids],
    )
    return len(observation_ids)
