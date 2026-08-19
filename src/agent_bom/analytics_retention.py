"""Shared analytics growth caps for local mirrors and runtime observations."""

from __future__ import annotations

import os
import sqlite3
from typing import Any, Protocol

_DEFAULT_ANALYTICS_MAX_EVENTS = 50_000
_DEFAULT_ANALYTICS_MAX_PACKAGES = 500_000
_DEFAULT_ANALYTICS_MAX_FINDINGS = 250_000


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


def _env_cap(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def analytics_max_packages() -> int:
    """Return the retained local package-row cap. ``<= 0`` disables it."""
    try:
        from agent_bom.config import ANALYTICS_MAX_PACKAGES

        default = int(ANALYTICS_MAX_PACKAGES)
    except (ImportError, TypeError, ValueError):
        default = _DEFAULT_ANALYTICS_MAX_PACKAGES
    return _env_cap("AGENT_BOM_ANALYTICS_MAX_PACKAGES", default)


def analytics_max_findings() -> int:
    """Return the retained local finding-row cap. ``<= 0`` disables it."""
    try:
        from agent_bom.config import ANALYTICS_MAX_FINDINGS

        default = int(ANALYTICS_MAX_FINDINGS)
    except (ImportError, TypeError, ValueError):
        default = _DEFAULT_ANALYTICS_MAX_FINDINGS
    return _env_cap("AGENT_BOM_ANALYTICS_MAX_FINDINGS", default)


def plan_local_scan_prune(
    conn: sqlite3.Connection,
    *,
    max_events: int | None = None,
    max_packages: int | None = None,
    max_findings: int | None = None,
) -> list[str]:
    """Return the oldest whole runs that must be removed to satisfy every cap.

    The newest run is always retained, even if that single run exceeds a row
    cap. This keeps the local mirror useful while making the over-limit state
    visible to operators.
    """
    event_cap = analytics_max_events() if max_events is None else max_events
    package_cap = analytics_max_packages() if max_packages is None else max_packages
    finding_cap = analytics_max_findings() if max_findings is None else max_findings
    rows = conn.execute(
        """
        SELECT run_id, package_rows, finding_rows
        FROM scan_runs
        ORDER BY generated_at ASC, recorded_at ASC, rowid ASC
        """
    ).fetchall()
    if len(rows) <= 1:
        return []

    package_total = sum(int(row[1]) for row in rows)
    finding_total = sum(int(row[2]) for row in rows)
    stale: list[str] = []
    remaining = len(rows)
    for row in rows[:-1]:
        over_events = event_cap > 0 and remaining > event_cap
        over_packages = package_cap > 0 and package_total > package_cap
        over_findings = finding_cap > 0 and finding_total > finding_cap
        if not (over_events or over_packages or over_findings):
            break
        stale.append(str(row[0]))
        remaining -= 1
        package_total -= int(row[1])
        finding_total -= int(row[2])
    return stale


def prune_local_scan_runs(
    conn: sqlite3.Connection,
    *,
    max_events: int | None = None,
    max_packages: int | None = None,
    max_findings: int | None = None,
) -> int:
    """Drop oldest whole scan runs when any configured mirror cap is exceeded."""
    run_ids = plan_local_scan_prune(
        conn,
        max_events=max_events,
        max_packages=max_packages,
        max_findings=max_findings,
    )
    if not run_ids:
        return 0
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
