"""Privacy-bounded, opt-in product adoption funnel events.

The store deliberately accepts only coarse enumerated dimensions. It never
receives tenant, finding, resource, source-content, or credential identifiers,
so enabling it cannot turn scan evidence into a second customer-data store.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

from agent_bom.config import ADOPTION_EVENTS_DB, ADOPTION_EVENTS_ENABLED

SCHEMA_VERSION: Final = "adoption-funnel.v1"
DEFAULT_PATH: Final = Path.home() / ".agent-bom" / "adoption-events.sqlite"

_EVENTS: Final = frozenset(
    {
        "scan_completed",
        "artifact_created",
        "investigation_started",
        "verification_completed",
        "repeat_use",
        "ci_adopted",
        "control_plane_adopted",
    }
)
_CHANNELS: Final = frozenset({"cli", "ci", "github_action", "control_plane", "docker"})
_OUTCOMES: Final = frozenset({"complete", "partial", "failed", "verified_fixed", "still_affected", "unavailable_evidence"})
_ARTIFACT_TYPES: Final = frozenset({"json", "sarif", "cyclonedx", "spdx", "html", "markdown", "graph"})
_CI_PROVIDERS: Final = frozenset({"github_actions", "gitlab_ci", "circleci", "jenkins", "other"})
_DIMENSIONS: Final = {
    "channel": _CHANNELS,
    "outcome": _OUTCOMES,
    "artifact_type": _ARTIFACT_TYPES,
    "ci_provider": _CI_PROVIDERS,
}
_MILESTONES: Final = frozenset({"repeat_use", "ci_adopted", "control_plane_adopted"})


class AdoptionEventStore:
    """SQLite funnel store that is a complete no-op until explicitly enabled."""

    def __init__(self, db_path: str | Path | None = None, *, enabled: bool = ADOPTION_EVENTS_ENABLED) -> None:
        configured_path = Path(ADOPTION_EVENTS_DB).expanduser() if ADOPTION_EVENTS_DB else DEFAULT_PATH
        self.db_path = Path(db_path).expanduser() if db_path is not None else configured_path
        self.enabled = enabled
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        try:
            self.db_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except NotImplementedError:  # pragma: no cover - Windows permission shim
            pass
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS adoption_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                channel TEXT,
                outcome TEXT,
                artifact_type TEXT,
                ci_provider TEXT,
                recorded_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS adoption_milestone_once
            ON adoption_events(event) WHERE event IN ('repeat_use', 'ci_adopted', 'control_plane_adopted');
            """
        )
        return conn

    @staticmethod
    def _validate(event: str, dimensions: dict[str, str]) -> dict[str, str | None]:
        if event not in _EVENTS:
            raise ValueError(f"Unsupported adoption event: {event}")
        unknown = set(dimensions) - set(_DIMENSIONS)
        if unknown:
            raise ValueError("Adoption events accept only documented bounded dimensions")
        normalized: dict[str, str | None] = {name: None for name in _DIMENSIONS}
        for name, value in dimensions.items():
            if not isinstance(value, str) or value not in _DIMENSIONS[name]:
                raise ValueError(f"Unsupported {name} value")
            normalized[name] = value
        if event in {"scan_completed", "artifact_created", "investigation_started", "verification_completed"} and not normalized["channel"]:
            raise ValueError("channel is required")
        if event == "scan_completed" and not normalized["outcome"]:
            raise ValueError("outcome is required")
        if event == "artifact_created" and not normalized["artifact_type"]:
            raise ValueError("artifact_type is required")
        return normalized

    def _insert(self, conn: sqlite3.Connection, event: str, values: dict[str, str | None]) -> bool:
        verb = "INSERT OR IGNORE" if event in _MILESTONES else "INSERT"
        cursor = conn.execute(
            f"{verb} INTO adoption_events(event, channel, outcome, artifact_type, ci_provider, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",  # noqa: S608 - verb is selected from a fixed literal
            (
                event,
                values["channel"],
                values["outcome"],
                values["artifact_type"],
                values["ci_provider"],
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        return cursor.rowcount > 0

    def record(self, event: str, **dimensions: str) -> bool:
        values = self._validate(event, dimensions)
        if not self.enabled:
            return False
        with self._lock, self._connect() as conn:
            scan_count_before = int(conn.execute("SELECT COUNT(*) FROM adoption_events WHERE event = 'scan_completed'").fetchone()[0])
            recorded = self._insert(conn, event, values)
            if event == "scan_completed":
                if scan_count_before >= 1:
                    self._insert(conn, "repeat_use", {name: None for name in _DIMENSIONS})
                if values["channel"] in {"ci", "github_action"}:
                    self._insert(conn, "ci_adopted", {name: None for name in _DIMENSIONS})
                if values["channel"] == "control_plane":
                    self._insert(conn, "control_plane_adopted", {name: None for name in _DIMENSIONS})
            conn.commit()
        return recorded

    def events(self) -> list[dict[str, str | int | None]]:
        if not self.enabled or not self.db_path.exists():
            return []
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT event, channel, outcome, artifact_type, ci_provider, recorded_at FROM adoption_events ORDER BY id"
            ).fetchall()
        return [dict(row) for row in rows]

    def summary(self) -> dict[str, object]:
        counts = Counter(str(row["event"]) for row in self.events())

        def _transition(numerator_event: str, denominator_event: str) -> dict[str, int | float | None]:
            numerator = counts[numerator_event]
            denominator = counts[denominator_event]
            return {
                "numerator": numerator,
                "denominator": denominator,
                "rate": round(numerator / denominator, 4) if denominator else None,
            }

        return {
            "schema_version": SCHEMA_VERSION,
            "enabled": self.enabled,
            "counts": dict(sorted(counts.items())),
            "funnel": {
                "unit": "bounded_event_counts_not_unique_users",
                "transitions": {
                    "scan_to_artifact": _transition("artifact_created", "scan_completed"),
                    "artifact_to_investigation": _transition("investigation_started", "artifact_created"),
                    "investigation_to_verification": _transition("verification_completed", "investigation_started"),
                },
                "limitations": [
                    "Rates describe event progression on this installation, not unique people or market adoption.",
                    "Numerators are not forced below denominators; retries and multiple artifacts remain visible.",
                ],
            },
            "privacy": {
                "telemetry_disabled_by_default": True,
                "stores_source_contents": False,
                "stores_secrets_or_credentials": False,
                "stores_raw_findings": False,
                "stores_customer_resource_identifiers": False,
                "stores_tenant_identifiers": False,
                "dimensions": sorted(_DIMENSIONS),
            },
        }


_store: AdoptionEventStore | None = None


def get_adoption_event_store() -> AdoptionEventStore:
    global _store
    if _store is None:
        enabled = os.environ.get("AGENT_BOM_ADOPTION_EVENTS_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}
        path = os.environ.get("AGENT_BOM_ADOPTION_EVENTS_DB", "").strip() or None
        _store = AdoptionEventStore(path, enabled=enabled)
    return _store


def set_adoption_event_store(store: AdoptionEventStore | None) -> None:
    global _store
    _store = store


def record_adoption_event_best_effort(event: str, **dimensions: str) -> bool:
    """Record a bounded event without ever changing the product workflow result."""
    try:
        return get_adoption_event_store().record(event, **dimensions)
    except (OSError, sqlite3.Error, ValueError):
        return False


def adoption_channel() -> str:
    """Return a coarse execution channel without recording repository or runner identity."""
    if os.environ.get("GITHUB_ACTIONS", "").strip().lower() == "true":
        return "github_action"
    if os.environ.get("CI", "").strip().lower() in {"1", "true", "yes"}:
        return "ci"
    return "cli"


def record_scan_completion_best_effort(
    *,
    outcome: str,
    artifact_type: str | None = None,
    channel: str | None = None,
) -> bool:
    """Record a scan and optional artifact using only environment class, never identity."""
    if channel is None:
        channel = adoption_channel()
    provider = "github_actions" if channel == "github_action" else None
    recorded = record_adoption_event_best_effort(
        "scan_completed",
        **{key: value for key, value in {"channel": channel, "outcome": outcome, "ci_provider": provider}.items() if value},
    )
    if artifact_type:
        record_adoption_event_best_effort("artifact_created", channel=channel, artifact_type=artifact_type)
    return recorded


__all__ = [
    "AdoptionEventStore",
    "adoption_channel",
    "get_adoption_event_store",
    "record_adoption_event_best_effort",
    "record_scan_completion_best_effort",
    "set_adoption_event_store",
]
