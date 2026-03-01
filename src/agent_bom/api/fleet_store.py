"""Fleet agent registry storage backends.

Persistent storage for managed agent fleet with lifecycle states and trust scores.
Follows the same pattern as ``store.py`` (Protocol + InMemory + SQLite).
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol

from pydantic import BaseModel

# ─── Models ──────────────────────────────────────────────────────────────────


class FleetLifecycleState(str, Enum):
    DISCOVERED = "discovered"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    QUARANTINED = "quarantined"
    DECOMMISSIONED = "decommissioned"


class FleetAgent(BaseModel):
    """A managed agent in the fleet registry."""

    agent_id: str
    name: str
    agent_type: str
    config_path: str = ""
    lifecycle_state: FleetLifecycleState = FleetLifecycleState.DISCOVERED
    owner: str | None = None
    environment: str | None = None
    tags: list[str] = []
    trust_score: float = 0.0
    trust_factors: dict = {}
    server_count: int = 0
    package_count: int = 0
    credential_count: int = 0
    vuln_count: int = 0
    last_discovery: str | None = None
    last_scan: str | None = None
    created_at: str = ""
    updated_at: str = ""
    notes: str = ""


# ─── Protocol ────────────────────────────────────────────────────────────────


class FleetStore(Protocol):
    """Protocol for fleet agent persistence."""

    def put(self, agent: FleetAgent) -> None: ...
    def get(self, agent_id: str) -> FleetAgent | None: ...
    def get_by_name(self, name: str) -> FleetAgent | None: ...
    def delete(self, agent_id: str) -> bool: ...
    def list_all(self) -> list[FleetAgent]: ...
    def list_summary(self) -> list[dict]: ...
    def update_state(self, agent_id: str, state: FleetLifecycleState) -> bool: ...
    def batch_put(self, agents: list[FleetAgent]) -> int: ...


# ─── In-Memory ───────────────────────────────────────────────────────────────


class InMemoryFleetStore:
    """Dict-based in-memory fleet store."""

    def __init__(self) -> None:
        self._agents: dict[str, FleetAgent] = {}

    def put(self, agent: FleetAgent) -> None:
        self._agents[agent.agent_id] = agent

    def get(self, agent_id: str) -> FleetAgent | None:
        return self._agents.get(agent_id)

    def get_by_name(self, name: str) -> FleetAgent | None:
        for a in self._agents.values():
            if a.name == name:
                return a
        return None

    def delete(self, agent_id: str) -> bool:
        if agent_id in self._agents:
            del self._agents[agent_id]
            return True
        return False

    def list_all(self) -> list[FleetAgent]:
        return list(self._agents.values())

    def list_summary(self) -> list[dict]:
        return [
            {
                "agent_id": a.agent_id,
                "name": a.name,
                "lifecycle_state": a.lifecycle_state,
                "trust_score": a.trust_score,
                "updated_at": a.updated_at,
            }
            for a in self._agents.values()
        ]

    def update_state(self, agent_id: str, state: FleetLifecycleState) -> bool:
        agent = self._agents.get(agent_id)
        if agent is None:
            return False
        agent.lifecycle_state = state
        agent.updated_at = datetime.now(timezone.utc).isoformat()
        return True

    def batch_put(self, agents: list[FleetAgent]) -> int:
        """Upsert multiple agents at once."""
        for agent in agents:
            self._agents[agent.agent_id] = agent
        return len(agents)


# ─── SQLite ──────────────────────────────────────────────────────────────────


class SQLiteFleetStore:
    """SQLite-backed persistent fleet store.

    Uses the same database as SQLiteJobStore when configured with the same path.
    """

    def __init__(self, db_path: str = "agent_bom_jobs.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS fleet_agents (
                agent_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                trust_score REAL DEFAULT 0.0,
                updated_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_name ON fleet_agents(name)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_fleet_state ON fleet_agents(lifecycle_state)")
        self._conn.commit()

    def put(self, agent: FleetAgent) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO fleet_agents
               (agent_id, name, lifecycle_state, trust_score, updated_at, data)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                agent.agent_id,
                agent.name,
                agent.lifecycle_state.value,
                agent.trust_score,
                agent.updated_at,
                agent.model_dump_json(),
            ),
        )
        self._conn.commit()

    def get(self, agent_id: str) -> FleetAgent | None:
        row = self._conn.execute("SELECT data FROM fleet_agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if row is None:
            return None
        return FleetAgent.model_validate_json(row[0])

    def get_by_name(self, name: str) -> FleetAgent | None:
        row = self._conn.execute("SELECT data FROM fleet_agents WHERE name = ?", (name,)).fetchone()
        if row is None:
            return None
        return FleetAgent.model_validate_json(row[0])

    def delete(self, agent_id: str) -> bool:
        cursor = self._conn.execute("DELETE FROM fleet_agents WHERE agent_id = ?", (agent_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def list_all(self) -> list[FleetAgent]:
        rows = self._conn.execute("SELECT data FROM fleet_agents ORDER BY name").fetchall()
        return [FleetAgent.model_validate_json(r[0]) for r in rows]

    def list_summary(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT agent_id, name, lifecycle_state, trust_score, updated_at FROM fleet_agents ORDER BY name"
        ).fetchall()
        return [
            {
                "agent_id": r[0],
                "name": r[1],
                "lifecycle_state": r[2],
                "trust_score": r[3],
                "updated_at": r[4],
            }
            for r in rows
        ]

    def update_state(self, agent_id: str, state: FleetLifecycleState) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        agent = self.get(agent_id)
        if agent is None:
            return False
        agent.lifecycle_state = state
        agent.updated_at = now
        self.put(agent)
        return True

    def batch_put(self, agents: list[FleetAgent]) -> int:
        """Upsert multiple agents in a single transaction."""
        if not agents:
            return 0
        self._conn.executemany(
            """INSERT OR REPLACE INTO fleet_agents
               (agent_id, name, lifecycle_state, trust_score, updated_at, data)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [
                (
                    a.agent_id,
                    a.name,
                    a.lifecycle_state.value,
                    a.trust_score,
                    a.updated_at,
                    a.model_dump_json(),
                )
                for a in agents
            ],
        )
        self._conn.commit()
        return len(agents)
