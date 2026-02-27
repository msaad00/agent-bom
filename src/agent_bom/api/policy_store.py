"""Gateway policy persistence — CRUD + audit log for runtime MCP policies.

Follows the same Protocol → InMemory → SQLite pattern as store.py and
fleet_store.py.  All three stores can share the same AGENT_BOM_DB file.
"""

from __future__ import annotations

import sqlite3
import threading
from enum import Enum
from typing import Protocol

from pydantic import BaseModel

# ── Models ────────────────────────────────────────────────────────────────────


class PolicyMode(str, Enum):
    AUDIT = "audit"
    ENFORCE = "enforce"


class GatewayRule(BaseModel):
    id: str
    description: str = ""
    action: str = "block"
    block_tools: list[str] = []
    tool_name: str | None = None
    tool_name_pattern: str | None = None
    arg_pattern: dict[str, str] = {}
    rate_limit: int | None = None
    require_registry_verified: bool = False


class GatewayPolicy(BaseModel):
    policy_id: str
    name: str
    description: str = ""
    mode: PolicyMode = PolicyMode.AUDIT
    rules: list[GatewayRule] = []
    bound_agents: list[str] = []
    bound_agent_types: list[str] = []
    bound_environments: list[str] = []
    created_at: str = ""
    updated_at: str = ""
    enabled: bool = True


class PolicyAuditEntry(BaseModel):
    entry_id: str
    policy_id: str
    policy_name: str
    rule_id: str
    agent_name: str
    tool_name: str
    arguments_preview: dict = {}
    action_taken: str  # "blocked" | "alerted" | "allowed"
    reason: str
    timestamp: str = ""


# ── Protocol ──────────────────────────────────────────────────────────────────


class PolicyStore(Protocol):
    def put_policy(self, policy: GatewayPolicy) -> None: ...
    def get_policy(self, policy_id: str) -> GatewayPolicy | None: ...
    def delete_policy(self, policy_id: str) -> bool: ...
    def list_policies(self) -> list[GatewayPolicy]: ...
    def get_policies_for_agent(
        self,
        agent_name: str | None = None,
        agent_type: str | None = None,
        environment: str | None = None,
    ) -> list[GatewayPolicy]: ...
    def put_audit_entry(self, entry: PolicyAuditEntry) -> None: ...
    def list_audit_entries(
        self,
        policy_id: str | None = None,
        agent_name: str | None = None,
        limit: int = 100,
    ) -> list[PolicyAuditEntry]: ...


# ── InMemory ──────────────────────────────────────────────────────────────────


class InMemoryPolicyStore:
    def __init__(self) -> None:
        self._policies: dict[str, GatewayPolicy] = {}
        self._audit: list[PolicyAuditEntry] = []

    def put_policy(self, policy: GatewayPolicy) -> None:
        self._policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str) -> GatewayPolicy | None:
        return self._policies.get(policy_id)

    def delete_policy(self, policy_id: str) -> bool:
        if policy_id in self._policies:
            del self._policies[policy_id]
            return True
        return False

    def list_policies(self) -> list[GatewayPolicy]:
        return list(self._policies.values())

    def get_policies_for_agent(
        self,
        agent_name: str | None = None,
        agent_type: str | None = None,
        environment: str | None = None,
    ) -> list[GatewayPolicy]:
        results = []
        for p in self._policies.values():
            if not p.enabled:
                continue
            if p.bound_agents and agent_name and agent_name not in p.bound_agents:
                continue
            if p.bound_agent_types and agent_type and agent_type not in p.bound_agent_types:
                continue
            if p.bound_environments and environment and environment not in p.bound_environments:
                continue
            results.append(p)
        return results

    def put_audit_entry(self, entry: PolicyAuditEntry) -> None:
        self._audit.append(entry)

    def list_audit_entries(
        self,
        policy_id: str | None = None,
        agent_name: str | None = None,
        limit: int = 100,
    ) -> list[PolicyAuditEntry]:
        entries = self._audit
        if policy_id:
            entries = [e for e in entries if e.policy_id == policy_id]
        if agent_name:
            entries = [e for e in entries if e.agent_name == agent_name]
        return entries[-limit:][::-1]


# ── SQLite ────────────────────────────────────────────────────────────────────


class SQLitePolicyStore:
    def __init__(self, db_path: str) -> None:
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
        c = self._conn
        c.execute(
            """CREATE TABLE IF NOT EXISTS gateway_policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                mode TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT,
                data TEXT NOT NULL
            )"""
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_gp_name ON gateway_policies(name)"
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS policy_audit_log (
                entry_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                agent_name TEXT,
                action_taken TEXT,
                timestamp TEXT,
                data TEXT NOT NULL
            )"""
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_pal_policy ON policy_audit_log(policy_id)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_pal_agent ON policy_audit_log(agent_name)"
        )
        c.commit()

    # ── policies ──

    def put_policy(self, policy: GatewayPolicy) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO gateway_policies
               (policy_id, name, mode, enabled, updated_at, data)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                policy.policy_id,
                policy.name,
                policy.mode.value,
                int(policy.enabled),
                policy.updated_at,
                policy.model_dump_json(),
            ),
        )
        self._conn.commit()

    def get_policy(self, policy_id: str) -> GatewayPolicy | None:
        row = self._conn.execute(
            "SELECT data FROM gateway_policies WHERE policy_id = ?",
            (policy_id,),
        ).fetchone()
        if row is None:
            return None
        return GatewayPolicy.model_validate_json(row[0])

    def delete_policy(self, policy_id: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM gateway_policies WHERE policy_id = ?",
            (policy_id,),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def list_policies(self) -> list[GatewayPolicy]:
        rows = self._conn.execute(
            "SELECT data FROM gateway_policies ORDER BY name"
        ).fetchall()
        return [GatewayPolicy.model_validate_json(r[0]) for r in rows]

    def get_policies_for_agent(
        self,
        agent_name: str | None = None,
        agent_type: str | None = None,
        environment: str | None = None,
    ) -> list[GatewayPolicy]:
        policies = [p for p in self.list_policies() if p.enabled]
        results = []
        for p in policies:
            if p.bound_agents and agent_name and agent_name not in p.bound_agents:
                continue
            if p.bound_agent_types and agent_type and agent_type not in p.bound_agent_types:
                continue
            if p.bound_environments and environment and environment not in p.bound_environments:
                continue
            results.append(p)
        return results

    # ── audit ──

    def put_audit_entry(self, entry: PolicyAuditEntry) -> None:
        self._conn.execute(
            """INSERT INTO policy_audit_log
               (entry_id, policy_id, agent_name, action_taken, timestamp, data)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                entry.entry_id,
                entry.policy_id,
                entry.agent_name,
                entry.action_taken,
                entry.timestamp,
                entry.model_dump_json(),
            ),
        )
        self._conn.commit()

    def list_audit_entries(
        self,
        policy_id: str | None = None,
        agent_name: str | None = None,
        limit: int = 100,
    ) -> list[PolicyAuditEntry]:
        sql = "SELECT data FROM policy_audit_log WHERE 1=1"
        params: list[str] = []
        if policy_id:
            sql += " AND policy_id = ?"
            params.append(policy_id)
        if agent_name:
            sql += " AND agent_name = ?"
            params.append(agent_name)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(str(limit))
        rows = self._conn.execute(sql, params).fetchall()
        return [PolicyAuditEntry.model_validate_json(r[0]) for r in rows]
