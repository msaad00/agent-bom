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

from agent_bom.api.storage_schema import ensure_sqlite_schema_version

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
    deny_tool_classes: list[str] = []
    read_only: bool = False
    block_secret_paths: bool = False
    block_unknown_egress: bool = False
    allowed_hosts: list[str] = []
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
    tenant_id: str = "default"


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
    tenant_id: str = "default"


# ── Protocol ──────────────────────────────────────────────────────────────────


class PolicyStore(Protocol):
    def put_policy(self, policy: GatewayPolicy) -> None: ...
    def get_policy(self, policy_id: str, tenant_id: str | None = None) -> GatewayPolicy | None: ...
    def delete_policy(self, policy_id: str, tenant_id: str | None = None) -> bool: ...
    def list_policies(self, tenant_id: str | None = None) -> list[GatewayPolicy]: ...
    def get_policies_for_agent(
        self,
        agent_name: str | None = None,
        agent_type: str | None = None,
        environment: str | None = None,
        tenant_id: str | None = None,
    ) -> list[GatewayPolicy]: ...
    def put_audit_entry(self, entry: PolicyAuditEntry) -> None: ...
    def list_audit_entries(
        self,
        policy_id: str | None = None,
        agent_name: str | None = None,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[PolicyAuditEntry]: ...


# ── InMemory ──────────────────────────────────────────────────────────────────


class InMemoryPolicyStore:
    def __init__(self) -> None:
        self._policies: dict[str, GatewayPolicy] = {}
        self._audit: list[PolicyAuditEntry] = []

    def put_policy(self, policy: GatewayPolicy) -> None:
        self._policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str, tenant_id: str | None = None) -> GatewayPolicy | None:
        policy = self._policies.get(policy_id)
        if policy is None:
            return None
        if tenant_id is not None and policy.tenant_id != tenant_id:
            return None
        return policy

    def delete_policy(self, policy_id: str, tenant_id: str | None = None) -> bool:
        if self.get_policy(policy_id, tenant_id=tenant_id) is not None:
            del self._policies[policy_id]
            return True
        return False

    def list_policies(self, tenant_id: str | None = None) -> list[GatewayPolicy]:
        policies = list(self._policies.values())
        if tenant_id is not None:
            policies = [p for p in policies if p.tenant_id == tenant_id]
        return policies

    def get_policies_for_agent(
        self,
        agent_name: str | None = None,
        agent_type: str | None = None,
        environment: str | None = None,
        tenant_id: str | None = None,
    ) -> list[GatewayPolicy]:
        results = []
        for p in self.list_policies(tenant_id=tenant_id):
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
        tenant_id: str | None = None,
    ) -> list[PolicyAuditEntry]:
        entries = self._audit
        if policy_id:
            entries = [e for e in entries if e.policy_id == policy_id]
        if agent_name:
            entries = [e for e in entries if e.agent_name == agent_name]
        if tenant_id is not None:
            entries = [e for e in entries if e.tenant_id == tenant_id]
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
        ensure_sqlite_schema_version(c, "gateway_policies")
        c.execute(
            """CREATE TABLE IF NOT EXISTS gateway_policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                mode TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                data TEXT NOT NULL
            )"""
        )
        cols = {r[1] for r in c.execute("PRAGMA table_info(gateway_policies)").fetchall()}
        if "tenant_id" not in cols:
            c.execute("ALTER TABLE gateway_policies ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
        c.execute("CREATE INDEX IF NOT EXISTS idx_gp_name ON gateway_policies(name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_gp_tenant_name ON gateway_policies(tenant_id, name)")
        c.execute(
            """CREATE TABLE IF NOT EXISTS policy_audit_log (
                entry_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                agent_name TEXT,
                action_taken TEXT,
                timestamp TEXT,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                data TEXT NOT NULL
            )"""
        )
        audit_cols = {r[1] for r in c.execute("PRAGMA table_info(policy_audit_log)").fetchall()}
        if "tenant_id" not in audit_cols:
            c.execute("ALTER TABLE policy_audit_log ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
        c.execute("CREATE INDEX IF NOT EXISTS idx_pal_policy ON policy_audit_log(policy_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_pal_agent ON policy_audit_log(agent_name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_pal_ts ON policy_audit_log(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_pal_tenant_ts ON policy_audit_log(tenant_id, timestamp)")
        c.commit()

    # ── policies ──

    def put_policy(self, policy: GatewayPolicy) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO gateway_policies
               (policy_id, name, mode, enabled, updated_at, tenant_id, data)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                policy.policy_id,
                policy.name,
                policy.mode.value,
                int(policy.enabled),
                policy.updated_at,
                policy.tenant_id,
                policy.model_dump_json(),
            ),
        )
        self._conn.commit()

    def get_policy(self, policy_id: str, tenant_id: str | None = None) -> GatewayPolicy | None:
        sql = "SELECT data FROM gateway_policies WHERE policy_id = ?"
        params: list[object] = [policy_id]
        if tenant_id is not None:
            sql += " AND tenant_id = ?"
            params.append(tenant_id)
        row = self._conn.execute(sql, params).fetchone()
        if row is None:
            return None
        return GatewayPolicy.model_validate_json(row[0])

    def delete_policy(self, policy_id: str, tenant_id: str | None = None) -> bool:
        sql = "DELETE FROM gateway_policies WHERE policy_id = ?"
        params: list[object] = [policy_id]
        if tenant_id is not None:
            sql += " AND tenant_id = ?"
            params.append(tenant_id)
        cur = self._conn.execute(sql, params)
        self._conn.commit()
        return cur.rowcount > 0

    def list_policies(self, tenant_id: str | None = None) -> list[GatewayPolicy]:
        sql = "SELECT data FROM gateway_policies"
        params: list[object] = []
        if tenant_id is not None:
            sql += " WHERE tenant_id = ?"
            params.append(tenant_id)
        sql += " ORDER BY name"
        rows = self._conn.execute(sql, params).fetchall()
        return [GatewayPolicy.model_validate_json(r[0]) for r in rows]

    def get_policies_for_agent(
        self,
        agent_name: str | None = None,
        agent_type: str | None = None,
        environment: str | None = None,
        tenant_id: str | None = None,
    ) -> list[GatewayPolicy]:
        policies = [p for p in self.list_policies(tenant_id=tenant_id) if p.enabled]
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
               (entry_id, policy_id, agent_name, action_taken, timestamp, tenant_id, data)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.entry_id,
                entry.policy_id,
                entry.agent_name,
                entry.action_taken,
                entry.timestamp,
                entry.tenant_id,
                entry.model_dump_json(),
            ),
        )
        self._conn.commit()

    def list_audit_entries(
        self,
        policy_id: str | None = None,
        agent_name: str | None = None,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[PolicyAuditEntry]:
        sql = "SELECT data FROM policy_audit_log WHERE 1=1"
        params: list[str] = []
        if policy_id:
            sql += " AND policy_id = ?"
            params.append(policy_id)
        if agent_name:
            sql += " AND agent_name = ?"
            params.append(agent_name)
        if tenant_id is not None:
            sql += " AND tenant_id = ?"
            params.append(tenant_id)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(str(limit))
        rows = self._conn.execute(sql, params).fetchall()
        return [PolicyAuditEntry.model_validate_json(r[0]) for r in rows]

    def cleanup_audit_log(self, max_entries: int = 50_000) -> int:
        """Remove oldest audit log entries when exceeding retention limit."""
        count = self._conn.execute("SELECT COUNT(*) FROM policy_audit_log").fetchone()[0]
        if count <= max_entries:
            return 0
        to_delete = count - max_entries
        cursor = self._conn.execute(
            "DELETE FROM policy_audit_log WHERE entry_id IN (SELECT entry_id FROM policy_audit_log ORDER BY timestamp ASC LIMIT ?)",
            (to_delete,),
        )
        self._conn.commit()
        return cursor.rowcount
