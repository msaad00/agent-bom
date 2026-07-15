"""Persisted, composable AI-system blueprints with versioning + approval.

A blueprint is a first-class, stored, queryable object describing an *approved*
AI system: the agents, models, tools, datasets, identities, owners, and
guardrails that compose it. It replaces the read-only role archetypes in
``agent_bom.runtime_blueprints`` (which still seed it) with a durable entity that
the graph snapshot and drift evaluation can reference by id.

Lifecycle (this module is the foundation the rest of the governance epic builds
on):

- a blueprint owns an ordered series of immutable **versions**; each version
  snapshots the full composition,
- a version moves through an **approval workflow** — ``draft`` → ``pending`` →
  ``approved`` / ``rejected`` — recorded with a **mandatory accountable
  approver**, decision timestamp, and optional note,
- an ``approved`` version is immutable; a new edit always creates a fresh
  ``draft`` version rather than mutating an approved one.

Approval authority is enforced at the API layer with the existing RBAC model
(the admin/``config`` capability); this module additionally refuses to approve a
version without an accountable approver, so an approved version can never be
orphaned. Storage matches the durable-by-default control-plane store pattern
(in-memory / SQLite / Postgres with tenant RLS, idempotent DDL).
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version

# Approval-workflow states. A version is born ``draft``, is ``pending`` once
# submitted for approval, and lands in a terminal ``approved`` / ``rejected``
# state. Only ``approved`` is immutable-and-active; ``rejected`` is retained for
# the audit trail.
STATUS_DRAFT = "draft"
STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
VALID_STATUSES = (STATUS_DRAFT, STATUS_PENDING, STATUS_APPROVED, STATUS_REJECTED)

# Actor recorded as the approver for system-seeded archetype versions. Seeded
# blueprints are pre-approved so a fresh tenant starts from the canonical role
# archetypes without a manual approval round-trip; the accountable-approver
# invariant is still satisfied by this explicit system principal.
SEED_APPROVER = "system:blueprint-seed"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class BlueprintComposition:
    """The approved entities a blueprint version composes.

    Every axis is a list of stable string references (names/ids). ``guardrails``
    carries the human/tooling controls the blueprint asserts (e.g. approval-gated
    or restricted capabilities). Kept as plain string lists so a version snapshot
    serialises deterministically and diffs cleanly.
    """

    agents: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    datasets: list[str] = field(default_factory=list)
    identities: list[str] = field(default_factory=list)
    owners: list[str] = field(default_factory=list)
    guardrails: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, list[str]]:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict[str, Any] | None) -> BlueprintComposition:
        data = data or {}

        def _strs(key: str) -> list[str]:
            value = data.get(key)
            if not isinstance(value, list | tuple):
                return []
            return [str(item) for item in value]

        return BlueprintComposition(
            agents=_strs("agents"),
            models=_strs("models"),
            tools=_strs("tools"),
            datasets=_strs("datasets"),
            identities=_strs("identities"),
            owners=_strs("owners"),
            guardrails=_strs("guardrails"),
        )


@dataclass
class BlueprintVersion:
    """One immutable-once-approved version of a blueprint and its approval state."""

    version_id: str
    blueprint_id: str
    tenant_id: str
    version: int
    status: str  # draft | pending | approved | rejected
    composition: BlueprintComposition
    created_at: str
    created_by: str = ""
    submitted_at: str = ""
    submitted_by: str = ""
    decided_at: str = ""
    # Accountable approver recorded on an approve/reject decision. Mandatory for
    # an approval — an approved version is never orphaned.
    approver: str = ""
    decision_note: str = ""
    # Role archetype this version was seeded from, when applicable (empty for
    # operator-authored versions). Lets the graph tie a stored blueprint back to
    # the code archetype it derived from.
    seeded_from: str = ""

    def is_immutable(self) -> bool:
        """An approved version is frozen; edits must create a new draft."""
        return self.status == STATUS_APPROVED

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["composition"] = self.composition.to_dict()
        return data

    @staticmethod
    def from_dict(data: dict[str, Any]) -> BlueprintVersion:
        payload = dict(data)
        payload["composition"] = BlueprintComposition.from_dict(payload.get("composition"))
        return BlueprintVersion(**payload)


@dataclass
class Blueprint:
    """A persisted AI-system blueprint header (its versions live alongside)."""

    blueprint_id: str
    tenant_id: str
    name: str
    owner: str
    owner_type: str = ""
    description: str = ""
    created_at: str = ""
    updated_at: str = ""
    # Highest version number that reached ``approved`` (0 = never approved).
    current_version: int = 0
    # Highest version number that exists in any state.
    latest_version: int = 0
    # Status of the latest (highest-numbered) version — the blueprint's
    # workflow position at a glance.
    approval_status: str = STATUS_DRAFT
    # Archetype id this blueprint was seeded from (empty for authored blueprints).
    seeded_from: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Blueprint:
        return Blueprint(**data)


@dataclass
class BlueprintPage:
    """A paginated slice of a tenant's blueprints."""

    blueprints: list[Blueprint]
    next_offset: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "blueprints": [b.to_dict() for b in self.blueprints],
            "next_offset": self.next_offset,
        }


class BlueprintStore(Protocol):
    def put_blueprint(self, blueprint: Blueprint) -> None: ...

    def get_blueprint(self, tenant_id: str, blueprint_id: str) -> Blueprint | None: ...

    def list_blueprints(self, tenant_id: str, *, limit: int = 50, offset: int = 0) -> BlueprintPage: ...

    def iter_all_blueprints(self, *, limit: int = 10000) -> list[Blueprint]: ...

    def put_version(self, version: BlueprintVersion) -> None: ...

    def get_version(self, tenant_id: str, blueprint_id: str, version: int) -> BlueprintVersion | None: ...

    def list_versions(self, tenant_id: str, blueprint_id: str, *, limit: int = 200) -> list[BlueprintVersion]: ...


# ── In-memory backend (explicit ephemeral opt-out / tests) ────────────────────


class InMemoryBlueprintStore:
    def __init__(self) -> None:
        self._blueprints: dict[str, dict[str, Blueprint]] = defaultdict(dict)
        self._versions: dict[str, dict[str, BlueprintVersion]] = defaultdict(dict)
        self._lock = threading.Lock()

    @staticmethod
    def _vkey(blueprint_id: str, version: int) -> str:
        return f"{blueprint_id}:{version}"

    def put_blueprint(self, blueprint: Blueprint) -> None:
        with self._lock:
            self._blueprints[blueprint.tenant_id][blueprint.blueprint_id] = blueprint

    def get_blueprint(self, tenant_id: str, blueprint_id: str) -> Blueprint | None:
        with self._lock:
            return self._blueprints.get(tenant_id, {}).get(blueprint_id)

    def list_blueprints(self, tenant_id: str, *, limit: int = 50, offset: int = 0) -> BlueprintPage:
        with self._lock:
            rows = sorted(
                self._blueprints.get(tenant_id, {}).values(),
                key=lambda b: (b.updated_at, b.blueprint_id),
                reverse=True,
            )
        window = rows[offset : offset + limit]
        next_offset = offset + limit if offset + limit < len(rows) else None
        return BlueprintPage(blueprints=window, next_offset=next_offset)

    def iter_all_blueprints(self, *, limit: int = 10000) -> list[Blueprint]:
        with self._lock:
            rows = [b for tenant in self._blueprints.values() for b in tenant.values()]
        return rows[:limit]

    def put_version(self, version: BlueprintVersion) -> None:
        with self._lock:
            self._versions[version.tenant_id][self._vkey(version.blueprint_id, version.version)] = version

    def get_version(self, tenant_id: str, blueprint_id: str, version: int) -> BlueprintVersion | None:
        with self._lock:
            return self._versions.get(tenant_id, {}).get(self._vkey(blueprint_id, version))

    def list_versions(self, tenant_id: str, blueprint_id: str, *, limit: int = 200) -> list[BlueprintVersion]:
        with self._lock:
            rows = [v for v in self._versions.get(tenant_id, {}).values() if v.blueprint_id == blueprint_id]
        return sorted(rows, key=lambda v: v.version, reverse=True)[:limit]


# ── SQLite backend (single-node durable default) ──────────────────────────────


class SQLiteBlueprintStore:
    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "ai_system_blueprints")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_system_blueprints (
                tenant_id TEXT NOT NULL,
                blueprint_id TEXT NOT NULL,
                name TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, blueprint_id)
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ai_system_blueprints_tenant "
            "ON ai_system_blueprints(tenant_id, updated_at DESC, blueprint_id)"
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_system_blueprint_versions (
                tenant_id TEXT NOT NULL,
                blueprint_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                version_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, blueprint_id, version)
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ai_system_blueprint_versions_lookup "
            "ON ai_system_blueprint_versions(tenant_id, blueprint_id, version DESC)"
        )
        self._conn.commit()

    def put_blueprint(self, blueprint: Blueprint) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO ai_system_blueprints (tenant_id, blueprint_id, name, updated_at, data) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                blueprint.tenant_id,
                blueprint.blueprint_id,
                blueprint.name,
                blueprint.updated_at,
                json.dumps(blueprint.to_dict(), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get_blueprint(self, tenant_id: str, blueprint_id: str) -> Blueprint | None:
        row = self._conn.execute(
            "SELECT data FROM ai_system_blueprints WHERE tenant_id = ? AND blueprint_id = ?",
            (tenant_id, blueprint_id),
        ).fetchone()
        return Blueprint.from_dict(json.loads(row[0])) if row else None

    def list_blueprints(self, tenant_id: str, *, limit: int = 50, offset: int = 0) -> BlueprintPage:
        rows = self._conn.execute(
            "SELECT data FROM ai_system_blueprints WHERE tenant_id = ? "
            "ORDER BY updated_at DESC, blueprint_id DESC LIMIT ? OFFSET ?",
            (tenant_id, limit + 1, offset),
        ).fetchall()
        blueprints = [Blueprint.from_dict(json.loads(r[0])) for r in rows[:limit]]
        next_offset = offset + limit if len(rows) > limit else None
        return BlueprintPage(blueprints=blueprints, next_offset=next_offset)

    def iter_all_blueprints(self, *, limit: int = 10000) -> list[Blueprint]:
        rows = self._conn.execute(
            "SELECT data FROM ai_system_blueprints ORDER BY updated_at ASC LIMIT ?", (limit,)
        ).fetchall()
        return [Blueprint.from_dict(json.loads(r[0])) for r in rows]

    def put_version(self, version: BlueprintVersion) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO ai_system_blueprint_versions "
            "(tenant_id, blueprint_id, version, version_id, status, created_at, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                version.tenant_id,
                version.blueprint_id,
                version.version,
                version.version_id,
                version.status,
                version.created_at,
                json.dumps(version.to_dict(), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get_version(self, tenant_id: str, blueprint_id: str, version: int) -> BlueprintVersion | None:
        row = self._conn.execute(
            "SELECT data FROM ai_system_blueprint_versions WHERE tenant_id = ? AND blueprint_id = ? AND version = ?",
            (tenant_id, blueprint_id, version),
        ).fetchone()
        return BlueprintVersion.from_dict(json.loads(row[0])) if row else None

    def list_versions(self, tenant_id: str, blueprint_id: str, *, limit: int = 200) -> list[BlueprintVersion]:
        rows = self._conn.execute(
            "SELECT data FROM ai_system_blueprint_versions WHERE tenant_id = ? AND blueprint_id = ? "
            "ORDER BY version DESC LIMIT ?",
            (tenant_id, blueprint_id, limit),
        ).fetchall()
        return [BlueprintVersion.from_dict(json.loads(r[0])) for r in rows]


# ── Lifecycle / workflow operations ───────────────────────────────────────────


class BlueprintApprovalError(ValueError):
    """Raised when an approval/transition violates the workflow invariants.

    Mapped to an HTTP 400 by the API layer. Covers a missing accountable
    approver, an out-of-order state transition, and an attempt to mutate an
    immutable (approved) version.
    """


def _archetype_composition(archetype: dict[str, Any]) -> BlueprintComposition:
    """Derive a blueprint composition from a runtime role archetype.

    The archetype expresses allowed/restricted/approval-gated tool *categories*
    and intended users; we map those onto the composition axes so a seeded
    blueprint is a faithful, editable starting point rather than an opaque copy.
    """

    def _strs(key: str) -> list[str]:
        value = archetype.get(key)
        if not isinstance(value, list | tuple):
            return []
        return [str(item) for item in value]

    guardrails = [f"restricted:{c}" for c in _strs("restricted_tool_categories")]
    guardrails += [f"approval_required:{c}" for c in _strs("approval_required_for")]
    guardrails.append(f"default_decision:{archetype.get('default_decision', 'warn')}")
    guardrails.append(f"retention:{archetype.get('retention_mode', 'metadata_only')}")
    return BlueprintComposition(
        agents=[],
        models=[],
        tools=_strs("allowed_tool_categories"),
        datasets=[],
        identities=[],
        owners=_strs("intended_users"),
        guardrails=guardrails,
    )


def create_blueprint(
    store: BlueprintStore,
    *,
    tenant_id: str,
    name: str,
    owner: str,
    composition: BlueprintComposition | None = None,
    owner_type: str = "",
    description: str = "",
    created_by: str = "",
    seeded_from: str = "",
    blueprint_id: str | None = None,
) -> tuple[Blueprint, BlueprintVersion]:
    """Create a blueprint with an initial draft version 1.

    A blueprint is always owner-bound at creation (``owner`` is the accountable
    human/team). The first version is a ``draft`` — it does not take effect until
    it is submitted for approval and approved.
    """
    now = _now_iso()
    bid = blueprint_id or f"bp_{secrets.token_hex(8)}"
    version = BlueprintVersion(
        version_id=f"bpv_{secrets.token_hex(8)}",
        blueprint_id=bid,
        tenant_id=tenant_id,
        version=1,
        status=STATUS_DRAFT,
        composition=composition or BlueprintComposition(),
        created_at=now,
        created_by=created_by,
        seeded_from=seeded_from,
    )
    blueprint = Blueprint(
        blueprint_id=bid,
        tenant_id=tenant_id,
        name=name.strip()[:200] or bid,
        owner=owner.strip()[:200],
        owner_type=owner_type.strip()[:60],
        description=description.strip()[:1000],
        created_at=now,
        updated_at=now,
        current_version=0,
        latest_version=1,
        approval_status=STATUS_DRAFT,
        seeded_from=seeded_from,
    )
    store.put_version(version)
    store.put_blueprint(blueprint)
    return blueprint, version


def create_draft_version(
    store: BlueprintStore,
    *,
    tenant_id: str,
    blueprint_id: str,
    composition: BlueprintComposition,
    created_by: str = "",
) -> BlueprintVersion | None:
    """Add a new ``draft`` version (latest + 1) capturing an edited composition.

    Approved versions are immutable, so an edit never rewrites history — it opens
    a fresh draft that must itself go through approval. Returns None when the
    blueprint does not exist.
    """
    blueprint = store.get_blueprint(tenant_id, blueprint_id)
    if blueprint is None:
        return None
    next_version = blueprint.latest_version + 1
    now = _now_iso()
    version = BlueprintVersion(
        version_id=f"bpv_{secrets.token_hex(8)}",
        blueprint_id=blueprint_id,
        tenant_id=tenant_id,
        version=next_version,
        status=STATUS_DRAFT,
        composition=composition,
        created_at=now,
        created_by=created_by,
    )
    store.put_version(version)
    blueprint.latest_version = next_version
    blueprint.approval_status = STATUS_DRAFT
    blueprint.updated_at = now
    store.put_blueprint(blueprint)
    return version


def _refresh_blueprint_after(store: BlueprintStore, blueprint: Blueprint, version: BlueprintVersion) -> None:
    """Roll a version's new status up onto its blueprint header."""
    blueprint.updated_at = _now_iso()
    if version.version >= blueprint.latest_version:
        blueprint.approval_status = version.status
    if version.status == STATUS_APPROVED:
        blueprint.current_version = max(blueprint.current_version, version.version)
    store.put_blueprint(blueprint)


def submit_version_for_approval(
    store: BlueprintStore,
    *,
    tenant_id: str,
    blueprint_id: str,
    version: int,
    submitted_by: str = "",
) -> BlueprintVersion | None:
    """Move a ``draft`` version to ``pending`` (awaiting an approver)."""
    record = store.get_version(tenant_id, blueprint_id, version)
    if record is None:
        return None
    if record.status != STATUS_DRAFT:
        raise BlueprintApprovalError(f"only a draft version can be submitted (current status: {record.status})")
    record.status = STATUS_PENDING
    record.submitted_at = _now_iso()
    record.submitted_by = submitted_by
    store.put_version(record)
    blueprint = store.get_blueprint(tenant_id, blueprint_id)
    if blueprint is not None:
        _refresh_blueprint_after(store, blueprint, record)
    return record


def approve_version(
    store: BlueprintStore,
    *,
    tenant_id: str,
    blueprint_id: str,
    version: int,
    approver: str,
    note: str = "",
) -> BlueprintVersion | None:
    """Approve a ``pending`` version, recording the mandatory accountable approver.

    An approval requires an accountable approver — an empty ``approver`` raises
    ``BlueprintApprovalError`` so an approved (immutable, in-effect) version can
    never be orphaned. RBAC (who is *allowed* to approve) is enforced separately
    at the API boundary.
    """
    if not approver or not approver.strip():
        raise BlueprintApprovalError("an approval requires an accountable approver")
    record = store.get_version(tenant_id, blueprint_id, version)
    if record is None:
        return None
    if record.status == STATUS_APPROVED:
        raise BlueprintApprovalError("version is already approved and immutable")
    if record.status != STATUS_PENDING:
        raise BlueprintApprovalError(f"only a pending version can be approved (current status: {record.status})")
    record.status = STATUS_APPROVED
    record.approver = approver.strip()[:200]
    record.decision_note = note.strip()[:1000]
    record.decided_at = _now_iso()
    store.put_version(record)
    blueprint = store.get_blueprint(tenant_id, blueprint_id)
    if blueprint is not None:
        _refresh_blueprint_after(store, blueprint, record)
    return record


def reject_version(
    store: BlueprintStore,
    *,
    tenant_id: str,
    blueprint_id: str,
    version: int,
    approver: str,
    note: str = "",
) -> BlueprintVersion | None:
    """Reject a ``pending`` version, recording the accountable decision-maker."""
    if not approver or not approver.strip():
        raise BlueprintApprovalError("a rejection requires an accountable reviewer")
    record = store.get_version(tenant_id, blueprint_id, version)
    if record is None:
        return None
    if record.status != STATUS_PENDING:
        raise BlueprintApprovalError(f"only a pending version can be rejected (current status: {record.status})")
    record.status = STATUS_REJECTED
    record.approver = approver.strip()[:200]
    record.decision_note = note.strip()[:1000]
    record.decided_at = _now_iso()
    store.put_version(record)
    blueprint = store.get_blueprint(tenant_id, blueprint_id)
    if blueprint is not None:
        _refresh_blueprint_after(store, blueprint, record)
    return record


def _composition_entities(composition: BlueprintComposition) -> dict[str, set[str]]:
    return {
        "agents": set(composition.agents),
        "models": set(composition.models),
        "tools": set(composition.tools),
        "datasets": set(composition.datasets),
        "identities": set(composition.identities),
        "owners": set(composition.owners),
        "guardrails": set(composition.guardrails),
    }


def diff_versions(
    store: BlueprintStore,
    *,
    tenant_id: str,
    blueprint_id: str,
    from_version: int,
    to_version: int,
) -> dict[str, Any] | None:
    """Diff two versions' compositions (added / removed / persistent per axis).

    Mirrors the ``BaselineDiff`` vocabulary (``added``/``removed``/``persistent``
    with counts + a net_change) so a version diff reads like the scan baseline
    diffs used elsewhere. Returns None when either version is missing.
    """
    a = store.get_version(tenant_id, blueprint_id, from_version)
    b = store.get_version(tenant_id, blueprint_id, to_version)
    if a is None or b is None:
        return None
    from_entities = _composition_entities(a.composition)
    to_entities = _composition_entities(b.composition)
    axes: dict[str, dict[str, list[str]]] = {}
    added_count = removed_count = persistent_count = 0
    for axis in from_entities:
        prev = from_entities[axis]
        curr = to_entities[axis]
        added = sorted(curr - prev)
        removed = sorted(prev - curr)
        persistent = sorted(prev & curr)
        added_count += len(added)
        removed_count += len(removed)
        persistent_count += len(persistent)
        axes[axis] = {"added": added, "removed": removed, "persistent": persistent}
    return {
        "blueprint_id": blueprint_id,
        "from_version": from_version,
        "to_version": to_version,
        "axes": axes,
        "added_count": added_count,
        "removed_count": removed_count,
        "persistent_count": persistent_count,
        "net_change": added_count - removed_count,
    }


def seed_blueprints_from_archetypes(
    store: BlueprintStore,
    *,
    tenant_id: str,
    archetypes: list[dict[str, Any]] | None = None,
    actor: str = SEED_APPROVER,
) -> list[Blueprint]:
    """Seed a tenant's blueprints from the canonical runtime role archetypes.

    Each archetype becomes a stored, pre-approved blueprint (version 1) whose
    composition is derived from the archetype's tool categories / intended users
    / guardrails. Idempotent: an archetype already seeded for this tenant (matched
    by ``seeded_from``) is skipped, so re-running seed does not duplicate rows.
    The code archetypes are not deleted — they remain the derivation source.
    """
    if archetypes is None:
        from agent_bom.runtime_blueprints import runtime_role_blueprints

        archetypes = runtime_role_blueprints()
    existing = {b.seeded_from for b in store.iter_all_blueprints(limit=10000) if b.tenant_id == tenant_id and b.seeded_from}
    created: list[Blueprint] = []
    for archetype in archetypes:
        archetype_id = str(archetype.get("blueprint_id") or "").strip()
        if not archetype_id or archetype_id in existing:
            continue
        composition = _archetype_composition(archetype)
        owner = (composition.owners[0] if composition.owners else "governance") or "governance"
        blueprint, version = create_blueprint(
            store,
            tenant_id=tenant_id,
            name=str(archetype.get("label") or archetype_id),
            owner=owner,
            owner_type="role_archetype",
            description=str(archetype.get("description") or ""),
            composition=composition,
            created_by=actor,
            seeded_from=archetype_id,
            blueprint_id=f"bp_seed_{archetype_id}",
        )
        # A seeded archetype ships pre-approved: submit + approve in one pass so a
        # new tenant starts from the canonical, in-effect blueprints.
        submit_version_for_approval(
            store, tenant_id=tenant_id, blueprint_id=blueprint.blueprint_id, version=version.version, submitted_by=actor
        )
        approve_version(
            store,
            tenant_id=tenant_id,
            blueprint_id=blueprint.blueprint_id,
            version=version.version,
            approver=actor,
            note="seeded from runtime role archetype",
        )
        refreshed = store.get_blueprint(tenant_id, blueprint.blueprint_id)
        created.append(refreshed or blueprint)
    return created


# ── Durable-by-default backend selection ──────────────────────────────────────

_BLUEPRINT_STORE: BlueprintStore | None = None


def get_blueprint_store() -> BlueprintStore:
    """Return the process blueprint store, durable by default.

    Backend precedence mirrors the other control-plane lifecycle stores via
    :mod:`agent_bom.api.durable_store`: Postgres (multi-replica, tenant RLS) when
    configured, in-memory only on an explicit ephemeral opt-out, else durable
    single-node SQLite.
    """
    global _BLUEPRINT_STORE
    if _BLUEPRINT_STORE is not None:
        return _BLUEPRINT_STORE
    from agent_bom.api.durable_store import select_backend, sqlite_path

    backend = select_backend()
    if backend == "postgres":
        from agent_bom.api.postgres_blueprint import PostgresBlueprintStore

        _BLUEPRINT_STORE = PostgresBlueprintStore()
    elif backend == "memory":
        _BLUEPRINT_STORE = InMemoryBlueprintStore()
    else:
        _BLUEPRINT_STORE = SQLiteBlueprintStore(sqlite_path())
    return _BLUEPRINT_STORE


def set_blueprint_store(store: BlueprintStore | None) -> None:
    global _BLUEPRINT_STORE
    _BLUEPRINT_STORE = store


__all__ = [
    "SEED_APPROVER",
    "STATUS_APPROVED",
    "STATUS_DRAFT",
    "STATUS_PENDING",
    "STATUS_REJECTED",
    "VALID_STATUSES",
    "Blueprint",
    "BlueprintApprovalError",
    "BlueprintComposition",
    "BlueprintPage",
    "BlueprintStore",
    "BlueprintVersion",
    "InMemoryBlueprintStore",
    "SQLiteBlueprintStore",
    "approve_version",
    "create_blueprint",
    "create_draft_version",
    "diff_versions",
    "get_blueprint_store",
    "reject_version",
    "seed_blueprints_from_archetypes",
    "set_blueprint_store",
    "submit_version_for_approval",
]
