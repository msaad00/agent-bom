"""Scheduled access-review / recertification campaigns for non-human identities.

NHI discovery (Okta/Entra) lands ``managed_identity`` nodes and
``graph/effective_permissions`` computes their ``HAS_PERMISSION`` closure, but
nothing periodically *attests* that each non-human identity still needs the
access it holds. This module adds that governance workflow on top: a reviewer
runs a recurring campaign that enumerates every discovered NHI (plus its
effective permissions) as a review item and records an ``attest`` /
``revoke_recommended`` / ``flag`` decision against each one, with due dates,
campaign status, and a signed/audited evidence trail.

It is **reference-only**. A ``revoke_recommended`` decision records the
reviewer's recommendation as evidence and emits a finding; it never executes a
revocation against Okta/Entra or any external system. No secret material is
read or stored — only identity ids, owners, scope/permission *references*, and
the decisions themselves.

Persistence follows the established store pattern (Protocol -> InMemory ->
SQLite, with a Postgres mirror selected via ``AGENT_BOM_POSTGRES_URL``). Every
decision is appended to the HMAC-chained audit log via
:func:`agent_bom.api.audit_log.log_action`, so the evidence trail is tamper
evident.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version

# Review decisions a reviewer may record against one item.
DECISION_ATTEST = "attest"
DECISION_REVOKE = "revoke_recommended"
DECISION_FLAG = "flag"
DECISION_PENDING = "pending"
_VALID_DECISIONS = frozenset({DECISION_ATTEST, DECISION_REVOKE, DECISION_FLAG})

# Campaign lifecycle states.
STATUS_OPEN = "open"
STATUS_IN_PROGRESS = "in_progress"
STATUS_COMPLETED = "completed"
STATUS_OVERDUE = "overdue"

DEFAULT_DUE_DAYS = 14


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = raw.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass
class AccessReviewItem:
    """One non-human identity under review within a campaign.

    Carries only reference metadata (identity id / name / provider / owner) and
    *references* to the effective permissions the identity holds — never secret
    material. ``decision`` starts at ``pending`` and is set exactly once a
    reviewer attests/recommends-revoke/flags it.
    """

    item_id: str
    campaign_id: str
    tenant_id: str
    subject_id: str  # discovered NHI id (e.g. provider:identity_id)
    subject_name: str
    subject_type: str  # service_account | service_principal | managed_identity | ...
    provider: str = ""
    owner: str = ""
    # Reference-only list of permission/scope labels the subject holds.
    permissions: list[str] = field(default_factory=list)
    permission_count: int = 0
    privileged: bool = False  # subject reaches an admin-equivalent permission
    decision: str = DECISION_PENDING
    decided_by: str = ""
    decided_at: str = ""
    decision_note: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AccessReviewCampaign:
    """A scheduled recertification campaign over a tenant's non-human identities."""

    campaign_id: str
    tenant_id: str
    name: str
    status: str  # open | in_progress | completed | overdue
    created_at: str
    created_by: str = ""
    due_at: str = ""
    completed_at: str = ""
    description: str = ""
    item_count: int = 0
    decided_count: int = 0

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)

    def is_overdue(self, *, at: datetime | None = None) -> bool:
        """True when the campaign is unfinished and past its due date."""
        if self.status == STATUS_COMPLETED:
            return False
        due = _parse_iso(self.due_at)
        if due is None:
            return False
        return (at or _now()) > due


class AccessReviewStore(Protocol):
    """Protocol for access-review campaign + item persistence."""

    def put_campaign(self, campaign: AccessReviewCampaign) -> None: ...

    def get_campaign(self, campaign_id: str, tenant_id: str | None = None) -> AccessReviewCampaign | None: ...

    def list_campaigns(self, tenant_id: str, *, limit: int = 200) -> list[AccessReviewCampaign]: ...

    def put_item(self, item: AccessReviewItem) -> None: ...

    def get_item(self, item_id: str, tenant_id: str | None = None) -> AccessReviewItem | None: ...

    def list_items(self, campaign_id: str, tenant_id: str | None = None, *, limit: int = 1000) -> list[AccessReviewItem]: ...


class InMemoryAccessReviewStore:
    """Dict-based in-memory access-review store."""

    def __init__(self) -> None:
        self._campaigns: dict[str, AccessReviewCampaign] = {}
        self._items: dict[str, AccessReviewItem] = {}
        self._lock = threading.Lock()

    def put_campaign(self, campaign: AccessReviewCampaign) -> None:
        with self._lock:
            self._campaigns[campaign.campaign_id] = campaign

    def get_campaign(self, campaign_id: str, tenant_id: str | None = None) -> AccessReviewCampaign | None:
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
        if campaign is None:
            return None
        if tenant_id is not None and campaign.tenant_id != tenant_id:
            return None
        return campaign

    def list_campaigns(self, tenant_id: str, *, limit: int = 200) -> list[AccessReviewCampaign]:
        with self._lock:
            rows = [c for c in self._campaigns.values() if c.tenant_id == tenant_id]
        return sorted(rows, key=lambda c: c.created_at, reverse=True)[:limit]

    def put_item(self, item: AccessReviewItem) -> None:
        with self._lock:
            self._items[item.item_id] = item

    def get_item(self, item_id: str, tenant_id: str | None = None) -> AccessReviewItem | None:
        with self._lock:
            item = self._items.get(item_id)
        if item is None:
            return None
        if tenant_id is not None and item.tenant_id != tenant_id:
            return None
        return item

    def list_items(self, campaign_id: str, tenant_id: str | None = None, *, limit: int = 1000) -> list[AccessReviewItem]:
        with self._lock:
            rows = [i for i in self._items.values() if i.campaign_id == campaign_id]
        if tenant_id is not None:
            rows = [i for i in rows if i.tenant_id == tenant_id]
        return sorted(rows, key=lambda i: i.subject_name.lower())[:limit]


class SQLiteAccessReviewStore:
    """SQLite-backed persistent access-review store."""

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
        ensure_sqlite_schema_version(self._conn, "access_reviews")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_review_campaigns (
                campaign_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                due_at TEXT NOT NULL DEFAULT '',
                data TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_access_review_campaigns_tenant ON access_review_campaigns(tenant_id, created_at)"
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_review_items (
                item_id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_access_review_items_campaign ON access_review_items(campaign_id, tenant_id)")
        self._conn.commit()

    def put_campaign(self, campaign: AccessReviewCampaign) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO access_review_campaigns "
            "(campaign_id, tenant_id, status, created_at, due_at, data) VALUES (?, ?, ?, ?, ?, ?)",
            (
                campaign.campaign_id,
                campaign.tenant_id,
                campaign.status,
                campaign.created_at,
                campaign.due_at,
                json.dumps(asdict(campaign), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get_campaign(self, campaign_id: str, tenant_id: str | None = None) -> AccessReviewCampaign | None:
        if tenant_id is None:
            row = self._conn.execute("SELECT data FROM access_review_campaigns WHERE campaign_id = ?", (campaign_id,)).fetchone()
        else:
            row = self._conn.execute(
                "SELECT data FROM access_review_campaigns WHERE campaign_id = ? AND tenant_id = ?",
                (campaign_id, tenant_id),
            ).fetchone()
        return AccessReviewCampaign(**json.loads(row[0])) if row else None

    def list_campaigns(self, tenant_id: str, *, limit: int = 200) -> list[AccessReviewCampaign]:
        rows = self._conn.execute(
            "SELECT data FROM access_review_campaigns WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
            (tenant_id, limit),
        ).fetchall()
        return [AccessReviewCampaign(**json.loads(r[0])) for r in rows]

    def put_item(self, item: AccessReviewItem) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO access_review_items "
            "(item_id, campaign_id, tenant_id, subject_id, decision, data) VALUES (?, ?, ?, ?, ?, ?)",
            (
                item.item_id,
                item.campaign_id,
                item.tenant_id,
                item.subject_id,
                item.decision,
                json.dumps(asdict(item), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get_item(self, item_id: str, tenant_id: str | None = None) -> AccessReviewItem | None:
        if tenant_id is None:
            row = self._conn.execute("SELECT data FROM access_review_items WHERE item_id = ?", (item_id,)).fetchone()
        else:
            row = self._conn.execute(
                "SELECT data FROM access_review_items WHERE item_id = ? AND tenant_id = ?",
                (item_id, tenant_id),
            ).fetchone()
        return AccessReviewItem(**json.loads(row[0])) if row else None

    def list_items(self, campaign_id: str, tenant_id: str | None = None, *, limit: int = 1000) -> list[AccessReviewItem]:
        if tenant_id is None:
            rows = self._conn.execute(
                "SELECT data FROM access_review_items WHERE campaign_id = ? ORDER BY item_id LIMIT ?",
                (campaign_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM access_review_items WHERE campaign_id = ? AND tenant_id = ? ORDER BY item_id LIMIT ?",
                (campaign_id, tenant_id, limit),
            ).fetchall()
        items = [AccessReviewItem(**json.loads(r[0])) for r in rows]
        return sorted(items, key=lambda i: i.subject_name.lower())


# ── Subject extraction ────────────────────────────────────────────────────────


_ADMIN_KEYWORDS = ("admin", "owner", "root", "fullaccess", "*:*", "*")


def _subject_records_from_discovery(discovered: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize discovered-NHI dicts into review-subject records (reference-only).

    Accepts the payload shape ``merge_discovery_results`` /
    ``serialize_discovery_result`` emit (``identity_id`` / ``name`` / ``owner`` /
    ``identity_type`` / ``provider`` / ``scopes``). Never reads secret fields.
    """
    subjects: list[dict[str, Any]] = []
    for raw in discovered:
        if not isinstance(raw, dict):
            continue
        identity_id = str(raw.get("identity_id") or raw.get("id") or "").strip()
        if not identity_id:
            continue
        provider = str(raw.get("provider") or "").strip()
        scopes_raw = raw.get("scopes")
        scopes = [str(s).strip() for s in scopes_raw if str(s).strip()] if isinstance(scopes_raw, list) else []
        privileged = any(any(kw in scope.lower() for kw in _ADMIN_KEYWORDS) for scope in scopes)
        subjects.append(
            {
                "subject_id": f"{provider}:{identity_id}" if provider else identity_id,
                "subject_name": str(raw.get("name") or identity_id),
                "subject_type": str(raw.get("identity_type") or "service_account"),
                "provider": provider,
                "owner": str(raw.get("owner") or ""),
                "permissions": scopes[:200],
                "permission_count": len(scopes),
                "privileged": privileged,
            }
        )
    return subjects


# ── Campaign lifecycle ─────────────────────────────────────────────────────────


def create_campaign(
    store: AccessReviewStore,
    *,
    tenant_id: str,
    name: str,
    subjects: list[dict[str, Any]],
    created_by: str = "",
    due_days: int = DEFAULT_DUE_DAYS,
    description: str = "",
    now: datetime | None = None,
) -> tuple[AccessReviewCampaign, list[AccessReviewItem]]:
    """Create a campaign and enumerate one review item per subject.

    ``subjects`` are reference-only records (``subject_id`` / ``subject_name`` /
    ``permissions`` …). Returns the persisted campaign and its items.
    """
    moment = now or _now()
    due_days = max(1, int(due_days))
    campaign = AccessReviewCampaign(
        campaign_id=f"arc_{secrets.token_hex(8)}",
        tenant_id=tenant_id,
        name=name[:200],
        status=STATUS_OPEN,
        created_at=_iso(moment),
        created_by=created_by[:120],
        due_at=_iso(moment + timedelta(days=due_days)),
        description=description[:1000],
        item_count=len(subjects),
        decided_count=0,
    )
    items: list[AccessReviewItem] = []
    for subject in subjects:
        item = AccessReviewItem(
            item_id=f"ari_{secrets.token_hex(8)}",
            campaign_id=campaign.campaign_id,
            tenant_id=tenant_id,
            subject_id=str(subject.get("subject_id") or "")[:200],
            subject_name=str(subject.get("subject_name") or subject.get("subject_id") or "")[:200],
            subject_type=str(subject.get("subject_type") or "service_account")[:60],
            provider=str(subject.get("provider") or "")[:60],
            owner=str(subject.get("owner") or "")[:200],
            permissions=[str(p)[:200] for p in (subject.get("permissions") or [])][:200],
            permission_count=int(subject.get("permission_count") or len(subject.get("permissions") or [])),
            privileged=bool(subject.get("privileged")),
        )
        items.append(item)

    store.put_campaign(campaign)
    for item in items:
        store.put_item(item)
    return campaign, items


def create_campaign_from_discovery(
    store: AccessReviewStore,
    *,
    tenant_id: str,
    name: str,
    discovered: list[dict[str, Any]],
    created_by: str = "",
    due_days: int = DEFAULT_DUE_DAYS,
    description: str = "",
    now: datetime | None = None,
) -> tuple[AccessReviewCampaign, list[AccessReviewItem]]:
    """Create a campaign whose scope is a set of discovered non-human identities."""
    subjects = _subject_records_from_discovery(discovered)
    return create_campaign(
        store,
        tenant_id=tenant_id,
        name=name,
        subjects=subjects,
        created_by=created_by,
        due_days=due_days,
        description=description,
        now=now,
    )


def _recount(store: AccessReviewStore, campaign: AccessReviewCampaign, *, now: datetime | None = None) -> AccessReviewCampaign:
    """Recompute item/decided counts and roll the campaign status forward."""
    items = store.list_items(campaign.campaign_id, campaign.tenant_id)
    decided = [i for i in items if i.decision != DECISION_PENDING]
    campaign.item_count = len(items)
    campaign.decided_count = len(decided)
    if campaign.status != STATUS_COMPLETED:
        if items and len(decided) == len(items):
            campaign.status = STATUS_COMPLETED
            campaign.completed_at = _iso(now or _now())
        elif decided:
            campaign.status = STATUS_IN_PROGRESS
        else:
            campaign.status = STATUS_OPEN
        if campaign.status != STATUS_COMPLETED and campaign.is_overdue(at=now):
            campaign.status = STATUS_OVERDUE
    return campaign


def record_decision(
    store: AccessReviewStore,
    *,
    tenant_id: str,
    item_id: str,
    decision: str,
    decided_by: str = "",
    note: str = "",
    now: datetime | None = None,
) -> tuple[AccessReviewItem, AccessReviewCampaign] | None:
    """Record a reviewer decision on one item and roll the campaign status forward.

    Returns ``(item, campaign)`` on success, or ``None`` when the item is not
    found in ``tenant_id``. Raises ``ValueError`` for an invalid decision.
    """
    if decision not in _VALID_DECISIONS:
        raise ValueError(f"decision must be one of {sorted(_VALID_DECISIONS)}")
    item = store.get_item(item_id, tenant_id)
    if item is None:
        return None
    campaign = store.get_campaign(item.campaign_id, tenant_id)
    if campaign is None:
        return None
    moment = now or _now()
    item.decision = decision
    item.decided_by = decided_by[:120]
    item.decided_at = _iso(moment)
    item.decision_note = note[:1000]
    store.put_item(item)
    campaign = _recount(store, campaign, now=moment)
    store.put_campaign(campaign)
    return item, campaign


def refresh_campaign_status(
    store: AccessReviewStore,
    *,
    tenant_id: str,
    campaign_id: str,
    now: datetime | None = None,
) -> AccessReviewCampaign | None:
    """Recompute and persist a campaign's status (e.g. to surface overdue)."""
    campaign = store.get_campaign(campaign_id, tenant_id)
    if campaign is None:
        return None
    campaign = _recount(store, campaign, now=now)
    store.put_campaign(campaign)
    return campaign


def export_evidence(
    store: AccessReviewStore,
    *,
    tenant_id: str,
    campaign_id: str,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Return a non-secret, signable evidence bundle for one campaign.

    Includes the campaign, every item + decision, and rolled-up decision counts.
    Suitable for attaching to a compliance evidence trail. No secret values.
    """
    campaign = refresh_campaign_status(store, tenant_id=tenant_id, campaign_id=campaign_id, now=now)
    if campaign is None:
        return None
    items = store.list_items(campaign_id, tenant_id)
    counts: dict[str, int] = {DECISION_PENDING: 0, DECISION_ATTEST: 0, DECISION_REVOKE: 0, DECISION_FLAG: 0}
    for item in items:
        counts[item.decision] = counts.get(item.decision, 0) + 1
    return {
        "schema_version": "identity.access_review.v1",
        "secret_values_included": False,
        "generated_at": _iso(now or _now()),
        "tenant_id": tenant_id,
        "campaign": campaign.to_public_dict(),
        "decision_counts": counts,
        "revoke_recommended": [i.subject_name or i.subject_id for i in items if i.decision == DECISION_REVOKE],
        "flagged": [i.subject_name or i.subject_id for i in items if i.decision == DECISION_FLAG],
        "items": [i.to_public_dict() for i in items],
    }


# ── Module-level singleton ──────────────────────────────────────────────────────

_ACCESS_REVIEW_STORE: AccessReviewStore | None = None


def get_access_review_store() -> AccessReviewStore:
    global _ACCESS_REVIEW_STORE
    if _ACCESS_REVIEW_STORE is not None:
        return _ACCESS_REVIEW_STORE
    if os.environ.get("AGENT_BOM_POSTGRES_URL"):
        from agent_bom.api.postgres_access_review import PostgresAccessReviewStore

        _ACCESS_REVIEW_STORE = PostgresAccessReviewStore()
    elif os.environ.get("AGENT_BOM_DB"):
        _ACCESS_REVIEW_STORE = SQLiteAccessReviewStore(os.environ["AGENT_BOM_DB"])
    else:
        _ACCESS_REVIEW_STORE = InMemoryAccessReviewStore()
    return _ACCESS_REVIEW_STORE


def set_access_review_store(store: AccessReviewStore | None) -> None:
    global _ACCESS_REVIEW_STORE
    _ACCESS_REVIEW_STORE = store


__all__ = [
    "DECISION_ATTEST",
    "DECISION_FLAG",
    "DECISION_PENDING",
    "DECISION_REVOKE",
    "STATUS_COMPLETED",
    "STATUS_IN_PROGRESS",
    "STATUS_OPEN",
    "STATUS_OVERDUE",
    "AccessReviewCampaign",
    "AccessReviewItem",
    "AccessReviewStore",
    "InMemoryAccessReviewStore",
    "SQLiteAccessReviewStore",
    "create_campaign",
    "create_campaign_from_discovery",
    "export_evidence",
    "get_access_review_store",
    "record_decision",
    "refresh_campaign_status",
    "set_access_review_store",
]
