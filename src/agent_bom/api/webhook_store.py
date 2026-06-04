"""Governance webhook subscriptions and event dispatch.

Operators register outbound webhook destinations (URL + signing secret + an
event-type filter) for agent-identity governance events — budget enforcement,
identity lifecycle, JIT grants, conditional-access denials, and behavioral
drift. Matching events are enqueued into the durable, HMAC-signed, retry-aware
``WebhookOutbox`` (``posture_streaming``); the existing delivery worker ships
them. Signing secrets are stored as-is (needed to sign at delivery) but never
returned after creation. Destination URLs are SSRF-validated at registration.
"""

from __future__ import annotations

import builtins
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version

logger = logging.getLogger(__name__)

# Canonical governance event types a subscription may filter on.
GOVERNANCE_EVENT_TYPES = (
    "budget.exceeded",
    "identity.issued",
    "identity.rotated",
    "identity.revoked",
    "identity.jit_granted",
    "identity.jit_revoked",
    "identity.conditional_access_blocked",
    "drift.detected",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@dataclass
class WebhookSubscription:
    """An operator-registered outbound webhook destination."""

    subscription_id: str
    tenant_id: str
    url: str
    signing_secret: str
    event_types: list[str] = field(default_factory=list)  # empty = all governance events
    status: str = "active"  # active | disabled
    description: str = ""
    created_at: str = ""
    updated_at: str = ""
    allow_private_networks: bool = False

    def wants(self, event_type: str) -> bool:
        """True when this subscription should receive ``event_type``."""
        if self.status != "active":
            return False
        if not self.event_types:
            return True
        return event_type in self.event_types or any(
            event_type.startswith(prefix[:-1]) for prefix in self.event_types if prefix.endswith("*")
        )

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize without the signing secret; expose only a fingerprint."""
        d = asdict(self)
        secret = d.pop("signing_secret", "")
        d["secret_fingerprint"] = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12] if secret else ""
        return d


class WebhookSubscriptionStore(Protocol):
    def put(self, subscription: WebhookSubscription) -> None: ...

    def get(self, subscription_id: str) -> WebhookSubscription | None: ...

    def list(self, tenant_id: str, *, include_disabled: bool = False, limit: int = 200) -> builtins.list[WebhookSubscription]: ...

    def delete(self, subscription_id: str) -> bool: ...

    def matching(self, tenant_id: str, event_type: str) -> builtins.list[WebhookSubscription]: ...


class InMemoryWebhookSubscriptionStore:
    def __init__(self) -> None:
        self._by_id: dict[str, WebhookSubscription] = {}
        self._lock = threading.Lock()

    def put(self, subscription: WebhookSubscription) -> None:
        with self._lock:
            self._by_id[subscription.subscription_id] = subscription

    def get(self, subscription_id: str) -> WebhookSubscription | None:
        with self._lock:
            return self._by_id.get(subscription_id)

    def list(self, tenant_id: str, *, include_disabled: bool = False, limit: int = 200) -> builtins.list[WebhookSubscription]:
        with self._lock:
            rows = [s for s in self._by_id.values() if s.tenant_id == tenant_id and (include_disabled or s.status == "active")]
            return sorted(rows, key=lambda s: s.created_at, reverse=True)[:limit]

    def delete(self, subscription_id: str) -> bool:
        with self._lock:
            return self._by_id.pop(subscription_id, None) is not None

    def matching(self, tenant_id: str, event_type: str) -> builtins.list[WebhookSubscription]:
        with self._lock:
            return [s for s in self._by_id.values() if s.tenant_id == tenant_id and s.wants(event_type)]


class SQLiteWebhookSubscriptionStore:
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
        ensure_sqlite_schema_version(self._conn, "webhook_subscriptions")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS webhook_subscriptions (
                subscription_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_webhook_subs_tenant ON webhook_subscriptions(tenant_id, status)")
        self._conn.commit()

    def put(self, subscription: WebhookSubscription) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO webhook_subscriptions (subscription_id, tenant_id, status, created_at, data) VALUES (?, ?, ?, ?, ?)",
            (
                subscription.subscription_id,
                subscription.tenant_id,
                subscription.status,
                subscription.created_at,
                json.dumps(asdict(subscription), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get(self, subscription_id: str) -> WebhookSubscription | None:
        row = self._conn.execute("SELECT data FROM webhook_subscriptions WHERE subscription_id = ?", (subscription_id,)).fetchone()
        return WebhookSubscription(**json.loads(row[0])) if row else None

    def list(self, tenant_id: str, *, include_disabled: bool = False, limit: int = 200) -> builtins.list[WebhookSubscription]:
        if include_disabled:
            rows = self._conn.execute(
                "SELECT data FROM webhook_subscriptions WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?", (tenant_id, limit)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM webhook_subscriptions WHERE tenant_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [WebhookSubscription(**json.loads(r[0])) for r in rows]

    def delete(self, subscription_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM webhook_subscriptions WHERE subscription_id = ?", (subscription_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def matching(self, tenant_id: str, event_type: str) -> builtins.list[WebhookSubscription]:
        return [s for s in self.list(tenant_id, include_disabled=False, limit=500) if s.wants(event_type)]


# ── Lifecycle ────────────────────────────────────────────────────────────────


def create_subscription(
    store: WebhookSubscriptionStore,
    *,
    tenant_id: str,
    url: str,
    event_types: list[str] | None = None,
    description: str = "",
    signing_secret: str = "",
    allow_private_networks: bool = False,
) -> WebhookSubscription:
    """Register a webhook destination. Generates a signing secret if none given.

    Raises ValueError (propagated as 400 by the route) when the URL fails the
    SSRF guard, surfaced via ``WebhookDestination`` validation.
    """
    from agent_bom.posture_streaming import WebhookDestination

    secret = signing_secret.strip() or f"whsec_{secrets.token_urlsafe(32)}"
    # Validate URL + secret through the canonical destination guard (SSRF, scheme).
    WebhookDestination(
        destination_id="validate",
        tenant_id=tenant_id,
        url=url,
        signing_secret=secret,
        allow_private_networks=allow_private_networks,
    )
    now = _iso(_now())
    subscription = WebhookSubscription(
        subscription_id=f"whsub_{secrets.token_hex(8)}",
        tenant_id=tenant_id,
        url=url,
        signing_secret=secret,
        event_types=list(event_types or []),
        status="active",
        description=description[:500],
        created_at=now,
        updated_at=now,
        allow_private_networks=allow_private_networks,
    )
    store.put(subscription)
    return subscription


def set_subscription_status(store: WebhookSubscriptionStore, subscription_id: str, *, status: str) -> WebhookSubscription | None:
    if status not in ("active", "disabled"):
        raise ValueError("status must be 'active' or 'disabled'")
    subscription = store.get(subscription_id)
    if subscription is None:
        return None
    subscription.status = status
    subscription.updated_at = _iso(_now())
    store.put(subscription)
    return subscription


def emit_governance_event(
    *,
    event_type: str,
    tenant_id: str,
    source: str,
    payload: dict[str, Any],
    subject_id: str = "",
    store: WebhookSubscriptionStore | None = None,
    outbox: Any = None,
) -> int:
    """Enqueue ``event_type`` to every matching subscription. Returns the count
    enqueued. Best-effort: never raises into the caller's request path.
    """
    try:
        sub_store = store or get_webhook_subscription_store()
        subs = sub_store.matching(tenant_id, event_type)
        if not subs:
            return 0
        from agent_bom.posture_streaming import PostureEvent, WebhookDestination, default_webhook_outbox

        target_outbox = outbox or default_webhook_outbox()
        event = PostureEvent(
            event_type=event_type,
            tenant_id=tenant_id,
            source=source,
            payload=payload,
            subject_id=subject_id,
        )
        enqueued = 0
        for sub in subs:
            try:
                destination = WebhookDestination(
                    destination_id=sub.subscription_id,
                    tenant_id=sub.tenant_id,
                    url=sub.url,
                    signing_secret=sub.signing_secret,
                    allow_private_networks=sub.allow_private_networks,
                )
                target_outbox.enqueue(event, destination)
                enqueued += 1
            except Exception:  # noqa: BLE001
                logger.warning("webhook enqueue failed for subscription %s", sub.subscription_id, exc_info=True)
        return enqueued
    except Exception:  # noqa: BLE001
        logger.warning("governance webhook emit failed for %s", event_type, exc_info=True)
        return 0


_WEBHOOK_SUBSCRIPTION_STORE: WebhookSubscriptionStore | None = None


def get_webhook_subscription_store() -> WebhookSubscriptionStore:
    global _WEBHOOK_SUBSCRIPTION_STORE
    if _WEBHOOK_SUBSCRIPTION_STORE is not None:
        return _WEBHOOK_SUBSCRIPTION_STORE
    if os.environ.get("AGENT_BOM_DB"):
        _WEBHOOK_SUBSCRIPTION_STORE = SQLiteWebhookSubscriptionStore(os.environ["AGENT_BOM_DB"])
    else:
        _WEBHOOK_SUBSCRIPTION_STORE = InMemoryWebhookSubscriptionStore()
    return _WEBHOOK_SUBSCRIPTION_STORE


def set_webhook_subscription_store(store: WebhookSubscriptionStore | None) -> None:
    global _WEBHOOK_SUBSCRIPTION_STORE
    _WEBHOOK_SUBSCRIPTION_STORE = store
