"""Posture-event streaming primitives.

The module provides the first concrete push lane for posture events: a
tenant-scoped, retry-aware webhook outbox. It deliberately does not create
hidden egress. Operators must enqueue events for an explicit destination and
provide the delivery function that performs the HTTPS POST.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

from agent_bom.security import sanitize_error, sanitize_sensitive_payload

POSTURE_EVENT_SCHEMA_VERSION = "1"
WebhookSender = Callable[[str, dict[str, str], dict[str, Any]], Awaitable[int]]


class PostureStreamingError(RuntimeError):
    """Raised when a posture event cannot be queued or delivered safely."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _now() -> float:
    return time.time()


def _validate_tenant_id(tenant_id: str) -> str:
    cleaned = tenant_id.strip()
    if not cleaned:
        raise ValueError("tenant_id must not be empty")
    return cleaned


def _validate_destination_url(url: str, *, allow_private_networks: bool = False) -> str:
    cleaned = url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme != "https":
        raise ValueError("webhook destinations must use https")
    if not parsed.netloc:
        raise ValueError("webhook destination must include a host")
    if parsed.username or parsed.password:
        raise ValueError("webhook destination must not embed credentials")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("webhook destination must include a host")
    if not allow_private_networks:
        normalized_host = hostname.lower().strip("[]")
        if normalized_host in {"localhost", "localhost.localdomain"} or normalized_host.endswith(".localhost"):
            raise ValueError("webhook destination private networks require explicit opt-in")
        try:
            ip_addr = ipaddress.ip_address(normalized_host)
        except ValueError:
            ip_addr = None
        if ip_addr and (
            ip_addr.is_private
            or ip_addr.is_loopback
            or ip_addr.is_link_local
            or ip_addr.is_multicast
            or ip_addr.is_unspecified
            or ip_addr.is_reserved
        ):
            raise ValueError("webhook destination private networks require explicit opt-in")
    return cleaned


@dataclass(frozen=True)
class PostureEvent:
    """Redacted, tenant-scoped event queued for streaming sinks."""

    event_type: str
    tenant_id: str
    source: str
    payload: dict[str, Any]
    subject_id: str = ""
    event_id: str = ""
    created_at: float = field(default_factory=_now)
    schema_version: str = POSTURE_EVENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        clean_tenant = _validate_tenant_id(self.tenant_id)
        clean_payload = sanitize_sensitive_payload(self.payload)
        if not isinstance(clean_payload, dict):
            clean_payload = {"value": clean_payload}
        object.__setattr__(self, "tenant_id", clean_tenant)
        object.__setattr__(self, "payload", clean_payload)
        if not self.event_type.strip():
            raise ValueError("event_type must not be empty")
        if not self.source.strip():
            raise ValueError("source must not be empty")
        if not self.event_id:
            fingerprint = _canonical_json(
                {
                    "schema_version": self.schema_version,
                    "event_type": self.event_type,
                    "tenant_id": self.tenant_id,
                    "source": self.source,
                    "subject_id": self.subject_id,
                    "payload": self.payload,
                }
            )
            object.__setattr__(self, "event_id", hashlib.sha256(fingerprint.encode("utf-8")).hexdigest())

    @property
    def idempotency_key(self) -> str:
        return f"{self.tenant_id}:{self.event_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "tenant_id": self.tenant_id,
            "source": self.source,
            "subject_id": self.subject_id,
            "created_at": self.created_at,
            "payload": self.payload,
        }


@dataclass(frozen=True)
class WebhookDestination:
    """Operator-approved webhook destination."""

    destination_id: str
    tenant_id: str
    url: str
    signing_secret: str
    allow_private_networks: bool = False

    def __post_init__(self) -> None:
        if not self.destination_id.strip():
            raise ValueError("destination_id must not be empty")
        if not self.signing_secret:
            raise ValueError("signing_secret must not be empty")
        object.__setattr__(self, "tenant_id", _validate_tenant_id(self.tenant_id))
        object.__setattr__(self, "url", _validate_destination_url(self.url, allow_private_networks=self.allow_private_networks))


@dataclass(frozen=True)
class QueuedDelivery:
    """One outbox delivery attempt candidate."""

    row_id: int
    event_id: str
    tenant_id: str
    destination_id: str
    url: str
    payload: dict[str, Any]
    attempts: int
    next_attempt_at: float
    last_error: str = ""


class WebhookOutbox:
    """SQLite-backed webhook outbox with retry and idempotency metadata."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS posture_webhook_outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    destination_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL,
                    delivered_at REAL,
                    idempotency_key TEXT NOT NULL,
                    UNIQUE(tenant_id, destination_id, event_id)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_posture_webhook_outbox_due
                ON posture_webhook_outbox(status, tenant_id, next_attempt_at)
                """
            )

    def enqueue(self, event: PostureEvent, destination: WebhookDestination) -> int:
        if event.tenant_id != destination.tenant_id:
            raise ValueError("event tenant_id must match destination tenant_id")
        payload_json = _canonical_json(event.to_dict())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO posture_webhook_outbox (
                    event_id, tenant_id, destination_id, url, payload_json,
                    status, attempts, next_attempt_at, created_at, idempotency_key
                ) VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.tenant_id,
                    destination.destination_id,
                    destination.url,
                    payload_json,
                    event.created_at,
                    event.created_at,
                    event.idempotency_key,
                ),
            )
            row = conn.execute(
                """
                SELECT id FROM posture_webhook_outbox
                WHERE tenant_id = ? AND destination_id = ? AND event_id = ?
                """,
                (event.tenant_id, destination.destination_id, event.event_id),
            ).fetchone()
            return int(row["id"])

    def due(self, *, tenant_id: str, limit: int = 100, now: float | None = None) -> list[QueuedDelivery]:
        clean_tenant = _validate_tenant_id(tenant_id)
        effective_now = _now() if now is None else now
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM posture_webhook_outbox
                WHERE tenant_id = ? AND status = 'pending' AND next_attempt_at <= ?
                ORDER BY created_at ASC, id ASC
                LIMIT ?
                """,
                (clean_tenant, effective_now, limit),
            ).fetchall()
        return [
            QueuedDelivery(
                row_id=int(row["id"]),
                event_id=str(row["event_id"]),
                tenant_id=str(row["tenant_id"]),
                destination_id=str(row["destination_id"]),
                url=str(row["url"]),
                payload=json.loads(str(row["payload_json"])),
                attempts=int(row["attempts"]),
                next_attempt_at=float(row["next_attempt_at"]),
                last_error=str(row["last_error"] or ""),
            )
            for row in rows
        ]

    def mark_delivered(self, row_id: int, *, delivered_at: float | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE posture_webhook_outbox
                SET status = 'delivered', delivered_at = ?, last_error = ''
                WHERE id = ?
                """,
                (_now() if delivered_at is None else delivered_at, row_id),
            )

    def mark_failed(self, row_id: int, *, error: str, retry_at: float, max_attempts: int = 5) -> None:
        with self._connect() as conn:
            row = conn.execute("SELECT attempts FROM posture_webhook_outbox WHERE id = ?", (row_id,)).fetchone()
            attempts = int(row["attempts"]) + 1 if row else 1
            status = "dead_letter" if attempts >= max_attempts else "pending"
            conn.execute(
                """
                UPDATE posture_webhook_outbox
                SET status = ?, attempts = ?, next_attempt_at = ?, last_error = ?
                WHERE id = ?
                """,
                (status, attempts, retry_at, sanitize_error(error), row_id),
            )


def signed_webhook_headers(event: PostureEvent, destination: WebhookDestination, *, attempt: int = 1) -> dict[str, str]:
    payload_json = _canonical_json(event.to_dict())
    signature = hmac.new(destination.signing_secret.encode("utf-8"), payload_json.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "content-type": "application/json",
        "x-agent-bom-event-id": event.event_id,
        "x-agent-bom-tenant-id": event.tenant_id,
        "x-agent-bom-signature": f"sha256={signature}",
        "x-agent-bom-delivery-attempt": str(attempt),
        "idempotency-key": event.idempotency_key,
    }


async def deliver_due_webhooks(
    outbox: WebhookOutbox,
    *,
    destination: WebhookDestination,
    sender: WebhookSender,
    limit: int = 100,
    now: float | None = None,
    max_attempts: int = 5,
) -> dict[str, int]:
    """Deliver due webhook events for one tenant and explicit destination."""

    delivered = 0
    failed = 0
    dead_lettered = 0
    effective_now = _now() if now is None else now
    for item in outbox.due(tenant_id=destination.tenant_id, limit=limit, now=effective_now):
        if item.destination_id != destination.destination_id:
            continue
        event_payload = item.payload
        event = PostureEvent(
            event_type=str(event_payload["event_type"]),
            tenant_id=str(event_payload["tenant_id"]),
            source=str(event_payload["source"]),
            subject_id=str(event_payload.get("subject_id") or ""),
            payload=dict(event_payload.get("payload") or {}),
            event_id=str(event_payload["event_id"]),
            created_at=float(event_payload.get("created_at") or effective_now),
            schema_version=str(event_payload.get("schema_version") or POSTURE_EVENT_SCHEMA_VERSION),
        )
        headers = signed_webhook_headers(event, destination, attempt=item.attempts + 1)
        try:
            status = await sender(destination.url, headers, event.to_dict())
            if 200 <= status < 300:
                outbox.mark_delivered(item.row_id, delivered_at=effective_now)
                delivered += 1
            else:
                failed += 1
                retry_at = effective_now + min(3600, 2 ** max(item.attempts, 0))
                outbox.mark_failed(item.row_id, error=f"webhook returned HTTP {status}", retry_at=retry_at, max_attempts=max_attempts)
                if item.attempts + 1 >= max_attempts:
                    dead_lettered += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            retry_at = effective_now + min(3600, 2 ** max(item.attempts, 0))
            outbox.mark_failed(item.row_id, error=sanitize_error(exc), retry_at=retry_at, max_attempts=max_attempts)
            if item.attempts + 1 >= max_attempts:
                dead_lettered += 1
    return {"delivered": delivered, "failed": failed, "dead_lettered": dead_lettered}


__all__ = [
    "POSTURE_EVENT_SCHEMA_VERSION",
    "PostureEvent",
    "PostureStreamingError",
    "QueuedDelivery",
    "WebhookDestination",
    "WebhookOutbox",
    "deliver_due_webhooks",
    "signed_webhook_headers",
]
