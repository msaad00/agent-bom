"""Hardened outbound delivery foundation.

Every outbound integration — governance webhooks, SIEM/OCSF export, exporters
(siem, otel, slack, jira, vanta, drata, customer_archive) — should ride this
single ``DeliveryClient`` so the platform has one place that owns:

  * Retries with exponential backoff + jitter, bounded attempts then a durable
    **dead-letter** record (never blocks the caller).
  * An **idempotency key** per delivery so a retry — or a duplicate enqueue of
    the same payload to the same destination — is never double-sent.
  * Optional **HMAC request signing** + per-destination auth (header / token /
    bearer).
  * A **circuit breaker** per destination (opens on repeated failures,
    half-opens a single probe after a cooldown).
  * A queryable **delivery/audit log** — every attempt is recorded with a
    redacted payload preview; secret values are never persisted.

The design deliberately mirrors the ``posture_streaming`` webhook outbox
(durable SQLite, deterministic idempotency hash, sanitized errors) and the
shared ``http_client`` retry loop, consolidating them behind one API. It is
*graceful by construction*: a destination failure degrades to a dead-letter
record plus an actionable warning and the caller continues.

All time is taken from an injectable ``now`` callable so retry math and the
audit log are deterministic under test.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import random
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from agent_bom.security import sanitize_error, sanitize_sensitive_payload

logger = logging.getLogger(__name__)

# Statuses that should NOT consume a retry attempt as a transport failure but
# still represent a non-2xx result. Auth/permanent client errors are not
# retried (retrying a 401/403 just burns the budget); they go straight to
# dead-letter so an operator can fix the credential and requeue.
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
# 4xx (other than the retryable transient ones above) = permanent; do not retry.
_PERMANENT_4XX_FLOOR = 400
WEBHOOK_SIGNATURE_TIMESTAMP_HEADER = "x-agent-bom-timestamp"
WEBHOOK_SIGNATURE_FRESHNESS_SECONDS = 300


class DeliveryError(RuntimeError):
    """Raised only for programmer errors (bad config); never for a failed send."""


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


# ── Time injection ───────────────────────────────────────────────────────────


def _wall_now() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


# ── Destination ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Destination:
    """An operator-approved outbound delivery target.

    ``kind`` is a free-form label (``webhook``, ``siem``, ``otel``, ``slack`` …)
    used only for the audit log / circuit-breaker scoping. Auth material is held
    here to sign/authenticate at delivery time but is NEVER written to the
    delivery log (only a fingerprint is).
    """

    destination_id: str
    url: str
    kind: str = "webhook"
    signing_secret: str = ""
    auth_scheme: str = ""  # "", "bearer", "token", "header"
    auth_token: str = ""
    auth_header: str = "Authorization"
    headers: dict[str, str] = field(default_factory=dict)
    allow_private_networks: bool = False
    timeout: float = 30.0

    def __post_init__(self) -> None:
        if not self.destination_id.strip():
            raise DeliveryError("destination_id must not be empty")
        if not self.url.strip():
            raise DeliveryError("url must not be empty")
        scheme = self.auth_scheme.strip().lower()
        if scheme and scheme not in {"bearer", "token", "header"}:
            raise DeliveryError(f"unsupported auth_scheme: {self.auth_scheme!r}")

    @property
    def secret_fingerprint(self) -> str:
        material = f"{self.signing_secret}\x00{self.auth_token}"
        if not self.signing_secret and not self.auth_token:
            return ""
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


# ── Delivery (the unit of work) ──────────────────────────────────────────────


@dataclass(frozen=True)
class Delivery:
    """One logical payload bound for one destination.

    ``idempotency_key`` defaults to a deterministic content hash so the same
    payload to the same destination collapses to a single send. Callers with
    their own stable key (an event id, a finding id) should pass it explicitly.
    """

    destination_id: str
    payload: dict[str, Any]
    event_type: str = "delivery"
    idempotency_key: str = ""
    created_at: float = field(default_factory=_wall_now)

    def __post_init__(self) -> None:
        clean = sanitize_sensitive_payload(self.payload)
        if not isinstance(clean, dict):
            clean = {"value": clean}
        object.__setattr__(self, "payload", clean)
        if not self.idempotency_key:
            fingerprint = _canonical_json(
                {
                    "destination_id": self.destination_id,
                    "event_type": self.event_type,
                    "payload": self.payload,
                }
            )
            object.__setattr__(
                self,
                "idempotency_key",
                hashlib.sha256(fingerprint.encode("utf-8")).hexdigest(),
            )


@dataclass(frozen=True)
class DeliveryResult:
    """Outcome returned to the caller — never an exception for a failed send."""

    idempotency_key: str
    destination_id: str
    status: str  # "delivered" | "dead_letter" | "deduplicated" | "circuit_open"
    http_status: int | None = None
    attempts: int = 0
    delivered: bool = False
    warning: str = ""

    @property
    def ok(self) -> bool:
        return self.delivered


# ── Sender protocol ──────────────────────────────────────────────────────────
# A sender performs ONE HTTP attempt and returns (http_status, error_text).
# Injecting it keeps DeliveryClient transport-agnostic and trivially testable.

Sender = Callable[[str, dict[str, str], bytes, float], "SendOutcome"]


@dataclass(frozen=True)
class SendOutcome:
    http_status: int | None
    error: str = ""

    @property
    def is_success(self) -> bool:
        return self.http_status is not None and 200 <= self.http_status < 300


def http_sender(url: str, headers: dict[str, str], body: bytes, timeout: float) -> SendOutcome:
    """Default sender: one POST through the shared resilient sync client.

    The shared client already validates the URL (SSRF) and does connection-level
    retries; the application-level retry/backoff lives in ``DeliveryClient`` so
    every destination shares one policy.
    """
    from agent_bom.http_client import create_sync_client
    from agent_bom.security import SecurityError, validate_url

    allow_private = os.environ.get("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        validate_url(url, allowed_schemes=("https", "http") if allow_private else ("https",), allow_private=allow_private)
    except SecurityError as exc:
        return SendOutcome(http_status=None, error=f"url rejected by outbound policy: {sanitize_error(exc)}")
    try:
        with create_sync_client(timeout=timeout) as client:
            resp = client.request("POST", url, content=body, headers=headers)
        return SendOutcome(http_status=resp.status_code)
    except Exception as exc:  # noqa: BLE001 — any transport error becomes a retryable failure
        return SendOutcome(http_status=None, error=sanitize_error(exc))


# ── Audit / circuit store ────────────────────────────────────────────────────


@dataclass(frozen=True)
class AttemptRecord:
    row_id: int
    idempotency_key: str
    destination_id: str
    kind: str
    attempt: int
    status: str
    http_status: int | None
    payload_preview: str
    error: str
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "row_id": self.row_id,
            "idempotency_key": self.idempotency_key,
            "destination_id": self.destination_id,
            "kind": self.kind,
            "attempt": self.attempt,
            "status": self.status,
            "http_status": self.http_status,
            "payload_preview": self.payload_preview,
            "error": self.error,
            "created_at": self.created_at,
            "created_at_iso": _iso(self.created_at),
        }


class DeliveryStore:
    """SQLite-backed delivery audit log + idempotency ledger + breaker state.

    Tables:
      * ``delivery_log``       — every attempt (redacted preview, no secrets).
      * ``delivery_ledger``    — terminal outcome per idempotency key (dedupe).
      * ``delivery_breaker``   — per-destination circuit-breaker state.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS delivery_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    idempotency_key TEXT NOT NULL,
                    destination_id TEXT NOT NULL,
                    kind TEXT NOT NULL DEFAULT 'webhook',
                    attempt INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    http_status INTEGER,
                    payload_preview TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_delivery_log_key ON delivery_log(idempotency_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_delivery_log_dest ON delivery_log(destination_id, created_at)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS delivery_ledger (
                    idempotency_key TEXT NOT NULL,
                    destination_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    http_status INTEGER,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (destination_id, idempotency_key)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS delivery_breaker (
                    destination_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL DEFAULT 'closed',
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    opened_at REAL,
                    updated_at REAL NOT NULL
                )
                """
            )

    # — idempotency ledger —

    def terminal_status(self, destination_id: str, idempotency_key: str) -> str | None:
        """Return the terminal status (``delivered``/``dead_letter``) if this
        key already reached a terminal state for this destination, else None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM delivery_ledger WHERE destination_id = ? AND idempotency_key = ?",
                (destination_id, idempotency_key),
            ).fetchone()
        return str(row["status"]) if row else None

    def record_terminal(
        self, *, destination_id: str, idempotency_key: str, status: str, http_status: int | None, attempts: int, now: float
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO delivery_ledger (idempotency_key, destination_id, status, http_status, attempts, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(destination_id, idempotency_key)
                DO UPDATE SET
                    status=excluded.status,
                    http_status=excluded.http_status,
                    attempts=excluded.attempts,
                    updated_at=excluded.updated_at
                """,
                (idempotency_key, destination_id, status, http_status, attempts, now, now),
            )

    # — attempt log —

    def log_attempt(
        self,
        *,
        idempotency_key: str,
        destination_id: str,
        kind: str,
        attempt: int,
        status: str,
        http_status: int | None,
        payload_preview: str,
        error: str,
        now: float,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO delivery_log
                    (idempotency_key, destination_id, kind, attempt, status, http_status, payload_preview, error, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    idempotency_key,
                    destination_id,
                    kind,
                    attempt,
                    status,
                    http_status,
                    payload_preview,
                    sanitize_error(error) if error else "",
                    now,
                ),
            )

    def attempts(self, *, destination_id: str | None = None, idempotency_key: str | None = None, limit: int = 100) -> list[AttemptRecord]:
        bounded = max(1, min(int(limit), 1000))
        # Fully static queries selected by which filters are present — no string
        # interpolation, so there is no SQL-injection surface; all values bound.
        params: list[Any] = []
        if destination_id and idempotency_key:
            query = "SELECT * FROM delivery_log WHERE destination_id = ? AND idempotency_key = ? ORDER BY id DESC LIMIT ?"
            params = [destination_id, idempotency_key, bounded]
        elif destination_id:
            query = "SELECT * FROM delivery_log WHERE destination_id = ? ORDER BY id DESC LIMIT ?"
            params = [destination_id, bounded]
        elif idempotency_key:
            query = "SELECT * FROM delivery_log WHERE idempotency_key = ? ORDER BY id DESC LIMIT ?"
            params = [idempotency_key, bounded]
        else:
            query = "SELECT * FROM delivery_log ORDER BY id DESC LIMIT ?"
            params = [bounded]
        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [
            AttemptRecord(
                row_id=int(r["id"]),
                idempotency_key=str(r["idempotency_key"]),
                destination_id=str(r["destination_id"]),
                kind=str(r["kind"]),
                attempt=int(r["attempt"]),
                status=str(r["status"]),
                http_status=int(r["http_status"]) if r["http_status"] is not None else None,
                payload_preview=str(r["payload_preview"] or ""),
                error=str(r["error"] or ""),
                created_at=float(r["created_at"]),
            )
            for r in rows
        ]

    def dead_letters(self, *, destination_id: str | None = None, limit: int = 100) -> list[AttemptRecord]:
        records = self.attempts(destination_id=destination_id, limit=1000)
        out = [r for r in records if r.status == "dead_letter"]
        return out[: max(1, min(int(limit), 1000))]

    # — circuit breaker —

    def breaker_state(self, destination_id: str) -> tuple[CircuitState, int, float | None]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state, consecutive_failures, opened_at FROM delivery_breaker WHERE destination_id = ?",
                (destination_id,),
            ).fetchone()
        if not row:
            return CircuitState.CLOSED, 0, None
        return (
            CircuitState(str(row["state"])),
            int(row["consecutive_failures"]),
            (float(row["opened_at"]) if row["opened_at"] is not None else None),
        )

    def set_breaker(
        self, destination_id: str, *, state: CircuitState, consecutive_failures: int, opened_at: float | None, now: float
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO delivery_breaker (destination_id, state, consecutive_failures, opened_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(destination_id)
                DO UPDATE SET
                    state=excluded.state,
                    consecutive_failures=excluded.consecutive_failures,
                    opened_at=excluded.opened_at,
                    updated_at=excluded.updated_at
                """,
                (destination_id, state.value, consecutive_failures, opened_at, now),
            )


def default_delivery_store_path() -> Path:
    configured = os.environ.get("AGENT_BOM_DELIVERY_DB", "").strip()
    if configured:
        return Path(configured).expanduser()
    shared = os.environ.get("AGENT_BOM_DB", "").strip()
    if shared:
        return Path(shared).expanduser()
    return Path.home() / ".agent-bom" / "db" / "delivery.db"


# ── Payload preview (redacted) ───────────────────────────────────────────────

_PREVIEW_MAX = 512


def redacted_preview(payload: dict[str, Any]) -> str:
    """A short, secret-free preview of a payload for the audit log."""
    safe = sanitize_sensitive_payload(payload)
    text = _canonical_json(safe)
    if len(text) > _PREVIEW_MAX:
        return text[:_PREVIEW_MAX] + "…"
    return text


# ── DeliveryClient ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 4
    initial_backoff: float = 1.0
    max_backoff: float = 30.0
    backoff_multiplier: float = 2.0
    jitter_ratio: float = 0.1


@dataclass(frozen=True)
class BreakerPolicy:
    failure_threshold: int = 5  # consecutive failures before opening
    cooldown: float = 60.0  # seconds before a half-open probe


class DeliveryClient:
    """One hardened outbound delivery path shared by every exporter/webhook."""

    def __init__(
        self,
        store: DeliveryStore | None = None,
        *,
        sender: Sender = http_sender,
        retry: RetryPolicy | None = None,
        breaker: BreakerPolicy | None = None,
        now: Callable[[], float] = _wall_now,
        sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
    ):
        self.store = store or DeliveryStore(default_delivery_store_path())
        self.sender = sender
        self.retry = retry or RetryPolicy()
        self.breaker = breaker or BreakerPolicy()
        self._now = now
        self._sleep = sleep
        self._rng = rng

    # — header construction —

    def _build_headers(self, destination: Destination, delivery: Delivery, body: bytes, attempt: int) -> dict[str, str]:
        headers: dict[str, str] = {
            "content-type": "application/json",
            "idempotency-key": delivery.idempotency_key,
            "x-agent-bom-event-type": delivery.event_type,
            "x-agent-bom-delivery-attempt": str(attempt),
        }
        headers.update({str(k): str(v) for k, v in destination.headers.items()})
        if destination.signing_secret:
            timestamp = str(int(self._now()))
            signing_payload = timestamp.encode("utf-8") + b"." + body
            sig = hmac.new(destination.signing_secret.encode("utf-8"), signing_payload, hashlib.sha256).hexdigest()
            headers[WEBHOOK_SIGNATURE_TIMESTAMP_HEADER] = timestamp
            headers["x-agent-bom-signature"] = f"sha256={sig}"
        scheme = destination.auth_scheme.strip().lower()
        if scheme and destination.auth_token:
            if scheme == "bearer":
                headers[destination.auth_header] = f"Bearer {destination.auth_token}"
            elif scheme == "token":
                headers[destination.auth_header] = f"Token {destination.auth_token}"
            elif scheme == "header":
                headers[destination.auth_header] = destination.auth_token
        return headers

    def _backoff(self, attempt: int) -> float:
        # attempt is 1-based; first retry waits initial_backoff.
        raw = self.retry.initial_backoff * (self.retry.backoff_multiplier ** max(0, attempt - 1))
        raw = min(raw, self.retry.max_backoff)
        jitter = raw * self.retry.jitter_ratio * self._rng()
        return min(raw + jitter, self.retry.max_backoff)

    # — circuit breaker gates —

    def _breaker_allows(self, destination_id: str, now: float) -> tuple[bool, bool]:
        """Return (allowed, is_probe). When OPEN and past cooldown, allow a
        single half-open probe."""
        state, _failures, opened_at = self.store.breaker_state(destination_id)
        if state == CircuitState.CLOSED:
            return True, False
        if state == CircuitState.HALF_OPEN:
            return True, True
        # OPEN
        if opened_at is not None and (now - opened_at) >= self.breaker.cooldown:
            self.store.set_breaker(
                destination_id,
                state=CircuitState.HALF_OPEN,
                consecutive_failures=self.breaker.failure_threshold,
                opened_at=opened_at,
                now=now,
            )
            return True, True
        return False, False

    def _record_success(self, destination_id: str, now: float) -> None:
        self.store.set_breaker(destination_id, state=CircuitState.CLOSED, consecutive_failures=0, opened_at=None, now=now)

    def _record_failure(self, destination_id: str, now: float) -> None:
        state, failures, opened_at = self.store.breaker_state(destination_id)
        failures += 1
        if failures >= self.breaker.failure_threshold:
            self.store.set_breaker(destination_id, state=CircuitState.OPEN, consecutive_failures=failures, opened_at=now, now=now)
        else:
            self.store.set_breaker(destination_id, state=CircuitState.CLOSED, consecutive_failures=failures, opened_at=None, now=now)

    # — public API —

    def deliver(self, destination: Destination, delivery: Delivery) -> DeliveryResult:
        """Attempt delivery with retries/backoff, idempotency, circuit-breaker,
        dead-letter, and full audit logging. Never raises for a failed send.
        """
        if destination.destination_id != delivery.destination_id:
            raise DeliveryError("delivery.destination_id must match destination.destination_id")

        now = self._now()
        key = delivery.idempotency_key

        # Idempotency: a key that already reached a terminal state is not re-sent.
        prior = self.store.terminal_status(destination.destination_id, key)
        if prior is not None:
            return DeliveryResult(
                idempotency_key=key,
                destination_id=destination.destination_id,
                status="deduplicated",
                delivered=(prior == "delivered"),
                warning="" if prior == "delivered" else f"prior delivery for this key ended in '{prior}'",
            )

        # Circuit breaker gate.
        allowed, _is_probe = self._breaker_allows(destination.destination_id, now)
        if not allowed:
            warning = f"circuit open for destination '{destination.destination_id}'; delivery deferred to dead-letter"
            self.store.log_attempt(
                idempotency_key=key,
                destination_id=destination.destination_id,
                kind=destination.kind,
                attempt=0,
                status="circuit_open",
                http_status=None,
                payload_preview=redacted_preview(delivery.payload),
                error=warning,
                now=now,
            )
            self.store.record_terminal(
                destination_id=destination.destination_id, idempotency_key=key, status="dead_letter", http_status=None, attempts=0, now=now
            )
            logger.warning("delivery: %s", warning)
            return DeliveryResult(
                idempotency_key=key,
                destination_id=destination.destination_id,
                status="circuit_open",
                attempts=0,
                delivered=False,
                warning=warning,
            )

        body = _canonical_json(delivery.payload).encode("utf-8")
        preview = redacted_preview(delivery.payload)
        last_http: int | None = None
        last_error = ""

        for attempt in range(1, self.retry.max_attempts + 1):
            headers = self._build_headers(destination, delivery, body, attempt)
            outcome = self.sender(destination.url, headers, body, destination.timeout)
            attempt_now = self._now()
            last_http = outcome.http_status
            last_error = outcome.error

            if outcome.is_success:
                self.store.log_attempt(
                    idempotency_key=key,
                    destination_id=destination.destination_id,
                    kind=destination.kind,
                    attempt=attempt,
                    status="delivered",
                    http_status=outcome.http_status,
                    payload_preview=preview,
                    error="",
                    now=attempt_now,
                )
                self.store.record_terminal(
                    destination_id=destination.destination_id,
                    idempotency_key=key,
                    status="delivered",
                    http_status=outcome.http_status,
                    attempts=attempt,
                    now=attempt_now,
                )
                self._record_success(destination.destination_id, attempt_now)
                return DeliveryResult(
                    idempotency_key=key,
                    destination_id=destination.destination_id,
                    status="delivered",
                    http_status=outcome.http_status,
                    attempts=attempt,
                    delivered=True,
                )

            # Non-success: classify retryable vs permanent.
            retryable = _is_retryable(outcome)
            status_label = "retry" if (retryable and attempt < self.retry.max_attempts) else "failed"
            self.store.log_attempt(
                idempotency_key=key,
                destination_id=destination.destination_id,
                kind=destination.kind,
                attempt=attempt,
                status=status_label,
                http_status=outcome.http_status,
                payload_preview=preview,
                error=_attempt_error_text(outcome),
                now=attempt_now,
            )
            self._record_failure(destination.destination_id, attempt_now)

            if not retryable:
                break  # permanent (auth/4xx) — stop, dead-letter
            if attempt < self.retry.max_attempts:
                self._sleep(self._backoff(attempt))

        # Exhausted / permanent failure → dead-letter (never blocks caller).
        terminal_now = self._now()
        self.store.record_terminal(
            destination_id=destination.destination_id,
            idempotency_key=key,
            status="dead_letter",
            http_status=last_http,
            attempts=self.retry.max_attempts,
            now=terminal_now,
        )
        self.store.log_attempt(
            idempotency_key=key,
            destination_id=destination.destination_id,
            kind=destination.kind,
            attempt=self.retry.max_attempts,
            status="dead_letter",
            http_status=last_http,
            payload_preview=preview,
            error=last_error or (f"HTTP {last_http}" if last_http else "delivery failed"),
            now=terminal_now,
        )
        warning = _dead_letter_warning(destination, last_http, last_error)
        logger.warning("delivery: %s", warning)
        return DeliveryResult(
            idempotency_key=key,
            destination_id=destination.destination_id,
            status="dead_letter",
            http_status=last_http,
            attempts=self.retry.max_attempts,
            delivered=False,
            warning=warning,
        )

    # — operator queries —

    def delivery_log(
        self, *, destination_id: str | None = None, idempotency_key: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.store.attempts(destination_id=destination_id, idempotency_key=idempotency_key, limit=limit)]

    def dead_letters(self, *, destination_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.store.dead_letters(destination_id=destination_id, limit=limit)]

    def circuit_state(self, destination_id: str) -> str:
        return self._breaker_state_str(destination_id)

    def _breaker_state_str(self, destination_id: str) -> str:
        state, _f, opened_at = self.store.breaker_state(destination_id)
        # Reflect a cooldown-elapsed OPEN as half-open to callers (probe pending).
        if state == CircuitState.OPEN and opened_at is not None and (self._now() - opened_at) >= self.breaker.cooldown:
            return CircuitState.HALF_OPEN.value
        return state.value


# ── Classification helpers ───────────────────────────────────────────────────


def _is_retryable(outcome: SendOutcome) -> bool:
    if outcome.http_status is None:
        return True  # transport/connection error — retry
    if outcome.http_status in _RETRYABLE_STATUS:
        return True
    if outcome.http_status >= _PERMANENT_4XX_FLOOR and outcome.http_status < 500:
        return False  # auth / client error — permanent
    return False


def _attempt_error_text(outcome: SendOutcome) -> str:
    if outcome.error:
        return outcome.error
    if outcome.http_status is not None:
        return f"HTTP {outcome.http_status}"
    return "delivery failed"


def _dead_letter_warning(destination: Destination, http_status: int | None, error: str) -> str:
    base = f"delivery to '{destination.destination_id}' ({destination.kind}) dead-lettered after retries"
    if http_status in (401, 403):
        return f"{base}: authentication/authorization rejected (HTTP {http_status}) — check the destination credential, then requeue"
    if http_status == 429:
        return f"{base}: destination is rate-limiting (HTTP 429) — it will be retried; consider lowering send volume"
    if http_status is not None:
        return f"{base}: HTTP {http_status}"
    safe = sanitize_error(error) if error else "connection error"
    return f"{base}: {safe}"


# ── Process-wide singleton (opt-in, defaults preserve existing behavior) ──────

_DELIVERY_CLIENT: DeliveryClient | None = None
_DELIVERY_LOCK = threading.Lock()


def get_delivery_client() -> DeliveryClient:
    global _DELIVERY_CLIENT
    if _DELIVERY_CLIENT is None:
        with _DELIVERY_LOCK:
            if _DELIVERY_CLIENT is None:
                _DELIVERY_CLIENT = DeliveryClient()
    return _DELIVERY_CLIENT


def set_delivery_client(client: DeliveryClient | None) -> None:
    global _DELIVERY_CLIENT
    with _DELIVERY_LOCK:
        _DELIVERY_CLIENT = client


__all__ = [
    "AttemptRecord",
    "BreakerPolicy",
    "CircuitState",
    "Delivery",
    "DeliveryClient",
    "DeliveryError",
    "DeliveryResult",
    "DeliveryStore",
    "Destination",
    "RetryPolicy",
    "SendOutcome",
    "Sender",
    "WEBHOOK_SIGNATURE_FRESHNESS_SECONDS",
    "WEBHOOK_SIGNATURE_TIMESTAMP_HEADER",
    "default_delivery_store_path",
    "get_delivery_client",
    "http_sender",
    "redacted_preview",
    "set_delivery_client",
]
