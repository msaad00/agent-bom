"""Cluster-safe state for auth attempts and revoked browser sessions.

Closes the audit-5 PR-C deferred items: a process-local dict for the
auth-session attempt counter and the revoked-session-nonce set is unsafe
under multiple API replicas. Each replica enforces its own copy of the
limit, so the effective brute-force budget is ``limit × num_replicas``,
and a session revoked on replica-1 can still be presented to replica-2.

This module provides one abstraction with two backends:

- :class:`InMemoryAuthState` — process-local dict + ``threading.Lock``.
  Default; used when no shared backend is available.
- :class:`PostgresAuthState` — backed by ``auth_session_attempts`` and
  ``revoked_session_nonces`` tables, shared across every API replica.
  Auto-selected when ``AGENT_BOM_POSTGRES_URL`` is set.

Selection happens once per process via :func:`get_auth_state`. PR A's
warning emitter (``_warn_in_process_rate_limit_in_cluster``) becomes a
no-op once the Postgres backend takes over because the gap is closed.

The contract is:

- ``record_attempt(key, window_seconds, limit) -> bool`` — record an
  attempt for ``key`` and return whether it is still within the limit
  for the rolling window. Cluster-wide truth.
- ``revoke_nonce(nonce, expires_at)`` — mark a nonce as revoked until
  ``expires_at`` (Unix timestamp seconds). Idempotent.
- ``is_nonce_revoked(nonce, now=None) -> bool`` — fast lookup.
- ``cleanup_expired(now=None) -> int`` — best-effort sweep of stale
  rows; called opportunistically by route handlers. Returns the count
  of rows removed for observability.

The Postgres backend is intentionally written so a connection failure
falls back to the in-memory backend (with a ``WARNING`` log) rather
than failing closed and breaking the auth loop. The fail-open here is
narrow: any single replica still enforces the limit; only the
cross-replica multiplier is lost during the outage.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from typing import Any, Protocol

_logger = logging.getLogger(__name__)

# SQL strings are intentionally hardcoded (no f-strings, no user input)
# so bandit's B608 SQLi detector does not match them. Schema names are
# fixed identifiers; only parameter values flow through psycopg's
# parameter binding (`%s`). Audit-5 PR-C: every CREATE / DELETE /
# SELECT below uses constant SQL with bound parameters only.
_SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS auth_session_attempts (
        key TEXT NOT NULL,
        attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS auth_session_attempts_key_attempted_at_idx
        ON auth_session_attempts (key, attempted_at);
    CREATE INDEX IF NOT EXISTS auth_session_attempts_attempted_at_idx
        ON auth_session_attempts (attempted_at);

    CREATE TABLE IF NOT EXISTS revoked_session_nonces (
        nonce TEXT PRIMARY KEY,
        expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS revoked_session_nonces_expires_at_idx
        ON revoked_session_nonces (expires_at);
"""

_INSERT_ATTEMPT_SQL = "INSERT INTO auth_session_attempts (key, attempted_at) VALUES (%s, NOW())"
_DELETE_OLD_ATTEMPTS_SQL = "DELETE FROM auth_session_attempts WHERE attempted_at < NOW() - (%s::int * INTERVAL '1 second')"
_COUNT_ATTEMPTS_SQL = (
    "SELECT COUNT(*) FROM auth_session_attempts WHERE key = %s AND attempted_at >= NOW() - (%s::int * INTERVAL '1 second')"
)
_UPSERT_REVOKED_SQL = (
    "INSERT INTO revoked_session_nonces (nonce, expires_at)"
    " VALUES (%s, TO_TIMESTAMP(%s))"
    " ON CONFLICT (nonce) DO UPDATE SET expires_at = EXCLUDED.expires_at"
)
_CHECK_REVOKED_SQL = "SELECT 1 FROM revoked_session_nonces WHERE nonce = %s AND expires_at > TO_TIMESTAMP(%s)"
_DELETE_OLD_ATTEMPTS_SWEEP_SQL = "DELETE FROM auth_session_attempts WHERE attempted_at < NOW() - INTERVAL '24 hours'"
_DELETE_EXPIRED_REVOKED_SQL = "DELETE FROM revoked_session_nonces WHERE expires_at <= NOW()"


class AuthStateBackend(Protocol):
    """Stateful auth gating that may live in-process or in shared storage."""

    def record_attempt(self, key: str, window_seconds: int, limit: int) -> bool:
        """Record an attempt for ``key``; return ``True`` if still within ``limit`` for the rolling ``window_seconds``."""
        ...

    def revoke_nonce(self, nonce: str, expires_at: int) -> None:
        """Mark ``nonce`` as revoked until ``expires_at`` (Unix seconds)."""
        ...

    def is_nonce_revoked(self, nonce: str, now: int | None = None) -> bool:
        """Return ``True`` when ``nonce`` is currently revoked."""
        ...

    def cleanup_expired(self, now: int | None = None) -> int:
        """Sweep stale auth attempts and revoked nonces. Returns count removed."""
        ...

    @property
    def name(self) -> str:
        """Stable backend identifier for logs and posture surfaces."""
        ...


class InMemoryAuthState:
    """Process-local backend. Safe on a single replica."""

    name = "in_memory"

    def __init__(self) -> None:
        self._attempts: dict[str, deque[float]] = {}
        self._revoked: dict[str, int] = {}
        self._lock = threading.Lock()

    def record_attempt(self, key: str, window_seconds: int, limit: int) -> bool:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            entries = self._attempts.setdefault(key, deque())
            while entries and entries[0] < cutoff:
                entries.popleft()
            entries.append(now)
            return len(entries) <= limit

    def revoke_nonce(self, nonce: str, expires_at: int) -> None:
        if not nonce:
            return
        with self._lock:
            now = int(time.time())
            stale = [k for k, exp in self._revoked.items() if exp <= now]
            for k in stale:
                self._revoked.pop(k, None)
            self._revoked[nonce] = expires_at

    def is_nonce_revoked(self, nonce: str, now: int | None = None) -> bool:
        if not nonce:
            return False
        moment = int(time.time()) if now is None else int(now)
        with self._lock:
            expires_at = self._revoked.get(nonce)
            if expires_at is None:
                return False
            if expires_at <= moment:
                self._revoked.pop(nonce, None)
                return False
            return True

    def cleanup_expired(self, now: int | None = None) -> int:
        moment = int(time.time()) if now is None else int(now)
        cutoff = time.monotonic() - 24 * 3600  # bound attempt history at 24h
        removed = 0
        with self._lock:
            for key, entries in list(self._attempts.items()):
                while entries and entries[0] < cutoff:
                    entries.popleft()
                    removed += 1
                if not entries:
                    self._attempts.pop(key, None)
            stale = [k for k, exp in self._revoked.items() if exp <= moment]
            for k in stale:
                self._revoked.pop(k, None)
                removed += 1
        return removed


class PostgresAuthState:
    """Postgres-backed backend. Cluster-safe across replicas.

    Each method opens a short-lived connection from the existing pool
    in :mod:`agent_bom.api.postgres_common`. Schema is created lazily on
    first use, and surfaces no errors back to the caller — failures
    degrade to the in-memory fallback (with a one-shot warning per
    process) rather than blocking the auth loop.
    """

    name = "postgres"

    def __init__(self) -> None:
        self._fallback = InMemoryAuthState()
        self._schema_ready = False
        self._fallback_warned = False

    def _ensure_schema(self) -> bool:
        if self._schema_ready:
            return True
        try:
            from agent_bom.api.postgres_common import _get_pool

            pool = _get_pool()
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(_SCHEMA_SQL)
                conn.commit()
            self._schema_ready = True
            return True
        except Exception as exc:  # noqa: BLE001
            self._warn_fallback("schema bootstrap", exc)
            return False

    def _warn_fallback(self, context: str, exc: Exception) -> None:
        if self._fallback_warned:
            return
        self._fallback_warned = True
        _logger.warning(
            "PostgresAuthState falling back to in-memory backend (%s): %s. Cross-replica enforcement is degraded until Postgres recovers.",
            context,
            exc,
        )

    def record_attempt(self, key: str, window_seconds: int, limit: int) -> bool:
        if not self._ensure_schema():
            return self._fallback.record_attempt(key, window_seconds, limit)
        try:
            from agent_bom.api.postgres_common import _get_pool

            pool = _get_pool()
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(_INSERT_ATTEMPT_SQL, (key,))
                    cur.execute(_DELETE_OLD_ATTEMPTS_SQL, (window_seconds,))
                    cur.execute(_COUNT_ATTEMPTS_SQL, (key, window_seconds))
                    row = cur.fetchone()
                conn.commit()
            count = int(row[0]) if row else 0
            return count <= limit
        except Exception as exc:  # noqa: BLE001
            self._warn_fallback("record_attempt", exc)
            return self._fallback.record_attempt(key, window_seconds, limit)

    def revoke_nonce(self, nonce: str, expires_at: int) -> None:
        if not nonce:
            return
        if not self._ensure_schema():
            self._fallback.revoke_nonce(nonce, expires_at)
            return
        try:
            from agent_bom.api.postgres_common import _get_pool

            pool = _get_pool()
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(_UPSERT_REVOKED_SQL, (nonce, int(expires_at)))
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            self._warn_fallback("revoke_nonce", exc)
            self._fallback.revoke_nonce(nonce, expires_at)

    def is_nonce_revoked(self, nonce: str, now: int | None = None) -> bool:
        if not nonce:
            return False
        if not self._ensure_schema():
            return self._fallback.is_nonce_revoked(nonce, now)
        try:
            from agent_bom.api.postgres_common import _get_pool

            pool = _get_pool()
            moment = int(time.time()) if now is None else int(now)
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(_CHECK_REVOKED_SQL, (nonce, moment))
                    row = cur.fetchone()
            return row is not None
        except Exception as exc:  # noqa: BLE001
            self._warn_fallback("is_nonce_revoked", exc)
            return self._fallback.is_nonce_revoked(nonce, now)

    def cleanup_expired(self, now: int | None = None) -> int:
        if not self._ensure_schema():
            return self._fallback.cleanup_expired(now)
        try:
            from agent_bom.api.postgres_common import _get_pool

            pool = _get_pool()
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    # Cap attempts at 24h of history; revoked nonces drop on expiry.
                    cur.execute(_DELETE_OLD_ATTEMPTS_SWEEP_SQL)
                    attempts_removed = cur.rowcount
                    cur.execute(_DELETE_EXPIRED_REVOKED_SQL)
                    nonces_removed = cur.rowcount
                conn.commit()
            return int(attempts_removed or 0) + int(nonces_removed or 0)
        except Exception as exc:  # noqa: BLE001
            self._warn_fallback("cleanup_expired", exc)
            return self._fallback.cleanup_expired(now)


# ── Selection ───────────────────────────────────────────────────────────────

_BACKEND: AuthStateBackend | None = None
_BACKEND_LOCK = threading.Lock()


def _build_backend() -> AuthStateBackend:
    if os.environ.get("AGENT_BOM_POSTGRES_URL"):
        return PostgresAuthState()
    return InMemoryAuthState()


def get_auth_state() -> AuthStateBackend:
    """Return the active backend, building it lazily on first call."""
    global _BACKEND
    if _BACKEND is not None:
        return _BACKEND
    with _BACKEND_LOCK:
        if _BACKEND is None:
            _BACKEND = _build_backend()
    return _BACKEND


def reset_auth_state_for_tests() -> None:
    """Reset backend selection — used by tests that flip env vars."""
    global _BACKEND
    with _BACKEND_LOCK:
        _BACKEND = None


def set_auth_state_for_tests(backend: AuthStateBackend) -> None:
    """Inject a specific backend — used by tests."""
    global _BACKEND
    with _BACKEND_LOCK:
        _BACKEND = backend


def auth_state_posture() -> dict[str, Any]:
    """Operator-facing posture for the active backend (for /v1/auth/policy)."""
    backend = get_auth_state()
    clustered_ok = isinstance(backend, PostgresAuthState)
    cluster_mode_signal = bool(os.environ.get("AGENT_BOM_POSTGRES_URL") or os.environ.get("AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT"))
    return {
        "backend": backend.name,
        "clustered_safe": clustered_ok,
        "cluster_mode_detected": cluster_mode_signal,
        "warning": (
            "Auth attempt counter is process-local; under N replicas the brute-force budget is limit × N."
            if cluster_mode_signal and not clustered_ok
            else ""
        ),
    }
