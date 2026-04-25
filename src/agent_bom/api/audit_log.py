"""Immutable audit log for compliance and forensics.

Append-only log of all significant actions:
    - Scan executions
    - Policy evaluations
    - Fleet state changes
    - Exception grants/revocations
    - Alert dispatches

Each entry is HMAC-signed to detect tampering. The log supports both
in-memory (dev) and SQLite (production) backends.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

logger = logging.getLogger(__name__)
_AUDIT_DETAIL_KEY_RE = re.compile(r"[^a-zA-Z0-9_.:-]+")
_MAX_AUDIT_DETAIL_KEYS = 64
_MAX_AUDIT_DETAIL_KEY_LENGTH = 96
_MAX_AUDIT_DETAIL_STRING_LENGTH = 2048
_MAX_AUDIT_DETAIL_COLLECTION_ITEMS = 32
_MAX_AUDIT_DETAIL_DEPTH = 4
_MAX_AUDIT_DETAILS_JSON_BYTES = 16 * 1024


def _env_enabled(name: str) -> bool:
    value = os.environ.get(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str) -> int | None:
    value = (os.environ.get(name) or "").strip()
    if not value:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _describe_rotation_posture(
    *,
    configured: bool,
    last_rotated_env: str,
    rotation_days_env: str,
    max_age_days_env: str,
    subject: str,
    not_configured_status: str,
    not_configured_message: str,
) -> dict[str, object]:
    rotation_days = _env_int(rotation_days_env)
    max_age_days = _env_int(max_age_days_env)
    raw_last_rotated = (os.environ.get(last_rotated_env) or "").strip()

    if not configured:
        return {
            "rotation_tracking_supported": True,
            "rotation_status": not_configured_status,
            "rotation_method": "env_swap_and_restart",
            "rotation_days": rotation_days,
            "max_age_days": max_age_days,
            "last_rotated": None,
            "age_days": None,
            "rotation_message": not_configured_message,
        }

    if not raw_last_rotated:
        return {
            "rotation_tracking_supported": True,
            "rotation_status": "unknown_age",
            "rotation_method": "env_swap_and_restart",
            "rotation_days": rotation_days,
            "max_age_days": max_age_days,
            "last_rotated": None,
            "age_days": None,
            "rotation_message": (
                f"{subject} is configured but {last_rotated_env} is unset. Record an ISO-8601 rotation timestamp "
                "to expose key age in operator surfaces."
            ),
        }

    try:
        rotated = datetime.fromisoformat(raw_last_rotated)
    except ValueError:
        return {
            "rotation_tracking_supported": True,
            "rotation_status": "unknown_age",
            "rotation_method": "env_swap_and_restart",
            "rotation_days": rotation_days,
            "max_age_days": max_age_days,
            "last_rotated": raw_last_rotated,
            "age_days": None,
            "rotation_message": (
                f"{last_rotated_env} is set but is not a valid ISO-8601 timestamp. Use a value like '2026-04-17T00:00:00+00:00'."
            ),
        }

    if rotated.tzinfo is None:
        rotated = rotated.replace(tzinfo=timezone.utc)
    age_days = max(0, int((datetime.now(timezone.utc) - rotated).total_seconds() // 86400))

    if max_age_days is not None and age_days >= max_age_days:
        status = "max_age_exceeded"
        message = (
            f"{subject} is {age_days} days old, exceeding the configured maximum ({max_age_days} days). Rotate the "
            "secret, restart the control plane, and update the recorded rotation timestamp."
        )
    elif rotation_days is not None and age_days >= rotation_days:
        status = "rotation_due"
        message = f"{subject} is {age_days} days old, past the configured rotation interval ({rotation_days} days)."
    else:
        status = "ok"
        if rotation_days is not None:
            message = f"{subject} is {age_days} days old; configured rotation interval is {rotation_days} days."
        else:
            message = f"{subject} is {age_days} days old. No explicit rotation interval is configured."

    return {
        "rotation_tracking_supported": True,
        "rotation_status": status,
        "rotation_method": "env_swap_and_restart",
        "rotation_days": rotation_days,
        "max_age_days": max_age_days,
        "last_rotated": rotated.isoformat(),
        "age_days": age_days,
        "rotation_message": message,
    }


# HMAC key for audit log tamper detection.  When unset, an ephemeral
# per-process key is generated — signatures verify within the same process
# but provide no cross-restart integrity.  Production deployments MUST set
# AGENT_BOM_AUDIT_HMAC_KEY for meaningful tamper detection.
_HMAC_ENV_KEY = (os.environ.get("AGENT_BOM_AUDIT_HMAC_KEY") or "").strip()
if _HMAC_ENV_KEY:
    _HMAC_KEY = _HMAC_ENV_KEY.encode()
else:
    if _env_enabled("AGENT_BOM_REQUIRE_AUDIT_HMAC"):
        raise RuntimeError("AGENT_BOM_REQUIRE_AUDIT_HMAC is enabled but AGENT_BOM_AUDIT_HMAC_KEY is not set")
    import secrets as _secrets

    _HMAC_KEY = _secrets.token_bytes(32)
    logger.warning(
        "AGENT_BOM_AUDIT_HMAC_KEY not set — audit log HMAC uses ephemeral key "
        "(signatures will not survive process restart; set env var for production)"
    )


@dataclass
class AuditEntry:
    """Single audit log entry."""

    entry_id: str = ""
    timestamp: str = ""
    action: str = ""  # scan, policy_eval, fleet_change, exception, alert, config
    actor: str = ""  # API key prefix, role, or "system"
    resource: str = ""  # e.g., "job/abc123", "fleet/agent-1", "exception/exc-1"
    details: dict = field(default_factory=dict)
    prev_signature: str = ""
    hmac_signature: str = ""

    def __post_init__(self) -> None:
        if not self.entry_id:
            self.entry_id = str(uuid4())
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def _canonical_details_json(self) -> str:
        return json.dumps(self.details or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def _legacy_hmac(self) -> str:
        payload = f"{self.prev_signature}|{self.entry_id}|{self.timestamp}|{self.action}|{self.actor}|{self.resource}"
        return hmac.new(_HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()

    def compute_hmac(self) -> str:
        """Compute HMAC-SHA256 signature for tamper detection (chain-hashed)."""
        payload = (
            f"{self.prev_signature}|{self.entry_id}|{self.timestamp}|"
            f"{self.action}|{self.actor}|{self.resource}|{self._canonical_details_json()}"
        )
        return hmac.new(_HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()

    def sign(self) -> None:
        """Sign this entry."""
        self.hmac_signature = self.compute_hmac()

    def verify(self) -> bool:
        """Verify HMAC signature."""
        return hmac.compare_digest(self.hmac_signature, self.compute_hmac()) or hmac.compare_digest(
            self.hmac_signature, self._legacy_hmac()
        )

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "resource": self.resource,
            "details": self.details,
            "prev_signature": self.prev_signature,
            "hmac_signature": self.hmac_signature,
        }


def sign_export_payload(payload: bytes) -> str:
    """Sign an exported audit payload so downstream consumers can verify it."""
    return hmac.new(_HMAC_KEY, payload, hashlib.sha256).hexdigest()


def verify_export_payload(payload: bytes, signature: str) -> bool:
    """Verify a signed audit export payload without exposing key material."""
    expected = sign_export_payload(payload)
    return hmac.compare_digest(signature.strip(), expected)


def describe_audit_hmac_status() -> dict[str, object]:
    """Return operator-facing audit HMAC posture for auth/policy surfaces."""
    required = _env_enabled("AGENT_BOM_REQUIRE_AUDIT_HMAC")
    configured = bool(_HMAC_ENV_KEY)
    key_id = (os.environ.get("AGENT_BOM_AUDIT_HMAC_KEY_ID") or "").strip()
    rotation = _describe_rotation_posture(
        configured=configured,
        last_rotated_env="AGENT_BOM_AUDIT_HMAC_LAST_ROTATED",
        rotation_days_env="AGENT_BOM_AUDIT_HMAC_ROTATION_DAYS",
        max_age_days_env="AGENT_BOM_AUDIT_HMAC_MAX_AGE_DAYS",
        subject="Audit HMAC secret",
        not_configured_status="ephemeral",
        not_configured_message=(
            "Audit integrity is currently backed by a process-ephemeral secret, so there is no stable rotation history to track."
        ),
    )
    if configured:
        return {
            "status": "configured",
            "configured": True,
            "required": required,
            "source": "AGENT_BOM_AUDIT_HMAC_KEY",
            "persists_across_restart": True,
            "key_id_configured": bool(key_id),
            "key_id": key_id or None,
            "message": (
                "Audit log tamper detection uses a configured shared secret. "
                "Signatures remain verifiable across restarts as long as the same key stays in place."
            ),
            **rotation,
        }
    return {
        "status": "ephemeral",
        "configured": False,
        "required": required,
        "source": "process_ephemeral",
        "persists_across_restart": False,
        "key_id_configured": False,
        "key_id": None,
        "message": (
            "Audit log tamper detection is using an in-process ephemeral secret. "
            "Integrity checks work only for this process lifetime and reset after restart."
        ),
        **rotation,
    }


class AuditLogStore(Protocol):
    """Protocol for audit log persistence."""

    def append(self, entry: AuditEntry) -> None: ...
    def list_entries(
        self,
        action: str | None = None,
        resource: str | None = None,
        since: str | None = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[AuditEntry]: ...
    def count(self, action: str | None = None, tenant_id: str | None = None) -> int: ...
    def verify_integrity(self, limit: int = 1000, tenant_id: str | None = None) -> tuple[int, int]: ...


def _entry_tenant(entry: AuditEntry) -> str:
    return str((entry.details or {}).get("tenant_id") or "default")


class InMemoryAuditLog:
    """In-memory audit log for development."""

    _MAX_ENTRIES = 50_000

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()
        self._last_sig_by_tenant: dict[str, str] = defaultdict(str)

    def append(self, entry: AuditEntry) -> None:
        tenant_id = _entry_tenant(entry)
        entry.prev_signature = self._last_sig_by_tenant[tenant_id]
        entry.sign()
        self._last_sig_by_tenant[tenant_id] = entry.hmac_signature
        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self._MAX_ENTRIES:
                self._entries = self._entries[self._MAX_ENTRIES // 2 :]

    def list_entries(
        self,
        action: str | None = None,
        resource: str | None = None,
        since: str | None = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[AuditEntry]:
        with self._lock:
            filtered = self._entries
            if tenant_id is not None:
                filtered = [e for e in filtered if str((e.details or {}).get("tenant_id", "")) == tenant_id]
            if action:
                filtered = [e for e in filtered if e.action == action]
            if resource:
                filtered = [e for e in filtered if e.resource.startswith(resource)]
            if since:
                filtered = [e for e in filtered if e.timestamp >= since]
            # Most recent first
            filtered = list(reversed(filtered))
            return filtered[offset : offset + limit]

    def count(self, action: str | None = None, tenant_id: str | None = None) -> int:
        with self._lock:
            entries = self._entries
            if tenant_id is not None:
                entries = [e for e in entries if str((e.details or {}).get("tenant_id", "")) == tenant_id]
            if action:
                return sum(1 for e in entries if e.action == action)
            return len(entries)

    def verify_integrity(self, limit: int = 1000, tenant_id: str | None = None) -> tuple[int, int]:
        """Verify chain-hashed HMAC signatures. Returns (verified_count, tampered_count)."""
        entries = list(reversed(self.list_entries(limit=limit, tenant_id=tenant_id)))
        verified = 0
        tampered = 0
        prev_sig = entries[0].prev_signature if entries else ""
        for entry in entries:
            if entry.prev_signature != prev_sig or not entry.verify():
                tampered += 1
            else:
                verified += 1
            prev_sig = entry.hmac_signature
        return verified, tampered


class SQLiteAuditLog:
    """SQLite-backed append-only audit log."""

    def __init__(self, db_path: str = "agent_bom_audit.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._last_sig_by_tenant: dict[str, str] = defaultdict(str)
        self._init_db()
        self._hydrate_last_signatures()
        if os.path.exists(self._db_path):
            os.chmod(self._db_path, 0o600)

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self) -> None:
        self._conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            entry_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL DEFAULT '',
            resource TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '{}',
            prev_signature TEXT NOT NULL DEFAULT '',
            hmac_signature TEXT NOT NULL
        )""")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource)")
        self._conn.commit()

    def _latest_signature_for_tenant(self, tenant_id: str) -> str:
        row = self._conn.execute(
            """
            SELECT hmac_signature
            FROM audit_log
            WHERE COALESCE(NULLIF(json_extract(details, '$.tenant_id'), ''), 'default') = ?
            ORDER BY timestamp DESC, rowid DESC
            LIMIT 1
            """,
            (tenant_id,),
        ).fetchone()
        return row[0] if row else ""

    def _hydrate_last_signatures(self) -> None:
        rows = self._conn.execute(
            """
            SELECT tenant_id, hmac_signature
            FROM (
                SELECT
                    COALESCE(NULLIF(json_extract(details, '$.tenant_id'), ''), 'default') AS tenant_id,
                    hmac_signature,
                    ROW_NUMBER() OVER (
                        PARTITION BY COALESCE(NULLIF(json_extract(details, '$.tenant_id'), ''), 'default')
                        ORDER BY timestamp DESC, rowid DESC
                    ) AS rn
                FROM audit_log
            )
            WHERE rn = 1
            """
        ).fetchall()
        for tenant_id, signature in rows:
            self._last_sig_by_tenant[str(tenant_id)] = str(signature or "")

    def append(self, entry: AuditEntry) -> None:
        tenant_id = _entry_tenant(entry)
        prev_sig = self._last_sig_by_tenant.get(tenant_id)
        if prev_sig is None or prev_sig == "":
            prev_sig = self._latest_signature_for_tenant(tenant_id)
        entry.prev_signature = prev_sig
        entry.sign()
        self._last_sig_by_tenant[tenant_id] = entry.hmac_signature
        self._conn.execute(
            "INSERT INTO audit_log"
            " (entry_id, timestamp, action, actor, resource,"
            " details, prev_signature, hmac_signature)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry.entry_id,
                entry.timestamp,
                entry.action,
                entry.actor,
                entry.resource,
                json.dumps(entry.details),
                entry.prev_signature,
                entry.hmac_signature,
            ),
        )
        self._conn.commit()

    def list_entries(
        self,
        action: str | None = None,
        resource: str | None = None,
        since: str | None = None,
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> list[AuditEntry]:
        clauses = []
        params: list = []
        if tenant_id is not None:
            clauses.append("json_extract(details, '$.tenant_id') = ?")
            params.append(tenant_id)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if resource:
            clauses.append("resource LIKE ?")
            params.append(f"{resource}%")
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""  # nosec B608 — clauses are static strings, values are parameterized
        sql = (
            f"SELECT entry_id, timestamp, action, actor, resource, details, prev_signature, hmac_signature"  # nosec B608
            f" FROM audit_log {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])

        rows = self._conn.execute(sql, params).fetchall()
        return [
            AuditEntry(
                entry_id=r[0],
                timestamp=r[1],
                action=r[2],
                actor=r[3],
                resource=r[4],
                details=json.loads(r[5]),
                prev_signature=r[6],
                hmac_signature=r[7],
            )
            for r in rows
        ]

    def count(self, action: str | None = None, tenant_id: str | None = None) -> int:
        clauses = []
        params: list[object] = []
        if tenant_id is not None:
            clauses.append("json_extract(details, '$.tenant_id') = ?")
            params.append(tenant_id)
        if action:
            clauses.append("action = ?")
            params.append(action)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        row = self._conn.execute(f"SELECT COUNT(*) FROM audit_log{where}", params).fetchone()  # nosec B608
        return row[0] if row else 0

    def verify_integrity(self, limit: int = 1000, tenant_id: str | None = None) -> tuple[int, int]:
        """Verify chain-hashed HMAC signatures. Returns (verified_count, tampered_count)."""
        entries = self.list_entries(limit=limit, tenant_id=tenant_id)
        # list_entries returns most-recent-first; reverse for chronological chain verification
        entries = list(reversed(entries))
        verified = 0
        tampered = 0
        prev_sig = entries[0].prev_signature if entries else ""
        for entry in entries:
            if entry.prev_signature != prev_sig or not entry.verify():
                tampered += 1
            else:
                verified += 1
            prev_sig = entry.hmac_signature
        return verified, tampered


# ── Module-level singleton ──

_audit_log: AuditLogStore | None = None
_audit_lock = threading.Lock()


def get_audit_log() -> AuditLogStore:
    global _audit_log
    if _audit_log is None:
        with _audit_lock:
            if _audit_log is None:
                if os.environ.get("AGENT_BOM_POSTGRES_URL"):
                    from agent_bom.api.postgres_store import PostgresAuditLog

                    _audit_log = PostgresAuditLog()
                else:
                    db = os.environ.get("AGENT_BOM_AUDIT_DB") or os.environ.get("AGENT_BOM_DB")
                    if db:
                        _audit_log = SQLiteAuditLog(db)
                    else:
                        _audit_log = InMemoryAuditLog()
    return _audit_log


def _default_tenant_id(details: dict[str, object]) -> str:
    tenant = details.get("tenant_id")
    if tenant not in (None, ""):
        return str(tenant)
    try:
        from agent_bom.api.postgres_store import _current_tenant

        current = _current_tenant.get()
        if current:
            return str(current)
    except Exception:
        logger.debug("Audit tenant fallback unavailable", exc_info=True)
    return "default"


def _sanitize_detail_key(key: object) -> str:
    cleaned = _AUDIT_DETAIL_KEY_RE.sub("_", str(key).strip())[:_MAX_AUDIT_DETAIL_KEY_LENGTH].strip("._:-")
    cleaned = cleaned.strip("_")
    return cleaned or "detail"


def _sanitize_detail_value(value: object, *, depth: int = 0) -> object:
    if depth >= _MAX_AUDIT_DETAIL_DEPTH:
        return "[truncated]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        text = value.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        return text[:_MAX_AUDIT_DETAIL_STRING_LENGTH]
    if isinstance(value, dict):
        out: dict[str, object] = {}
        for index, (raw_key, raw_value) in enumerate(value.items()):
            if index >= _MAX_AUDIT_DETAIL_COLLECTION_ITEMS:
                out["_truncated"] = True
                break
            out[_sanitize_detail_key(raw_key)] = _sanitize_detail_value(raw_value, depth=depth + 1)
        return out
    if isinstance(value, list | tuple | set):
        items = list(value)
        list_out = [_sanitize_detail_value(item, depth=depth + 1) for item in items[:_MAX_AUDIT_DETAIL_COLLECTION_ITEMS]]
        if len(items) > _MAX_AUDIT_DETAIL_COLLECTION_ITEMS:
            list_out.append("[truncated]")
        return list_out
    return str(value)[:_MAX_AUDIT_DETAIL_STRING_LENGTH]


def sanitize_audit_details(details: dict[str, object]) -> dict[str, object]:
    """Bound audit metadata shape and size before persistence/export."""
    sanitized: dict[str, object] = {}
    for index, (raw_key, raw_value) in enumerate(details.items()):
        if index >= _MAX_AUDIT_DETAIL_KEYS:
            sanitized["_truncated"] = True
            break
        sanitized[_sanitize_detail_key(raw_key)] = _sanitize_detail_value(raw_value)

    encoded = json.dumps(sanitized, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")
    if len(encoded) <= _MAX_AUDIT_DETAILS_JSON_BYTES:
        return sanitized

    tenant_id = sanitized.get("tenant_id", "default")
    return {
        "tenant_id": str(tenant_id)[:_MAX_AUDIT_DETAIL_STRING_LENGTH],
        "_truncated": True,
        "_original_bytes": len(encoded),
    }


def set_audit_log(store: AuditLogStore) -> None:
    global _audit_log
    with _audit_lock:
        _audit_log = store


def log_action(action: str, actor: str = "system", resource: str = "", **details: object) -> None:
    """Convenience: append an audit entry."""
    audit_details = dict(details)
    audit_details["tenant_id"] = _default_tenant_id(audit_details)
    audit_details = sanitize_audit_details(audit_details)
    entry = AuditEntry(action=action, actor=actor, resource=resource, details=audit_details)
    get_audit_log().append(entry)
    try:
        from agent_bom.api.stores import _get_analytics_store

        _get_analytics_store().record_audit_event(
            {
                "entry_id": entry.entry_id,
                "timestamp": entry.timestamp,
                "action": entry.action,
                "actor": entry.actor,
                "resource": entry.resource,
                "tenant_id": str(entry.details.get("tenant_id", "default") or "default"),
                "session_id": str(entry.details.get("session_id", "") or ""),
                "trace_id": str(entry.details.get("trace_id", "") or ""),
                "request_id": str(entry.details.get("request_id", "") or ""),
            }
        )
    except Exception:
        logger.debug("Audit analytics sync skipped", exc_info=True)
