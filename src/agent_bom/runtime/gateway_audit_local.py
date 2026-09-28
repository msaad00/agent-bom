"""Local gateway audit adapter and fail-closed availability state."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

from agent_bom.runtime.audit_delivery import AuditSpilloverStore, canonical_runtime_state_path
from agent_bom.runtime.gateway_contracts import GatewayAuditDeliveryUnavailableError
from agent_bom.runtime.gateway_events import canonicalize_gateway_enforcement_event, ensure_gateway_event_identity
from agent_bom.security import sanitize_sensitive_payload
from agent_bom.storage import state_home

logger = logging.getLogger("agent_bom.gateway_server")


class LocalGatewayAuditSink:
    """HMAC-chained local durability for gateways without a control plane."""

    def __init__(self, db_path: Path) -> None:
        from agent_bom.api.audit_log import SQLiteAuditLog

        db_path = canonical_runtime_state_path(db_path)
        parent_fd = AuditSpilloverStore._safe_parent_fd(db_path)
        os.close(parent_fd)
        AuditSpilloverStore._validate_existing_path(db_path)
        self._hmac_key = self.load_key(db_path, create=not db_path.exists())
        self._store = SQLiteAuditLog(str(db_path), hmac_key=self._hmac_key)
        self._available = True
        self.db_path = db_path

    @staticmethod
    def load_key(db_path: Path, *, create: bool = False) -> bytes:
        return AuditSpilloverStore.load_or_create_private_key(
            canonical_runtime_state_path(db_path).with_suffix(".hmac.key"),
            create=create,
        )

    async def __call__(self, event: dict[str, Any]) -> None:
        from agent_bom.api.audit_log import AuditEntry, sanitize_audit_details

        if not self._available:
            raise GatewayAuditDeliveryUnavailableError("local durable audit store is unavailable")
        identified = canonicalize_gateway_enforcement_event(ensure_gateway_event_identity(event))
        sanitized = sanitize_sensitive_payload(identified)
        if not isinstance(sanitized, dict):
            self._available = False
            raise GatewayAuditDeliveryUnavailableError("local durable audit event is invalid")
        action = str(sanitized.get("action") or sanitized.get("event_type") or "gateway.runtime")[:256]
        upstream = str(sanitized.get("upstream") or "gateway")[:200]
        entry = AuditEntry(
            action=action,
            actor="gateway",
            resource=f"upstream/{upstream}",
            details=sanitize_audit_details(sanitized),
        )
        try:
            await asyncio.to_thread(self._store.append, entry)
        except Exception as exc:  # noqa: BLE001 - local audit failure is fail-closed
            self._available = False
            logger.error("Gateway local audit persistence unavailable (error_type=%s)", type(exc).__name__)
            raise GatewayAuditDeliveryUnavailableError("local durable audit store is unavailable") from None

    async def admit_before_tool_execution(self, event: dict[str, Any]) -> None:
        await self(event)

    def health(self) -> dict[str, str | int | bool]:
        return {
            "configured": True,
            "mode": "local_hmac_sqlite",
            "status": "healthy" if self._available else "degraded",
            "durable": self._available,
            "accepting_events": self._available,
            "backlog_observable": True,
            "retry_worker_running": False,
            "backlog_bytes": 0,
            "dropped_events": 0,
        }


class UnavailableGatewayAuditSink:
    """Fail-closed health surface retained when local audit setup fails."""

    async def __call__(self, _event: dict[str, Any]) -> None:
        raise GatewayAuditDeliveryUnavailableError("local durable audit store is unavailable")

    async def admit_before_tool_execution(self, event: dict[str, Any]) -> None:
        await self(event)

    @staticmethod
    def health() -> dict[str, str | int | bool]:
        return {
            "configured": True,
            "mode": "unavailable",
            "status": "degraded",
            "durable": False,
            "accepting_events": False,
            "backlog_observable": False,
            "retry_worker_running": False,
            "backlog_bytes": 0,
            "dropped_events": 0,
        }


def build_local_gateway_audit_sink(*, state_dir: Path | None = None) -> LocalGatewayAuditSink:
    """Build the default durable audit path for a standalone local gateway."""

    root = state_dir or state_home.state_dir()
    return LocalGatewayAuditSink(root / "runtime-audit" / "gateway-local-audit.db")
