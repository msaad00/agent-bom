"""Bounded control-plane audit delivery, tenant queues and recovery lifecycle."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from agent_bom.runtime.audit_delivery import (
    AuditDeliveryController,
    AuditDeliveryState,
    AuditSpilloverClaim,
    AuditSpilloverStore,
    audit_delivery_paths,
)
from agent_bom.runtime.gateway_audit_registry import _GatewayAuditTenantRegistry
from agent_bom.runtime.gateway_contracts import GatewayAuditDeliveryUnavailableError, GatewayAuditSender
from agent_bom.runtime.gateway_events import canonicalize_gateway_enforcement_event, ensure_gateway_event_identity
from agent_bom.storage import state_home

logger = logging.getLogger("agent_bom.gateway_server")

_GATEWAY_AUDIT_SPILLOVER_BYTES = 8 * 1024 * 1024


_GATEWAY_AUDIT_DLQ_BYTES = 64 * 1024 * 1024


_GATEWAY_AUDIT_MAX_TENANT_SINKS = 256


async def _send_gateway_audit_batch(
    audit_url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
) -> dict[str, Any]:
    """POST one already-redacted backlog batch to the control plane."""

    import httpx

    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)) as client:
        response = await client.post(audit_url, json=payload, headers=headers)
        response.raise_for_status()
        body = response.json()
    if not isinstance(body, dict):
        raise RuntimeError("control-plane audit acknowledgement is not an object")
    return body


def _audit_health_has_pending_state(health: dict[str, str | int | bool]) -> bool:
    """Return whether a tenant marker must remain for unresolved audit state."""

    return (
        not bool(health.get("backlog_observable", False))
        or int(health.get("backlog_bytes", 0)) > 0
        or int(health.get("dlq_bytes", 0)) > 0
        or int(health.get("dropped_events", 0)) > 0
    )


class ControlPlaneAuditSink:
    """Durably queue and retry standalone-gateway audit delivery.

    A remote outage is fail-safe while the bounded local backlog accepts the
    event: the relay may continue and health reports degraded. If neither the
    spill file nor its finite DLQ can retain the event, ``__call__`` raises and
    the gateway fails closed instead of acknowledging an unaudited decision.
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: str | None,
        tenant_id: str,
        source_id: str,
        session_id: str,
        delivery_state: AuditDeliveryState,
        sender: GatewayAuditSender,
        tenant_registry: _GatewayAuditTenantRegistry | None = None,
        tenant_routing_enabled: bool = True,
        max_tenant_sinks: int = _GATEWAY_AUDIT_MAX_TENANT_SINKS,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._tenant_id = tenant_id
        self._source_id = source_id
        self._session_id = session_id
        self._delivery_state = delivery_state
        self._sender = sender
        self._tenant_registry = tenant_registry
        self._tenant_registry_available = True
        self._lock = asyncio.Lock()
        self._worker: asyncio.Task[None] | None = None
        self._closed = False
        self._persistence_available = True
        self._remote_ack_available = True
        self._tenant_routing_enabled = tenant_routing_enabled
        self._max_tenant_sinks = max_tenant_sinks
        self._tenant_sinks: dict[str, ControlPlaneAuditSink] = {}
        self._tenant_sinks_lock = asyncio.Lock()

    async def bind_authenticated_tenant(self, tenant_id: str, token: str | None) -> None:
        """Bind one verified request credential to an isolated tenant queue."""

        normalized_tenant = tenant_id.strip()
        if not normalized_tenant:
            raise GatewayAuditDeliveryUnavailableError("authenticated audit tenant is unavailable")
        if self._tenant_registry is not None and not self._tenant_registry_available:
            raise GatewayAuditDeliveryUnavailableError("tenant audit routing registry is unavailable")
        if normalized_tenant == self._tenant_id:
            if token:
                self._token = token
            return
        if not self._tenant_routing_enabled or not token:
            raise GatewayAuditDeliveryUnavailableError("no tenant-bound audit credential is available")
        async with self._tenant_sinks_lock:
            sink = self._tenant_sinks.get(normalized_tenant)
            if sink is None:
                if len(self._tenant_sinks) >= self._max_tenant_sinks:
                    raise GatewayAuditDeliveryUnavailableError("tenant audit routing capacity is unavailable")
                if self._tenant_registry is None:
                    raise GatewayAuditDeliveryUnavailableError("tenant audit routing registry is unavailable")
                try:
                    self._tenant_registry.register(normalized_tenant)
                except Exception as exc:  # noqa: BLE001 - registry integrity is fail-closed
                    self._tenant_registry_available = False
                    logger.error("Gateway audit tenant registry unavailable (error_type=%s)", type(exc).__name__)
                    raise GatewayAuditDeliveryUnavailableError("tenant audit routing registry is unavailable") from None
                sink = build_control_plane_audit_sink(
                    self._base_url,
                    token,
                    tenant_id=normalized_tenant,
                    source_id=self._source_id,
                    sender=self._sender,
                    tenant_routing_enabled=False,
                    max_tenant_sinks=0,
                )
                self._tenant_sinks[normalized_tenant] = sink
                await sink.start()
            else:
                sink._token = token
                sink._remote_ack_available = True
                await sink.start()

    async def _recover_tenant_sinks(self) -> None:
        """Reconstruct unbound child queues so restart health remains truthful."""

        if self._tenant_registry is None or self._tenant_sinks:
            return
        try:
            tenant_ids = self._tenant_registry.discover()
            for tenant_id in tenant_ids:
                if tenant_id == self._tenant_id:
                    self._tenant_registry.unregister(tenant_id)
                    continue
                if len(self._tenant_sinks) >= self._max_tenant_sinks:
                    raise ValueError("gateway audit tenant registry exceeds configured capacity")
                sink = build_control_plane_audit_sink(
                    self._base_url,
                    None,
                    tenant_id=tenant_id,
                    source_id=self._source_id,
                    sender=self._sender,
                    tenant_routing_enabled=False,
                    max_tenant_sinks=0,
                )
                child_health = sink._own_health()
                if not _audit_health_has_pending_state(child_health):
                    self._tenant_registry.unregister(tenant_id)
                    continue
                sink._remote_ack_available = False
                self._tenant_sinks[tenant_id] = sink
        except Exception as exc:  # noqa: BLE001 - undiscoverable durable state is fail-closed
            self._tenant_registry_available = False
            logger.error("Gateway audit tenant registry recovery failed (error_type=%s)", type(exc).__name__)

    def _sink_for_event(self, event: dict[str, Any]) -> ControlPlaneAuditSink:
        if self._tenant_registry is not None and not self._tenant_registry_available:
            raise GatewayAuditDeliveryUnavailableError("tenant audit routing registry is unavailable")
        event_tenant = str(event.get("tenant_id") or "")
        if event_tenant == self._tenant_id:
            return self
        sink = self._tenant_sinks.get(event_tenant)
        if sink is None:
            raise GatewayAuditDeliveryUnavailableError("no tenant-bound audit credential is available")
        return sink

    @staticmethod
    def _batch_idempotency_key(session_id: str, events: list[dict[str, Any]]) -> str:
        event_identities = [
            str(event.get("event_id"))
            if event.get("event_id")
            else hashlib.sha256(json.dumps(event, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()
            for event in events
        ]
        material = json.dumps([session_id, event_identities], separators=(",", ":"), ensure_ascii=True)
        return "gateway-audit-" + hashlib.sha256(material.encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_acknowledgement(events: list[dict[str, Any]], response: dict[str, Any]) -> None:
        from agent_bom.runtime.gateway_events import GATEWAY_CANONICAL_EVENT_TYPES

        canonical_count = sum(str(event.get("event_type") or "") in GATEWAY_CANONICAL_EVENT_TYPES for event in events)
        durable_count = int(response.get("durable_accepted_count") or 0) + int(response.get("durable_duplicate_count") or 0)
        conflict_count = int(response.get("durable_conflict_count") or 0)
        accepted_count = int(response.get("accepted_alert_count") or 0) + int(response.get("duplicate_alert_count") or 0)
        if conflict_count or durable_count < canonical_count:
            raise RuntimeError("control plane did not durably acknowledge canonical gateway activity")
        if accepted_count < len(events):
            raise RuntimeError("control plane did not acknowledge the complete gateway audit batch")

    def _payload(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "source_id": self._source_id,
            "session_id": self._session_id,
            "idempotency_key": self._batch_idempotency_key(self._session_id, events),
            "alerts": events,
        }

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def _persist_and_flush(self, event: dict[str, Any], *, require_remote_ack: bool) -> None:
        async with self._lock:
            try:
                if not self._persistence_available:
                    raise GatewayAuditDeliveryUnavailableError("durable audit backlog is unavailable")
                event = canonicalize_gateway_enforcement_event(ensure_gateway_event_identity(event))
                event_tenant = str(event.get("tenant_id") or "")
                if event_tenant != self._tenant_id:
                    raise GatewayAuditDeliveryUnavailableError("audit credential is not bound to the event tenant")
                if self._delivery_state.store.dlq_size_bytes() or self._delivery_state.store.dropped_events:
                    self._persistence_available = False
                    raise GatewayAuditDeliveryUnavailableError("durable audit backlog is full")
                destination = self._delivery_state.store.append_events([event])
            except GatewayAuditDeliveryUnavailableError:
                raise
            except Exception as exc:  # noqa: BLE001 - local durability failure is fail-closed
                self._persistence_available = False
                logger.error("Gateway audit persistence unavailable (error_type=%s)", type(exc).__name__)
                raise GatewayAuditDeliveryUnavailableError("durable audit backlog is unavailable") from None
            if destination in {"dlq", "dropped"}:
                self._persistence_available = False
                raise GatewayAuditDeliveryUnavailableError("durable audit backlog is full")
            self._persistence_available = True
            flushed = False
            if not self._delivery_state.controller.is_circuit_open():
                flushed = await self._flush_locked()
            if not flushed and not self._persistence_available:
                raise GatewayAuditDeliveryUnavailableError("durable audit backlog is unavailable")
            if require_remote_ack and not flushed:
                raise GatewayAuditDeliveryUnavailableError("control-plane durable acknowledgement is unavailable")

    async def __call__(self, event: dict[str, Any]) -> None:
        sink = self._sink_for_event(event)
        if sink is not self:
            await sink(event)
            return
        await self._persist_and_flush(event, require_remote_ack=False)

    async def admit_before_tool_execution(self, event: dict[str, Any]) -> None:
        """Require the control plane to durably acknowledge before execution."""

        sink = self._sink_for_event(event)
        if sink is not self:
            await sink.admit_before_tool_execution(event)
            return
        await self._persist_and_flush(event, require_remote_ack=True)

    async def _flush_locked(self) -> bool:
        try:
            claim = self._delivery_state.store.claim_spillover()
        except Exception as exc:  # noqa: BLE001 - health must report local durability failure
            self._persistence_available = False
            logger.error("Gateway audit persistence unavailable during retry (error_type=%s)", type(exc).__name__)
            return False
        if claim is None:
            self._persistence_available = True
            return True
        if not claim.events:
            self._delivery_state.store.acknowledge_claim(claim)
            return True
        active_claim: AuditSpilloverClaim | None = claim
        try:
            while active_claim is not None:
                events = active_claim.events[:500]
                response = await self._sender(self._payload(events), self._headers())
                self._validate_acknowledgement(events, response)
                active_claim = self._delivery_state.store.acknowledge_claim_prefix(active_claim, len(events))
        except asyncio.CancelledError:
            if active_claim is not None:
                self._delivery_state.store.restore_claim(active_claim)
            raise
        except Exception as exc:  # noqa: BLE001 - retained backlog is retried
            try:
                if active_claim is not None:
                    self._delivery_state.store.restore_claim(active_claim)
            except Exception:  # noqa: BLE001 - do not leak persistence exception details
                self._persistence_available = False
                logger.error("Gateway audit persistence unavailable while retaining a failed delivery")
            self._delivery_state.controller.record_failure()
            self._remote_ack_available = False
            logger.warning("Gateway audit push failed; retained for retry (error_type=%s)", type(exc).__name__)
            return False
        self._persistence_available = True
        self._remote_ack_available = True
        self._delivery_state.controller.record_success()
        return True

    async def flush_once(self) -> bool:
        """Attempt one serialized backlog delivery, primarily for startup/tests."""

        async with self._lock:
            if self._delivery_state.controller.is_circuit_open():
                return False
            return await self._flush_locked()

    async def _retry_loop(self) -> None:
        while True:
            await asyncio.sleep(self._delivery_state.controller.current_backoff_seconds())
            await self.flush_once()

    async def start(self) -> None:
        """Recover a prior spill immediately, then maintain bounded retries."""

        if self._worker is not None:
            return
        self._closed = False
        await self._recover_tenant_sinks()
        await self.flush_once()
        self._worker = asyncio.create_task(self._retry_loop(), name="gateway-audit-delivery")

    async def aclose(self) -> None:
        self._closed = True
        children = list(self._tenant_sinks.items())
        for _tenant_id, child in children:
            await child.aclose()
        if self._tenant_registry is not None:
            for tenant_id, child in children:
                try:
                    child_health = child._own_health()
                    if not _audit_health_has_pending_state(child_health):
                        self._tenant_registry.unregister(tenant_id)
                except Exception as exc:  # noqa: BLE001 - shutdown remains secret-free
                    self._tenant_registry_available = False
                    logger.error("Gateway audit tenant registry cleanup failed (error_type=%s)", type(exc).__name__)
        if self._worker is None:
            return
        self._worker.cancel()
        try:
            await self._worker
        except asyncio.CancelledError:
            pass
        self._worker = None

    def _own_health(self) -> dict[str, str | int | bool]:
        try:
            health = self._delivery_state.health(buffer_bytes=0)
            backlog_observable = True
        except Exception:  # noqa: BLE001 - health remains secret-free and available
            self._persistence_available = False
            controller = self._delivery_state.controller
            health = {
                "status": "degraded",
                "buffer_bytes": 0,
                "spillover_bytes": 0,
                "dlq_bytes": 0,
                "backlog_bytes": 0,
                "consecutive_failures": controller.consecutive_failures,
                "backoff_seconds": controller.current_backoff_seconds(),
                "circuit_open": controller.is_circuit_open(),
                "dropped_events": self._delivery_state.store.dropped_events,
            }
            backlog_observable = False
        accepting_events = (
            self._persistence_available
            and self._remote_ack_available
            and not bool(health["dlq_bytes"])
            and not bool(health["dropped_events"])
        )
        if not accepting_events:
            health["status"] = "degraded"
        result: dict[str, str | int | bool] = {
            "configured": True,
            "durable": self._persistence_available and backlog_observable,
            "accepting_events": accepting_events,
            "backlog_observable": backlog_observable,
            "remote_acknowledgement_available": self._remote_ack_available,
            "retry_worker_running": self._worker is not None and not self._worker.done() and not self._closed,
            **health,
        }
        result["pending_audit_state"] = _audit_health_has_pending_state(result)
        return result

    def health(self) -> dict[str, str | int | bool]:
        health = self._own_health()
        child_health = [sink._own_health() for sink in self._tenant_sinks.values()]
        if child_health:
            all_health = [health, *child_health]
            health.update(
                {
                    "status": "degraded" if any(item["status"] != "healthy" for item in all_health) else "healthy",
                    "durable": all(bool(item["durable"]) for item in all_health),
                    "accepting_events": all(bool(item["accepting_events"]) for item in all_health),
                    "backlog_observable": all(bool(item["backlog_observable"]) for item in all_health),
                    "remote_acknowledgement_available": all(bool(item["remote_acknowledgement_available"]) for item in all_health),
                    "retry_worker_running": all(bool(item["retry_worker_running"]) for item in all_health),
                    "buffer_bytes": sum(int(item["buffer_bytes"]) for item in all_health),
                    "spillover_bytes": sum(int(item["spillover_bytes"]) for item in all_health),
                    "dlq_bytes": sum(int(item["dlq_bytes"]) for item in all_health),
                    "backlog_bytes": sum(int(item["backlog_bytes"]) for item in all_health),
                    "consecutive_failures": sum(int(item["consecutive_failures"]) for item in all_health),
                    "backoff_seconds": max(int(item["backoff_seconds"]) for item in all_health),
                    "circuit_open": any(bool(item["circuit_open"]) for item in all_health),
                    "dropped_events": sum(int(item["dropped_events"]) for item in all_health),
                    "pending_audit_state": any(_audit_health_has_pending_state(item) for item in all_health),
                    "tenant_sink_count": len(child_health) + 1,
                    "tenant_sink_capacity": self._max_tenant_sinks + 1,
                }
            )
        if self._tenant_registry is not None:
            health["tenant_registry_available"] = self._tenant_registry_available
            if not self._tenant_registry_available:
                health.update(
                    {
                        "status": "degraded",
                        "durable": False,
                        "accepting_events": False,
                        "backlog_observable": False,
                    }
                )
        return health


def build_control_plane_audit_sink(
    base_url: str,
    token: str | None,
    *,
    tenant_id: str = "default",
    source_id: str = "gateway",
    session_id: str | None = None,
    spill_path: Path | None = None,
    dlq_path: Path | None = None,
    max_spillover_bytes: int = _GATEWAY_AUDIT_SPILLOVER_BYTES,
    max_dlq_bytes: int = _GATEWAY_AUDIT_DLQ_BYTES,
    sender: GatewayAuditSender | None = None,
    tenant_routing_enabled: bool = True,
    max_tenant_sinks: int = _GATEWAY_AUDIT_MAX_TENANT_SINKS,
) -> ControlPlaneAuditSink:
    """Build the gateway's shared bounded control-plane audit delivery sink."""

    audit_url = base_url.rstrip("/") + "/v1/proxy/audit"
    normalized_tenant_id = tenant_id.strip()
    if not normalized_tenant_id:
        raise ValueError("gateway audit tenant_id must not be empty")
    if max_tenant_sinks < 0:
        raise ValueError("gateway audit max_tenant_sinks must not be negative")
    delivery_identity = f"{source_id}\0{audit_url}\0{normalized_tenant_id}"
    active_session_id = session_id or "gateway-" + hashlib.sha256(delivery_identity.encode("utf-8")).hexdigest()[:20]
    state_dir = state_home.state_dir()
    stable_paths = audit_delivery_paths(
        state_dir,
        surface="gateway",
        identity=delivery_identity,
    )
    active_spill_path = spill_path or stable_paths.spill_path
    active_dlq_path = dlq_path or stable_paths.dlq_path
    tenant_registry = (
        _GatewayAuditTenantRegistry(state_dir, source_id=source_id, audit_url=audit_url)
        if tenant_routing_enabled and max_tenant_sinks > 0
        else None
    )
    controller = AuditDeliveryController()
    store = AuditSpilloverStore(
        spill_path=active_spill_path,
        dlq_path=active_dlq_path,
        max_spillover_bytes=max_spillover_bytes,
        max_dlq_bytes=max_dlq_bytes,
    )

    active_sender: GatewayAuditSender
    if sender is None:

        async def _sender(payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
            return await _send_gateway_audit_batch(audit_url, payload, headers)

        active_sender = _sender
    else:
        active_sender = sender
    return ControlPlaneAuditSink(
        base_url=base_url,
        token=token,
        tenant_id=normalized_tenant_id,
        source_id=source_id,
        session_id=active_session_id,
        delivery_state=AuditDeliveryState(controller=controller, store=store),
        sender=active_sender,
        tenant_registry=tenant_registry,
        tenant_routing_enabled=tenant_routing_enabled,
        max_tenant_sinks=max_tenant_sinks,
    )
