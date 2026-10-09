"""Shared state and control-plane plumbing for one stdio proxy session.

``run_proxy`` composes a :class:`ProxySession` once and hands it to the relay
stages in :mod:`agent_bom.runtime.proxy_relay`. Names that live on
:mod:`agent_bom.proxy` are resolved through that module at call time so that
its public helpers (and the test seams patched on it) stay authoritative.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

from agent_bom.security import sanitize_text

if TYPE_CHECKING:
    from agent_bom.proxy_audit import ProxyMetrics, RotatingAuditLog
    from agent_bom.proxy_scanner import ScanConfig

PENDING_CALL_TTL_SECONDS = 300.0


@dataclass
class RuntimeDetectors:
    """The per-session runtime detectors, built once from the CLI flags and policy."""

    drift: Any
    arguments: Any
    credentials: Any
    visual: Any
    rate: Any
    sequence: Any
    response: Any
    vector: Any
    replay: Any
    local_policy_rate_limit: int | None


@dataclass(frozen=True)
class RelayOptions:
    """Operator choices that shape relay decisions; fixed for the session."""

    block_undeclared: bool
    log_only: bool
    rate_limit_threshold: int
    alert_webhook: str | None
    response_signing_key: str | None
    policy_refresh_seconds: int


@dataclass
class ControlPlane:
    """Control-plane identity and the policy bundle pulled from it."""

    url: str | None
    token: str | None
    tenant_id: str
    source_id: str
    session_id: str
    cache_path: Path
    cache_max_age_seconds: int
    policies: list[Any] = field(default_factory=list)
    etag: str | None = None


@dataclass
class ProxySession:
    """Everything one proxied stdio server session reads and mutates.

    ``host`` is the :mod:`agent_bom.proxy` module that composed the session.
    Proxy-owned helpers and evaluators are resolved through it at call time,
    which keeps that module authoritative without an import cycle.
    """

    host: ModuleType
    policy: dict
    log_file: RotatingAuditLog | None
    metrics: ProxyMetrics
    detectors: RuntimeDetectors
    scan_config: ScanConfig
    options: RelayOptions
    control: ControlPlane
    audit: Any
    audit_buffer: list[dict] = field(default_factory=list)
    audit_buffer_bytes: int = 0
    audit_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    runtime_alerts: list[dict] = field(default_factory=list)
    declared_tools: set[str] = field(default_factory=set)
    tools_list_request_ids: set[int | str] = field(default_factory=set)
    pending_calls: dict[int | str, tuple[str, float, dict[str, str]]] = field(default_factory=dict)
    pending_call_ttl: float = PENDING_CALL_TTL_SECONDS
    process: asyncio.subprocess.Process | None = None

    def pending_tool(self, msg: dict) -> str:
        """Tool name of the in-flight call this response answers, or ``""``."""
        resp_id = msg.get("id")
        if resp_id is not None and resp_id in self.pending_calls:
            return self.pending_calls[resp_id][0]
        return ""

    def sync_audit_metrics(self) -> None:
        health = self.audit.state.health(buffer_bytes=self.audit_buffer_bytes)
        self.metrics.set_audit_buffer_bytes(int(health["buffer_bytes"]))
        self.metrics.set_audit_spillover_bytes(int(health["spillover_bytes"]))
        self.metrics.set_audit_dlq_bytes(int(health["dlq_bytes"]))
        self.metrics.set_audit_push_backoff_seconds(int(health["backoff_seconds"]))
        self.metrics.set_audit_circuit_open(bool(health["circuit_open"]))

    async def queue_control_plane_alert(self, alert_payload: dict) -> None:
        event_size = len(json.dumps(alert_payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        async with self.audit_lock:
            if self.audit_buffer_bytes + event_size <= self.audit.max_buffer_bytes:
                self.audit_buffer.append(alert_payload)
                self.audit_buffer_bytes += event_size
            else:
                self._spill_alert(alert_payload)
            self.sync_audit_metrics()

    def _spill_alert(self, alert_payload: dict) -> None:
        destination = self.audit.spillover.append_events([alert_payload])
        if destination == "dlq":
            self.host.logger.error(
                "Proxy audit spillover exceeded %s bytes; diverting alert backlog to DLQ %s",
                self.audit.max_spillover_bytes,
                self.audit.dlq_path,
            )
        elif destination == "dropped":
            self.host.logger.error(
                "Proxy audit spillover and DLQ are full; dropping one sanitized audit event",
            )
        else:
            self.host.logger.warning(
                "Proxy audit buffer exceeded %s bytes; spilling alert backlog to %s",
                self.audit.max_buffer_bytes,
                self.audit.spill_path,
            )

    async def handle_alerts(self, alerts: Any, log_f: Any = None) -> None:
        """Log alerts and optionally record them + dispatch webhook."""
        for alert in alerts:
            alert_dict = alert.to_dict()
            self.runtime_alerts.append(alert_dict)
            self.host.logger.warning("Runtime alert: %s", sanitize_text(alert_dict.get("message", "runtime alert")))
            if log_f:
                self.host.write_audit_record(log_f, alert_dict)
                log_f.flush()
            if self.options.alert_webhook:
                self.host._fire_webhook(self.options.alert_webhook, alert_dict)
            if self.control.url:
                enriched = dict(alert_dict)
                enriched.setdefault("source_id", self.control.source_id)
                enriched.setdefault("session_id", self.control.session_id)
                await self.queue_control_plane_alert(enriched)

    async def refresh_control_plane_policies(self, initial: bool = False) -> None:
        control = self.control
        if not control.url:
            return
        try:
            policies, next_etag = await self.host._fetch_enabled_gateway_policies(control.url, control.token, control.etag)
        except Exception as exc:  # noqa: BLE001
            self.metrics.record_policy_fetch_failure()
            if not initial:
                self.host.logger.warning("Gateway policy refresh failed: %s", sanitize_text(exc))
                return
            self._fall_back_to_cached_policies(exc)
            self._apply_control_plane_rate_limit()
            return
        if policies is not None:
            control.policies = policies
            self.host._persist_gateway_policies_cache(control.cache_path, policies, next_etag)
        if next_etag:
            control.etag = next_etag
        self._apply_control_plane_rate_limit()

    def _fall_back_to_cached_policies(self, exc: Exception) -> None:
        control = self.control
        cached_policies, cached_etag = self.host._load_cached_gateway_policies(control.cache_path, control.cache_max_age_seconds)
        if cached_policies is None:
            self.host.logger.error("Failed to load enabled gateway policies from %s: %s", control.url, sanitize_text(exc))
            raise SystemExit(1) from exc
        control.policies = cached_policies
        control.etag = cached_etag
        self.host.logger.warning(
            "Gateway policy fetch failed from %s; using cached bundle from %s: %s",
            control.url,
            control.cache_path,
            sanitize_text(exc),
        )

    def _apply_control_plane_rate_limit(self) -> None:
        if self.options.rate_limit_threshold > 0:
            return
        control_plane_limit = self.host._resolve_control_plane_rate_limit_threshold(self.control.policies)
        if control_plane_limit and control_plane_limit > 0:
            self.detectors.rate._threshold = control_plane_limit
        else:
            self.detectors.rate._threshold = self.detectors.local_policy_rate_limit or 0

    async def flush_audit_buffer(self, summary: dict | None = None) -> bool:
        if not self.control.url:
            return True
        async with self.audit_lock:
            alerts = list(self.audit_buffer)
            spillover_claim = self.audit.spillover.claim_spillover()
            self.audit_buffer.clear()
            self.audit_buffer_bytes = 0
            self.sync_audit_metrics()
        spillover_alerts = spillover_claim.events if spillover_claim else []
        combined_alerts = spillover_alerts + alerts
        if not combined_alerts and summary is None:
            return True
        try:
            await self.host._push_proxy_audit_batch(
                self.control.url,
                self.control.token,
                self.control.source_id,
                self.control.session_id,
                combined_alerts,
                summary,
            )
        except Exception as exc:  # noqa: BLE001
            self.metrics.record_audit_push_failure()
            self.host.logger.warning("Proxy audit push failed: %s", sanitize_text(exc))
            await self._restore_failed_batch(spillover_claim, alerts)
            return False
        if spillover_claim is not None:
            self.audit.spillover.acknowledge_claim(spillover_claim)
        self.sync_audit_metrics()
        return True

    async def _restore_failed_batch(self, spillover_claim: Any, alerts: list[dict]) -> None:
        async with self.audit_lock:
            if spillover_claim is not None:
                destination = self.audit.spillover.restore_claim(spillover_claim, alerts)
            else:
                destination = self.audit.spillover.append_events(alerts)
            if destination == "dlq":
                self.host.logger.error("Proxy audit retry backlog exceeded the spill limit; persisted the batch to the bounded DLQ")
            elif destination == "dropped":
                self.host.logger.error("Proxy audit spillover and DLQ are full; a failed delivery batch was dropped")
            self.sync_audit_metrics()

    async def policy_refresh_loop(self) -> None:
        if not self.control.url:
            return
        while True:
            await asyncio.sleep(max(self.options.policy_refresh_seconds, 5))
            await self.refresh_control_plane_policies()

    async def audit_push_loop(self) -> None:
        if not self.control.url:
            return
        delivery = self.audit.controller
        while True:
            await asyncio.sleep(delivery.current_backoff_seconds())
            if delivery.is_circuit_open():
                self.sync_audit_metrics()
                continue
            if await self.flush_audit_buffer():
                delivery.record_success()
            else:
                delivery.record_failure()
            self.sync_audit_metrics()

    async def connect_control_plane(self) -> None:
        """Pull the initial policy bundle and install it as the gateway evaluator."""
        if not self.control.url:
            return
        await self.refresh_control_plane_policies(initial=True)
        control = self.control

        def _control_plane_gateway_evaluator(agent_id, tool_name, arguments):  # noqa: ANN001, ANN202
            from agent_bom.gateway import evaluate_gateway_policy_bundle

            return evaluate_gateway_policy_bundle(control.policies, agent_id, tool_name, arguments)

        self.host.set_gateway_evaluator(_control_plane_gateway_evaluator)


def start_metrics(host: ModuleType) -> tuple[ProxyMetrics, bool]:
    """Create session metrics and attach the CLI status strip when it is active."""
    from agent_bom.cli._runtime_status import proxy_metrics_status_callback

    metrics = host.ProxyMetrics()
    status_strip_active, status_update = proxy_metrics_status_callback(surface="proxy")
    if status_strip_active:
        metrics.set_update_callback(status_update)
        status_update(metrics)
    return metrics, status_strip_active


def build_detectors(
    host: ModuleType, policy: dict, *, detect_credentials: bool, detect_visual_leaks: bool, rate_limit_threshold: int
) -> RuntimeDetectors:
    """Instantiate the runtime detectors; visual leak detection fails closed without OCR."""
    from agent_bom.runtime.detectors import (
        ArgumentAnalyzer,
        CredentialLeakDetector,
        RateLimitTracker,
        ResponseInspector,
        SequenceAnalyzer,
        ToolDriftDetector,
        VectorDBInjectionDetector,
    )

    drift_detector = ToolDriftDetector()
    arg_analyzer = ArgumentAnalyzer()
    cred_detector = CredentialLeakDetector() if detect_credentials else None
    visual_detector = None
    if detect_visual_leaks:
        from agent_bom.runtime.visual_leak_detector import VisualLeakDetector, require_visual_leak_runtime

        require_visual_leak_runtime()
        visual_detector = VisualLeakDetector()
    local_policy_rate_limit = host.resolve_rate_limit_threshold(policy) if policy else None
    effective_rate_limit_threshold = rate_limit_threshold or local_policy_rate_limit or 0
    return RuntimeDetectors(
        drift=drift_detector,
        arguments=arg_analyzer,
        credentials=cred_detector,
        visual=visual_detector,
        rate=RateLimitTracker(threshold=max(effective_rate_limit_threshold, 0)),
        sequence=SequenceAnalyzer(),
        response=ResponseInspector(),
        vector=VectorDBInjectionDetector(),
        replay=host.ReplayDetector(),
        local_policy_rate_limit=local_policy_rate_limit,
    )
