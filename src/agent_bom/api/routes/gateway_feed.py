"""Gateway Live Feed — unified fleet event stream.

A single normalized, time-ordered stream that fuses three runtime surfaces the
platform already produces, with per-agent attribution:

    * tool-call authorization decisions  (allowed / blocked)  — proxy alert ring
      buffer + gateway audit events
    * data-filter / DLP redaction events  (PII / credential masking applied to
      tool responses)                                         — proxy alert ring
      buffer (credential_leak / pii detectors)
    * recent LLM calls                                          — observability
      cost store (priced OTel GenAI spans)

This module is read-only over those existing stores. It does NOT re-implement
enforcement, DLP, audit, or streaming — it consumes the in-process proxy alert
ring buffer (``agent_bom.api.routes.proxy``) and the cost store
(``agent_bom.api.cost_store``) and projects a unified, redaction-safe feed.

Endpoints:
    GET /v1/gateway/feed       normalized, time-ordered fused event list
    GET /v1/gateway/feed/kpis  KPI header rollup (calls / blocked / shadow-AI /
                               data filters)

All reads are RBAC-gated (``read`` permission), tenant-scoped, and
redaction-safe: only metadata (timestamps, agent identifiers, tool/target
names, action class, short non-secret detail strings) is returned. No raw
arguments, raw responses, or credential values cross this surface — the source
records are already sanitized by ``push_proxy_alert`` /
``redact_for_persistence`` before they reach the ring buffer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, cast

import anyio.to_thread
from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission
from agent_bom.runtime.gateway_events import (
    GATEWAY_ALLOWED_EVENT_TYPES,
    GATEWAY_BLOCKED_EVENT_TYPES,
    GATEWAY_DATA_FILTER_EVENT_TYPES,
)

router = APIRouter()

_FEED_SCHEMA_VERSION = "gateway.feed.v1"
_FEED_STALE_AFTER_SECONDS = 120


class GatewayFeedHealthModel(BaseModel):
    state: Literal["live", "stale", "unavailable", "sample"]
    live: bool
    heartbeat_at: str | None
    age_seconds: int | None
    stale_after_seconds: int
    reason: str


class GatewayFeedEventModel(BaseModel):
    event_id: str
    decision_id: str = Field(default="", max_length=200)
    ts: str
    agent: str
    identity_id: str = Field(default="", max_length=200)
    profile_id: str = Field(default="", max_length=200)
    profile_revision: int = Field(default=0, ge=0)
    blueprint_id: str = Field(default="", max_length=200)
    blueprint_revision: int = Field(default=0, ge=0)
    policy_ids: list[str] = Field(default_factory=list, max_length=200)
    reason_code: str = Field(default="", max_length=200)
    development_mode: bool = False
    action_type: Literal[
        "tool_call_authorized",
        "tool_call_blocked",
        "data_filter_applied",
        "llm_call",
    ]
    target: str
    upstream: str
    decision: str
    data_action: str
    policy_source: str
    trace_id: str
    detail: str
    tenant: str
    shadow: bool
    source: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None


class GatewayFeedResponseModel(BaseModel):
    schema_version: str
    tenant_id: str
    generated_at: str
    count: int
    events: list[GatewayFeedEventModel]
    health: GatewayFeedHealthModel


class GatewayFeedKpisModel(BaseModel):
    schema_version: str
    tenant_id: str
    generated_at: str
    calls_today: int
    blocked_today: int
    shadow_ai_blocked: int
    data_filters_applied: int
    tool_calls_authorized: int
    llm_calls: int
    uptime_seconds: float | None = None
    health: GatewayFeedHealthModel


# Action classes for a fused gateway feed event. Kept in sync with the badge
# vocabulary the UI renders.
ACTION_TOOL_CALL_AUTHORIZED = "tool_call_authorized"
ACTION_TOOL_CALL_BLOCKED = "tool_call_blocked"
ACTION_DATA_FILTER_APPLIED = "data_filter_applied"
ACTION_LLM_CALL = "llm_call"

# Block reasons that indicate a shadow / undeclared agent or shadow MCP server
# rather than an ordinary policy block. ``undeclared`` is emitted by the proxy
# block-undeclared enforcement (``proxy.undeclared_tool_block_reason``); the
# others cover unknown-agent / shadow-server gateway blocks.
_SHADOW_BLOCK_MARKERS = (
    "undeclared",
    "shadow",
    "unknown_agent",
    "unknown agent",
    "unregistered",
    "unknown-agent",
)


def _dep(permission: str) -> Any:
    return cast(Any, require_authenticated_permission(permission))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_gateway_feed_health(
    *,
    transport_enabled: bool,
    heartbeat_at: str | None,
    now: datetime | None = None,
    sample: bool = False,
    stale_after_seconds: int = _FEED_STALE_AFTER_SECONDS,
) -> dict[str, Any]:
    """Describe transport freshness independently from retained event presence."""
    checked_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    base: dict[str, Any] = {
        "state": "sample" if sample else "unavailable",
        "live": False,
        "heartbeat_at": heartbeat_at,
        "age_seconds": None,
        "stale_after_seconds": stale_after_seconds,
    }
    if sample:
        base["reason"] = "synthetic_sample"
        return base
    heartbeat = _parse_iso_timestamp(heartbeat_at)
    if not transport_enabled or heartbeat is None:
        base["reason"] = "transport_or_heartbeat_unavailable"
        return base

    age_delta = (checked_at - heartbeat).total_seconds()
    if age_delta < 0:
        base["reason"] = "transport_heartbeat_in_future"
        return base
    age_seconds = int(age_delta)
    base["age_seconds"] = age_seconds
    if age_seconds <= stale_after_seconds:
        base.update({"state": "live", "live": True, "reason": "recent_transport_heartbeat"})
    else:
        base.update({"state": "stale", "reason": "transport_heartbeat_stale"})
    return base


def _alert_timestamp(alert: dict[str, Any]) -> str:
    """Return a best-effort ISO-8601 timestamp for a proxy alert record.

    Proxy alerts carry either an epoch float ``ts`` or an ISO string
    ``timestamp`` / ``event_timestamp``. Normalize to ISO-8601 so all fused
    event sources sort on one comparable string key.
    """
    raw_ts = alert.get("ts")
    if isinstance(raw_ts, int | float) and raw_ts > 0:
        try:
            return datetime.fromtimestamp(float(raw_ts), tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            pass
    for key in ("timestamp", "event_timestamp", "received_at"):
        value = alert.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _sort_key(event: dict[str, Any]) -> str:
    """Sort key for fused events — newest first when reversed.

    Normalizes the ``ts`` ISO strings into a comparable form. Events without a
    timestamp sort last (oldest) by mapping to the empty string.
    """
    return str(event.get("ts") or "")


def _alert_agent(alert: dict[str, Any]) -> str:
    """Per-agent attribution for a proxy alert.

    Prefer the explicit agent name; fall back to source_id (the proxied agent
    process identifier) and finally to ``"unknown"`` so every event in the feed
    carries a visible actor.
    """
    for key in ("agent_name", "agent", "agent_id", "source_agent", "source_id"):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def _alert_target(alert: dict[str, Any]) -> str:
    for key in ("tool_name", "tool", "upstream", "target"):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def _bounded_alert_identifier(alert: dict[str, Any], key: str) -> str:
    value = alert.get(key)
    if not isinstance(value, str):
        return ""
    return value.strip()[:200]


def _alert_revision(alert: dict[str, Any], key: str) -> int:
    value = alert.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def _alert_policy_ids(alert: dict[str, Any]) -> list[str]:
    raw_policy_ids = alert.get("policy_ids")
    if not isinstance(raw_policy_ids, list | tuple):
        return []
    policy_ids: list[str] = []
    for value in raw_policy_ids:
        if not isinstance(value, str):
            continue
        normalized = value.strip()[:200]
        if normalized and normalized not in policy_ids:
            policy_ids.append(normalized)
        if len(policy_ids) == 200:
            break
    return policy_ids


def _is_shadow_block(alert: dict[str, Any]) -> bool:
    """True when a blocked event is a shadow / undeclared-agent or shadow-server block.

    Inspects the markers the proxy/gateway emit for undeclared tools and unknown
    agents. Free-text fields (``reason`` / ``message`` / ``action`` /
    ``details.reason``) are present on direct in-process alerts but are stripped
    by tier-A redaction before they reach the persisted ring buffer, so this
    also inspects the redaction-safe whitelisted fields (``event_type``,
    ``detector``, ``reason_code``, ``policy_source``, ``policy_result``,
    ``outcome``) that survive ``redact_for_persistence``. Used both to label
    feed events and to roll up the ``shadow_ai_blocked`` KPI.
    """
    details = alert.get("details")
    detail_reason = ""
    if isinstance(details, dict):
        detail_reason = str(details.get("reason") or details.get("block_reason") or "")
    haystack = " ".join(
        str(part).lower()
        for part in (
            detail_reason,
            # Free-text — survives on direct in-process alerts only.
            alert.get("reason"),
            alert.get("action"),
            alert.get("message"),
            # Redaction-safe (tier-A whitelist) — survives the ring buffer.
            alert.get("detector"),
            alert.get("event_type"),
            alert.get("reason_code"),
            alert.get("policy_source"),
            alert.get("policy_result"),
            alert.get("outcome"),
        )
        if part
    )
    return any(marker in haystack for marker in _SHADOW_BLOCK_MARKERS)


def _block_detail(alert: dict[str, Any]) -> str:
    details = alert.get("details")
    if isinstance(details, dict):
        reason = details.get("reason") or details.get("block_reason")
        if isinstance(reason, str) and reason.strip():
            return reason.strip()[:200]
    reason = alert.get("reason")
    if isinstance(reason, str) and reason.strip():
        return reason.strip()[:200]
    if _is_shadow_block(alert):
        return "shadow / undeclared agent blocked"
    # Redaction-safe coded reason survives the ring buffer when free text does not.
    reason_code = alert.get("reason_code")
    if isinstance(reason_code, str) and reason_code.strip():
        return reason_code.strip()[:200]
    return "blocked by gateway policy"


def _data_filter_detail(alert: dict[str, Any]) -> str:
    """Human-readable, secret-free detail for a DLP / redaction event.

    Surfaces what class of data was masked (e.g. "PII redacted",
    "credential masked") using the sanitized credential_type/pii_type metadata
    already present on the alert. Never returns raw matched values — the source
    record only retains redacted previews.
    """
    data_action = str(alert.get("data_action") or "").strip().lower()
    if data_action == "pii_redacted":
        return "PII redacted"
    if data_action == "visual_redacted":
        return "visual leak redacted"
    details = alert.get("details") if isinstance(alert.get("details"), dict) else {}
    detector = str(alert.get("detector") or "").lower()
    cred_type = ""
    pii_type = ""
    if isinstance(details, dict):
        cred_type = str(details.get("credential_type") or "")
        pii_type = str(details.get("pii_type") or details.get("pii_name") or "")
    if cred_type:
        return f"{cred_type} credential masked"
    if pii_type:
        return f"{pii_type} PII redacted"
    if "credential" in detector:
        return "credential masked"
    if "pii" in detector:
        return "PII redacted"
    if "visual" in detector:
        return "visual leak redacted"
    return "sensitive data masked"


def _classify_alert_action(alert: dict[str, Any]) -> str | None:
    """Map a proxy alert to a unified feed action class, or None to skip.

    Reuses the same decision vocabulary the proxy production index uses
    (``action`` / ``effective_decision`` / ``detector`` / ``message``) so this
    feed stays consistent with ``/v1/runtime/production-index``.
    """
    event_type = str(alert.get("event_type") or "").lower()
    if event_type in GATEWAY_DATA_FILTER_EVENT_TYPES or event_type == "gateway.visual_leak_blocked":
        return ACTION_DATA_FILTER_APPLIED
    if event_type in GATEWAY_BLOCKED_EVENT_TYPES:
        return ACTION_TOOL_CALL_BLOCKED
    if event_type in GATEWAY_ALLOWED_EVENT_TYPES:
        return ACTION_TOOL_CALL_AUTHORIZED

    # Backward-compatible inference for historical proxy-shaped events. New
    # standalone-gateway events are classified only by the exact types above.
    action = str(alert.get("action") or event_type or alert.get("type") or "").lower()
    detector = str(alert.get("detector") or "").lower()
    effective = str(alert.get("effective_decision") or alert.get("decision") or "").lower()
    message = str(alert.get("message") or "").lower()
    haystack = " ".join((action, detector, effective, message))

    if "redact" in haystack or "mask" in haystack or "data_filter" in haystack or "data filter" in haystack:
        return ACTION_DATA_FILTER_APPLIED
    if detector in {"credential_leak", "pii", "pii_leak"} or "leak" in detector:
        return ACTION_DATA_FILTER_APPLIED
    if "block" in haystack or "deny" in haystack or effective == "deny":
        return ACTION_TOOL_CALL_BLOCKED
    if "allow" in haystack or "authorized" in haystack or effective == "allow":
        return ACTION_TOOL_CALL_AUTHORIZED
    return None


def _normalize_alert_event(alert: dict[str, Any], tenant_id: str) -> dict[str, Any] | None:
    """Project one proxy alert into a normalized feed event, or None to skip."""
    action_type = _classify_alert_action(alert)
    if action_type is None:
        return None
    agent = _alert_agent(alert)
    target = _alert_target(alert)
    if action_type == ACTION_TOOL_CALL_BLOCKED:
        detail = _block_detail(alert)
        shadow = _is_shadow_block(alert)
    elif action_type == ACTION_DATA_FILTER_APPLIED:
        detail = _data_filter_detail(alert)
        shadow = False
    else:
        detail = "authorized"
        shadow = False
    return {
        "event_id": str(alert.get("event_id") or ""),
        "decision_id": _bounded_alert_identifier(alert, "decision_id"),
        "ts": _alert_timestamp(alert),
        "agent": agent,
        "identity_id": _bounded_alert_identifier(alert, "identity_id"),
        "profile_id": _bounded_alert_identifier(alert, "profile_id"),
        "profile_revision": _alert_revision(alert, "profile_revision"),
        "blueprint_id": _bounded_alert_identifier(alert, "blueprint_id"),
        "blueprint_revision": _alert_revision(alert, "blueprint_revision"),
        "policy_ids": _alert_policy_ids(alert),
        "reason_code": _bounded_alert_identifier(alert, "reason_code"),
        "development_mode": alert.get("development_mode") is True,
        "action_type": action_type,
        "target": target,
        "upstream": str(alert.get("upstream") or ""),
        "decision": str(alert.get("decision") or alert.get("outcome") or ""),
        "data_action": str(alert.get("data_action") or ""),
        "policy_source": str(alert.get("policy_source") or ""),
        "trace_id": str(alert.get("trace_id") or ""),
        "detail": detail,
        "tenant": tenant_id,
        "shadow": shadow,
        "source": "proxy",
    }


def _normalize_llm_event(record: Any, tenant_id: str) -> dict[str, Any]:
    """Project one priced LLM cost record into a normalized feed event."""
    provider = str(getattr(record, "provider", "") or "")
    model = str(getattr(record, "model", "") or "")
    target = "/".join(part for part in (provider, model) if part) or "llm"
    agent = str(getattr(record, "agent", "") or "").strip() or "unknown"
    cost = getattr(record, "cost_usd", 0.0)
    input_tokens = getattr(record, "input_tokens", 0) or 0
    output_tokens = getattr(record, "output_tokens", 0) or 0
    priced = bool(getattr(record, "priced", False))
    if priced and isinstance(cost, int | float) and cost > 0:
        detail = f"${float(cost):.4f} · {int(input_tokens) + int(output_tokens)} tokens"
    else:
        detail = f"{int(input_tokens) + int(output_tokens)} tokens"
    return {
        "event_id": "",
        "decision_id": "",
        "ts": str(getattr(record, "observed_at", "") or ""),
        "agent": agent,
        "identity_id": "",
        "profile_id": "",
        "profile_revision": 0,
        "blueprint_id": "",
        "blueprint_revision": 0,
        "policy_ids": [],
        "reason_code": "",
        "development_mode": False,
        "action_type": ACTION_LLM_CALL,
        "target": target,
        "upstream": "",
        "decision": "allow",
        "data_action": "",
        "policy_source": "observability",
        "trace_id": str(getattr(record, "trace_id", "") or ""),
        "detail": detail,
        "tenant": tenant_id,
        "shadow": False,
        "source": "observability",
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "cost_usd": float(cost) if priced and isinstance(cost, int | float) else None,
    }


def build_gateway_feed(
    *,
    tenant_id: str,
    alerts: list[dict[str, Any]],
    llm_records: list[Any],
    limit: int,
) -> dict[str, Any]:
    """Fuse and time-order proxy alerts + LLM cost records into one feed.

    Pure function (no I/O) so the normalization, ordering, tenant scoping, and
    redaction-safety can be unit-tested directly. ``alerts`` are expected to be
    pre-scoped to ``tenant_id`` by the caller (the proxy ring buffer enforces
    tenant visibility on read); LLM records come from the tenant-scoped cost
    store.
    """
    events: list[dict[str, Any]] = []
    for alert in alerts:
        event = _normalize_alert_event(alert, tenant_id)
        if event is not None:
            events.append(event)
    for record in llm_records:
        events.append(_normalize_llm_event(record, tenant_id))

    events.sort(key=_sort_key, reverse=True)
    bounded = events[:limit]
    return {
        "schema_version": _FEED_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "generated_at": _now_iso(),
        "count": len(bounded),
        "events": bounded,
    }


def build_gateway_feed_kpis(
    *,
    tenant_id: str,
    alerts: list[dict[str, Any]],
    llm_records: list[Any],
    uptime_seconds: float | None,
) -> dict[str, Any]:
    """Roll up the KPI header counters from the fused sources.

    Counters:
        * ``calls_today``          — authorized + blocked tool-call events + LLM
                                     calls (all gateway-mediated activity).
        * ``blocked_today``        — blocked tool-call events.
        * ``shadow_ai_blocked``    — subset of blocked events whose reason marks
                                     a shadow / undeclared agent or shadow MCP
                                     server (see ``_is_shadow_block``). Labeled
                                     accurately rather than overclaimed.
        * ``data_filters_applied`` — DLP / redaction events.
        * ``uptime_seconds``       — only emitted when the proxy reports it; never
                                     fabricated.

    ``_today`` reflects the live in-process window the ring buffer retains (the
    proxy alert deque + the day's cost records), not a wall-clock midnight cut —
    the label matches the operator-facing "today" framing without overstating
    retention.
    """
    authorized = 0
    blocked = 0
    shadow_blocked = 0
    data_filters = 0
    for alert in alerts:
        action_type = _classify_alert_action(alert)
        if action_type == ACTION_TOOL_CALL_AUTHORIZED:
            authorized += 1
        elif action_type == ACTION_TOOL_CALL_BLOCKED:
            blocked += 1
            if _is_shadow_block(alert):
                shadow_blocked += 1
        elif action_type == ACTION_DATA_FILTER_APPLIED:
            data_filters += 1

    llm_calls = len(llm_records)
    calls_today = authorized + blocked + llm_calls

    kpis: dict[str, Any] = {
        "schema_version": _FEED_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "generated_at": _now_iso(),
        "calls_today": calls_today,
        "blocked_today": blocked,
        "shadow_ai_blocked": shadow_blocked,
        "data_filters_applied": data_filters,
        "tool_calls_authorized": authorized,
        "llm_calls": llm_calls,
    }
    if isinstance(uptime_seconds, int | float) and uptime_seconds > 0:
        kpis["uptime_seconds"] = float(uptime_seconds)
    return kpis


def _load_tenant_alerts(tenant_id: str) -> list[dict[str, Any]]:
    """Read tenant-scoped proxy alerts from the existing ring buffer / log.

    Delegates to ``proxy._load_proxy_alerts`` which already enforces per-tenant
    visibility and reads the configured audit log when the in-process buffer is
    empty. This module never mutates that buffer.

    Synchronous by design — callers on the event loop must use
    :func:`_load_tenant_alerts_async`.
    """
    from agent_bom.api.routes.proxy import _load_proxy_alerts

    return _load_proxy_alerts(tenant_id)


async def _gather_feed_inputs_async(tenant_id: str, *, limit: int) -> tuple[list[dict[str, Any]], list[Any]]:
    """Load every synchronous feed input off the event loop, in one hop.

    Both the audit-log fallback and the cost-store read are blocking; offloading
    only one still left the loop stalled for hundreds of milliseconds.
    """

    def _gather() -> tuple[list[dict[str, Any]], list[Any]]:
        return _load_tenant_alerts(tenant_id), _load_tenant_llm_records(tenant_id, limit=limit)

    return await anyio.to_thread.run_sync(_gather)


async def _load_tenant_alerts_async(tenant_id: str) -> list[dict[str, Any]]:
    """Off-loop variant for async routes.

    The audit-log fallback opens a JSONL file and parses up to _MAX_LOG_LINES
    records, redacting each one. Called inline from an ``async def`` handler
    that froze the entire process -- measured at several seconds on a large log,
    stalling every other tenant's request and every background task, not just
    this one. AGENT_BOM_LOG is a shipped deployment surface, so this is reachable
    in a normal install.
    """
    return await anyio.to_thread.run_sync(_load_tenant_alerts, tenant_id)


def _load_tenant_uptime(tenant_id: str) -> float | None:
    """Best-effort proxy uptime for the tenant, or None when unreported."""
    from agent_bom.api.routes.proxy import _runtime_metrics_for_tenant

    metrics = _runtime_metrics_for_tenant(tenant_id)
    if not isinstance(metrics, dict):
        return None
    raw = metrics.get("uptime_seconds")
    if isinstance(raw, int | float) and raw > 0:
        return float(raw)
    return None


def _load_tenant_transport_metrics(tenant_id: str) -> dict[str, Any] | None:
    """Return the tenant's latest transport metrics/heartbeat, when reported."""
    from agent_bom.api.routes.proxy import _runtime_metrics_for_tenant

    metrics = _runtime_metrics_for_tenant(tenant_id)
    return metrics if isinstance(metrics, dict) else None


def _feed_health_from_metrics(metrics: dict[str, Any] | None) -> dict[str, Any]:
    if not metrics:
        return build_gateway_feed_health(transport_enabled=False, heartbeat_at=None)
    source_id = str(metrics.get("source_id") or "")
    session_id = str(metrics.get("session_id") or "")
    sample = source_id.startswith("demo-estate") or session_id.startswith("demo-estate")
    # ``received_at`` is stamped by the server at ingestion. Client event
    # timestamps remain useful provenance, but are not transport heartbeats.
    heartbeat = metrics.get("received_at")
    return build_gateway_feed_health(
        transport_enabled=True,
        heartbeat_at=str(heartbeat) if heartbeat else None,
        sample=sample,
    )


def _load_tenant_llm_records(tenant_id: str, *, limit: int) -> list[Any]:
    """Read recent priced LLM cost records for the tenant (read-only)."""
    try:
        from agent_bom.api.cost_store import get_cost_store

        return list(get_cost_store().list_records(tenant_id, limit=limit))
    except Exception:  # noqa: BLE001 — cost store is optional; feed degrades to proxy-only
        return []


@router.get(
    "/gateway/feed",
    tags=["gateway"],
    dependencies=[_dep("read")],
    response_model=GatewayFeedResponseModel,
)
async def gateway_feed(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500, description="Max fused events to return (1-500)"),
) -> dict[str, Any]:
    """Unified, time-ordered fleet event feed for the active tenant.

    Fuses tool-call authorization decisions (allowed / blocked), data-filter /
    DLP redaction events, and recent LLM calls into one normalized stream with
    per-agent attribution. Reference-only and redaction-safe: every event is
    metadata (timestamp, agent, action class, target, short non-secret detail);
    no raw arguments, responses, or credential values are returned.
    """
    tenant_id = require_request_tenant_id(request)
    alerts, llm_records = await _gather_feed_inputs_async(tenant_id, limit=limit)
    payload = build_gateway_feed(
        tenant_id=tenant_id,
        alerts=alerts,
        llm_records=llm_records,
        limit=limit,
    )
    payload["health"] = _feed_health_from_metrics(await anyio.to_thread.run_sync(_load_tenant_transport_metrics, tenant_id))
    return payload


@router.get(
    "/gateway/feed/kpis",
    tags=["gateway"],
    dependencies=[_dep("read")],
    response_model=GatewayFeedKpisModel,
)
async def gateway_feed_kpis(request: Request) -> dict[str, Any]:
    """KPI header rollup for the gateway live feed.

    Returns ``calls_today``, ``blocked_today``, ``shadow_ai_blocked`` (shadow /
    undeclared-agent + shadow-MCP-server blocks), ``data_filters_applied``, and
    ``uptime_seconds`` (only when the proxy reports it — never fabricated).
    """
    tenant_id = require_request_tenant_id(request)
    alerts, llm_records = await _gather_feed_inputs_async(tenant_id, limit=10000)
    uptime_seconds = await anyio.to_thread.run_sync(_load_tenant_uptime, tenant_id)
    payload = build_gateway_feed_kpis(
        tenant_id=tenant_id,
        alerts=alerts,
        llm_records=llm_records,
        uptime_seconds=uptime_seconds,
    )
    payload["health"] = _feed_health_from_metrics(await anyio.to_thread.run_sync(_load_tenant_transport_metrics, tenant_id))
    return payload
