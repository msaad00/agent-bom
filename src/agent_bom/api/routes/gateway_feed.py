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
from typing import Any, cast

from fastapi import APIRouter, Query, Request

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission

router = APIRouter()

_FEED_SCHEMA_VERSION = "gateway.feed.v1"

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
    for key in ("agent_name", "agent", "source_agent", "source_id"):
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
    action = str(alert.get("action") or alert.get("event_type") or alert.get("type") or "").lower()
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
        "ts": _alert_timestamp(alert),
        "agent": agent,
        "action_type": action_type,
        "target": target,
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
        "ts": str(getattr(record, "observed_at", "") or ""),
        "agent": agent,
        "action_type": ACTION_LLM_CALL,
        "target": target,
        "detail": detail,
        "tenant": tenant_id,
        "shadow": False,
        "source": "observability",
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
    """
    from agent_bom.api.routes.proxy import _load_proxy_alerts

    return _load_proxy_alerts(tenant_id)


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


def _load_tenant_llm_records(tenant_id: str, *, limit: int) -> list[Any]:
    """Read recent priced LLM cost records for the tenant (read-only)."""
    try:
        from agent_bom.api.cost_store import get_cost_store

        return list(get_cost_store().list_records(tenant_id, limit=limit))
    except Exception:  # noqa: BLE001 — cost store is optional; feed degrades to proxy-only
        return []


@router.get("/gateway/feed", tags=["gateway"], dependencies=[_dep("read")])
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
    alerts = _load_tenant_alerts(tenant_id)
    llm_records = _load_tenant_llm_records(tenant_id, limit=limit)
    return build_gateway_feed(
        tenant_id=tenant_id,
        alerts=alerts,
        llm_records=llm_records,
        limit=limit,
    )


@router.get("/gateway/feed/kpis", tags=["gateway"], dependencies=[_dep("read")])
async def gateway_feed_kpis(request: Request) -> dict[str, Any]:
    """KPI header rollup for the gateway live feed.

    Returns ``calls_today``, ``blocked_today``, ``shadow_ai_blocked`` (shadow /
    undeclared-agent + shadow-MCP-server blocks), ``data_filters_applied``, and
    ``uptime_seconds`` (only when the proxy reports it — never fabricated).
    """
    tenant_id = require_request_tenant_id(request)
    alerts = _load_tenant_alerts(tenant_id)
    llm_records = _load_tenant_llm_records(tenant_id, limit=10000)
    uptime_seconds = _load_tenant_uptime(tenant_id)
    return build_gateway_feed_kpis(
        tenant_id=tenant_id,
        alerts=alerts,
        llm_records=llm_records,
        uptime_seconds=uptime_seconds,
    )
