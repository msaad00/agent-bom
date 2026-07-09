"""Curated runtime gateway feed for the demo estate.

The showcase graph, findings, and CIS posture render on the demo, but the
runtime gateway / proxy / firewall dashboards read from live in-process runtime
stores that a demo deployment never populates (no real proxy traffic flows).
This module seeds a small, deterministic, tenant-scoped set of AI-firewall
events into those exact stores so a visitor to the hosted demo SEES the gateway
in action: authorized tool calls, policy blocks, shadow / undeclared-agent
blocks, and credential / PII data-filter redactions.

Stores seeded (all the ones the gateway/proxy/runtime dashboards read):

    * proxy alert ring buffer (``agent_bom.api.routes.proxy.push_proxy_alert``)
      — backs ``/v1/gateway/feed``, ``/v1/gateway/feed/kpis``,
      ``/v1/proxy/alerts`` and ``/v1/runtime/production-index``.
    * proxy metrics summary (``push_proxy_metrics``) — backs
      ``/v1/proxy/status`` and the traffic/uptime rollup in
      ``/v1/runtime/production-index``.
    * firewall decision store (``FirewallDecisionStore.record``) — backs
      ``/v1/firewall/stats`` and the ``firewall_runtime`` block of
      ``/v1/gateway/stats``.

Events reuse the demo estate's real agent / server / tool names so the feed is
consistent with the showcase graph. Everything is deterministic (a fixed time
anchor, no wall-clock or randomness) and idempotent (re-running detects the
demo marker and skips) so repeated bootstraps do not inflate the counters.

The event records are shaped exactly like alerts ingested through
``/v1/proxy/audit`` (they are pushed through ``push_proxy_alert``, which applies
the same secret-sanitization + evidence-tier redaction), so the classification
fields the feed relies on (``event_type``, ``detector``, ``decision``,
``reason_code``, ``agent_name``, ``tool_name``) survive redaction — free-text
fields intentionally do not.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

_logger = logging.getLogger(__name__)

# Marker written onto every seeded alert so the seeding is idempotent and so the
# events are unmistakably demo data (never mixed with real ingested traffic).
_DEMO_SOURCE_ID = "demo-estate-gateway"

# Fixed time anchor — deterministic across runs (no Date.now / randomness). The
# gateway KPI counters and feed are windowed by ring-buffer contents, not a
# wall-clock midnight cut, so a fixed anchor still reads as recent activity.
_ANCHOR = datetime(2026, 7, 6, 15, 30, 0, tzinfo=timezone.utc)


def _ts(minutes_ago: int) -> str:
    """ISO-8601 timestamp ``minutes_ago`` before the fixed anchor."""
    return (_ANCHOR - timedelta(minutes=minutes_ago)).isoformat()


def _epoch(minutes_ago: int) -> float:
    return (_ANCHOR - timedelta(minutes=minutes_ago)).timestamp()


# ── Curated feed ────────────────────────────────────────────────────────────
#
# Each tuple: (minutes_ago, agent_name, tool_name, event_type, detector,
#              decision, reason_code, severity). ``event_type`` + ``detector`` +
# ``decision`` + ``reason_code`` are the redaction-safe fields the gateway feed
# classifier reads; agent_name / tool_name provide per-event attribution.
_AUTHORIZED = "tool_call_authorized"
_BLOCKED = "tool_call_blocked"
_DATA_FILTER = "data_filter_applied"

_FEED_EVENTS: tuple[tuple[int, str, str, str, str, str, str, str], ...] = (
    # ── authorized tool calls (agent -> server.tool) ──
    (1, "Cursor IDE Agent", "filesystem-server.read_file", _AUTHORIZED, "policy", "allow", "policy_allow", "info"),
    (3, "Claude Desktop Agent", "github-server.create_issue", _AUTHORIZED, "policy", "allow", "policy_allow", "info"),
    (5, "Support Copilot", "helpdesk-server.create_ticket", _AUTHORIZED, "policy", "allow", "policy_allow", "info"),
    (7, "LangChain Service Agent", "vector-db-server.query_vectors", _AUTHORIZED, "policy", "allow", "policy_allow", "info"),
    (9, "Data Pipeline Agent", "warehouse-server.run_query", _AUTHORIZED, "policy", "allow", "policy_allow", "info"),
    (12, "Claude Desktop Agent", "team-chat-server.send_message", _AUTHORIZED, "policy", "allow", "policy_allow", "info"),
    (15, "Support Copilot", "email-server.list_inbox", _AUTHORIZED, "policy", "allow", "policy_allow", "info"),
    (19, "Cursor IDE Agent", "filesystem-server.list_directory", _AUTHORIZED, "policy", "allow", "policy_allow", "info"),
    # ── credential / PII data-filter redactions ──
    (4, "Support Copilot", "helpdesk-server.search_tickets", _DATA_FILTER, "credential_leak", "allow", "aws_key_masked", "medium"),
    (10, "Claude Desktop Agent", "team-chat-server.send_message", _DATA_FILTER, "pii", "allow", "email_pii_redacted", "medium"),
    (16, "Data Pipeline Agent", "warehouse-server.export_csv", _DATA_FILTER, "credential_leak", "allow", "db_password_masked", "medium"),
    # ── policy blocks (destructive / disallowed tool calls) ──
    (6, "Data Pipeline Agent", "warehouse-server.execute_sql", _BLOCKED, "policy", "deny", "destructive_sql_denied", "high"),
    (11, "Cursor IDE Agent", "shell-runner-server.run_shell", _BLOCKED, "policy", "deny", "destructive_command_blocked", "high"),
    (14, "Support Copilot", "email-server.send_email", _BLOCKED, "policy", "deny", "external_recipient_blocked", "medium"),
    # ── shadow / undeclared-agent blocks (the AI-firewall differentiator) ──
    (8, "shadow-agent (unregistered)", "warehouse-server.export_csv", _BLOCKED, "undeclared_agent", "deny", "undeclared_agent_blocked", "critical"),  # noqa: E501
    (13, "shadow-agent (unregistered)", "shell-runner-server.exec_command", _BLOCKED, "shadow_mcp", "deny", "shadow_server_blocked", "critical"),  # noqa: E501
    # ── rate-limit / replay protection blocks ──
    (17, "LangChain Service Agent", "llm-orchestrator-server.http_get", _BLOCKED, "rate_limit", "deny", "rate_limited", "medium"),
    (20, "shadow-agent (unregistered)", "github-server.push_files", _BLOCKED, "replay", "deny", "replay_blocked", "high"),
)

# ── Inter-agent firewall decisions (source_agent -> target_agent) ───────────
# Backs /v1/firewall/stats and gateway/stats.firewall_runtime. effective ==
# decision here (no dry-run downgrade in the demo). matched_rule mirrors the
# AgentFirewallPolicy rule payload shape (source/target/decision/description).
_FIREWALL_DECISIONS: tuple[tuple[int, str, str, str, dict[str, Any] | None], ...] = (
    (2, "Cursor IDE Agent", "github-server", "allow", None),
    (5, "LangChain Service Agent", "vector-db-server", "allow", None),
    (9, "Claude Desktop Agent", "team-chat-server", "allow", None),
    (
        13,
        "Support Copilot",
        "email-server",
        "warn",
        {"source": "Support Copilot", "target": "email-server", "decision": "warn", "description": "external email requires review"},
    ),
    (
        6,
        "Data Pipeline Agent",
        "warehouse-server",
        "deny",
        {"source": "Data Pipeline Agent", "target": "warehouse-server", "decision": "deny", "description": "bulk export blocked"},
    ),
    (
        8,
        "shadow-agent (unregistered)",
        "warehouse-server",
        "deny",
        {"source": "*", "target": "warehouse-server", "decision": "deny", "description": "undeclared source agent"},
    ),
)


def _proxy_metrics_summary(tenant_id: str) -> dict[str, Any]:
    """Believable traffic / uptime rollup for the proxy + runtime dashboards.

    Numbers are a curated day of activity — larger than the visible feed sample
    (the feed shows the most recent events; the rollup reflects the day) but
    internally consistent (block reasons match feed reason codes).
    """
    calls_by_tool = {
        "read_file": 312,
        "query_vectors": 208,
        "create_ticket": 141,
        "run_query": 189,
        "create_issue": 74,
        "send_message": 96,
        "list_inbox": 52,
        "search_tickets": 67,
        "http_get": 88,
        "run_shell": 18,
        "execute_sql": 23,
        "export_csv": 31,
    }
    blocked_by_reason = {
        "destructive_command_blocked": 9,
        "destructive_sql_denied": 6,
        "external_recipient_blocked": 5,
        "undeclared_agent_blocked": 4,
        "shadow_server_blocked": 3,
        "rate_limited": 7,
        "replay_blocked": 2,
    }
    total_tool_calls = sum(calls_by_tool.values())
    total_blocked = sum(blocked_by_reason.values())
    return {
        "tenant_id": tenant_id,
        "source_id": _DEMO_SOURCE_ID,
        "session_id": "demo-estate",
        "received_at": _ts(0),
        "ts": _ts(0),
        "uptime_seconds": 356_400.0,  # ~4.1 days
        "total_tool_calls": total_tool_calls,
        "total_blocked": total_blocked,
        "calls_by_tool": calls_by_tool,
        "blocked_by_reason": blocked_by_reason,
        "latency": {"p50_ms": 11.0, "p95_ms": 42.0},
    }


def _tenant_has_demo_gateway_events(tenant_id: str) -> bool:
    """True when this tenant's proxy alert buffer already holds the demo feed."""
    from agent_bom.api.routes.proxy import _load_proxy_alerts

    for alert in _load_proxy_alerts(tenant_id):
        if str(alert.get("source_id") or "") == _DEMO_SOURCE_ID:
            return True
    return False


def seed_showcase_gateway_events(*, tenant_id: str = SHOWCASE_TENANT) -> dict[str, Any]:
    """Seed the curated runtime gateway feed for the demo tenant (idempotent)."""
    from agent_bom.api.routes.proxy import push_proxy_alert, push_proxy_metrics
    from agent_bom.api.stores import _get_firewall_decision_store

    if _tenant_has_demo_gateway_events(tenant_id):
        return {"seeded": False, "reason": "already_present", "tenant_id": tenant_id}

    authorized = blocked = data_filters = shadow_blocked = 0
    for (minutes_ago, agent_name, tool_name, event_type, detector, decision, reason_code, severity) in _FEED_EVENTS:
        alert = {
            "event_id": f"{_DEMO_SOURCE_ID}:{minutes_ago}:{tool_name}",
            "ts": _ts(minutes_ago),
            "timestamp": _ts(minutes_ago),
            "tenant_id": tenant_id,
            "source_id": _DEMO_SOURCE_ID,
            "session_id": "demo-estate",
            "agent_name": agent_name,
            "tool_name": tool_name,
            "event_type": event_type,
            "action": event_type,
            "detector": detector,
            "decision": decision,
            "effective_decision": decision,
            "reason_code": reason_code,
            "severity": severity,
        }
        push_proxy_alert(alert)
        if event_type == _AUTHORIZED:
            authorized += 1
        elif event_type == _DATA_FILTER:
            data_filters += 1
        else:
            blocked += 1
            if detector in {"undeclared_agent", "shadow_mcp"}:
                shadow_blocked += 1

    push_proxy_metrics(_proxy_metrics_summary(tenant_id))

    firewall_store = _get_firewall_decision_store()
    for (minutes_ago, source_agent, target_agent, decision, matched_rule) in _FIREWALL_DECISIONS:
        firewall_store.record(
            tenant_id=tenant_id,
            event={
                "action": "gateway.firewall_decision",
                "source_agent": source_agent,
                "target_agent": target_agent,
                "decision": decision,
                "effective_decision": decision,
                "matched_rule": matched_rule,
                "enforcement_mode": "enforce",
                "timestamp": _epoch(minutes_ago),
                "tenant_id": tenant_id,
            },
        )

    summary = {
        "seeded": True,
        "tenant_id": tenant_id,
        "feed_events": len(_FEED_EVENTS),
        "authorized": authorized,
        "blocked": blocked,
        "data_filters": data_filters,
        "shadow_blocked": shadow_blocked,
        "firewall_decisions": len(_FIREWALL_DECISIONS),
    }
    _logger.info("demo estate gateway feed seeded %s", summary)
    return summary
