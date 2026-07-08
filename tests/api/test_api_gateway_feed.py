"""Tests for the Gateway Live Feed (/v1/gateway/feed + /v1/gateway/feed/kpis).

Covers the pure normalization / rollup functions (event fusion + ordering,
shadow-AI counting, redaction-safety, per-agent attribution) and HTTP-level
tenant isolation over the proxy alert ring buffer.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from starlette.testclient import TestClient

from agent_bom.api.routes.gateway_feed import (
    ACTION_DATA_FILTER_APPLIED,
    ACTION_LLM_CALL,
    ACTION_TOOL_CALL_AUTHORIZED,
    ACTION_TOOL_CALL_BLOCKED,
    build_gateway_feed,
    build_gateway_feed_kpis,
)

PROXY_SECRET = "feed-test-proxy-secret-with-32-plus-bytes"


@dataclass(frozen=True)
class _FakeCostRecord:
    tenant_id: str
    agent: str
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    priced: bool
    observed_at: str


def _authorized_alert(*, agent: str = "agent-a", tool: str = "read_file", ts: float = 100.0) -> dict:
    return {"ts": ts, "agent_name": agent, "action": "gateway.policy_allowed", "tool_name": tool, "decision": "allow"}


def _blocked_alert(*, agent: str = "agent-b", tool: str = "exec", ts: float = 200.0, reason: str = "policy") -> dict:
    return {
        "ts": ts,
        "agent_name": agent,
        "action": "gateway.policy_blocked",
        "tool_name": tool,
        "decision": "deny",
        "details": {"reason": reason},
    }


def _dlp_alert(*, agent: str = "agent-c", tool: str = "fetch", ts: float = 300.0) -> dict:
    return {
        "ts": ts,
        "agent_name": agent,
        "detector": "credential_leak",
        "action": "runtime_alert",
        "tool_name": tool,
        "message": "Credential leak detected: AWS Access Key in response — redacted",
        "details": {"credential_type": "AWS Access Key", "redacted_preview": ["AKIA..."]},
    }


def _shadow_alert(*, agent: str = "shadow-agent", tool: str = "delete", ts: float = 400.0) -> dict:
    return {
        "ts": ts,
        "agent_name": agent,
        "action": "gateway.policy_blocked",
        "tool_name": tool,
        "decision": "deny",
        "details": {"reason": "undeclared tool not present in tools/list"},
    }


# ── Normalization + fusion + ordering ─────────────────────────────────────────


def test_feed_fuses_all_three_sources_and_orders_newest_first() -> None:
    alerts = [_authorized_alert(), _blocked_alert(), _dlp_alert()]
    records = [
        _FakeCostRecord(
            tenant_id="t1",
            agent="agent-llm",
            provider="anthropic",
            model="claude-3",
            input_tokens=10,
            output_tokens=5,
            cost_usd=0.0012,
            priced=True,
            observed_at="2026-06-20T00:05:00+00:00",
        )
    ]
    feed = build_gateway_feed(tenant_id="t1", alerts=alerts, llm_records=records, limit=100)

    action_types = {e["action_type"] for e in feed["events"]}
    assert action_types == {
        ACTION_TOOL_CALL_AUTHORIZED,
        ACTION_TOOL_CALL_BLOCKED,
        ACTION_DATA_FILTER_APPLIED,
        ACTION_LLM_CALL,
    }
    assert feed["count"] == 4
    assert feed["schema_version"] == "gateway.feed.v1"
    assert feed["tenant_id"] == "t1"

    # Newest first: the LLM record (2026 ISO) sorts above epoch-float alerts,
    # and within alerts the highest ts wins.
    timestamps = [e["ts"] for e in feed["events"]]
    assert timestamps == sorted(timestamps, reverse=True)
    assert feed["events"][0]["action_type"] == ACTION_LLM_CALL


def test_feed_per_agent_attribution_present_on_every_event() -> None:
    alerts = [_authorized_alert(agent="alpha"), _blocked_alert(agent="beta"), _dlp_alert(agent="gamma")]
    feed = build_gateway_feed(tenant_id="t1", alerts=alerts, llm_records=[], limit=100)
    agents = {e["agent"] for e in feed["events"]}
    assert agents == {"alpha", "beta", "gamma"}
    assert all(e["agent"] for e in feed["events"])


def test_feed_falls_back_to_source_id_then_unknown_for_agent() -> None:
    alerts = [
        {"ts": 1.0, "source_id": "proc-7", "action": "gateway.policy_allowed", "tool_name": "x"},
        {"ts": 2.0, "action": "gateway.policy_allowed", "tool_name": "y"},
    ]
    feed = build_gateway_feed(tenant_id="t1", alerts=alerts, llm_records=[], limit=100)
    by_target = {e["target"]: e["agent"] for e in feed["events"]}
    assert by_target["x"] == "proc-7"
    assert by_target["y"] == "unknown"


def test_feed_skips_unclassifiable_alerts() -> None:
    alerts = [{"ts": 1.0, "action": "gateway.heartbeat", "tool_name": "n/a"}]
    feed = build_gateway_feed(tenant_id="t1", alerts=alerts, llm_records=[], limit=100)
    assert feed["count"] == 0


def test_feed_limit_truncates_after_ordering() -> None:
    alerts = [_authorized_alert(tool=f"t{i}", ts=float(i)) for i in range(10)]
    feed = build_gateway_feed(tenant_id="t1", alerts=alerts, llm_records=[], limit=3)
    assert feed["count"] == 3
    # Highest ts retained after truncation.
    assert {e["target"] for e in feed["events"]} == {"t9", "t8", "t7"}


# ── DLP / data-filter detail ─────────────────────────────────────────────────


def test_data_filter_event_detail_is_redaction_safe() -> None:
    feed = build_gateway_feed(tenant_id="t1", alerts=[_dlp_alert()], llm_records=[], limit=100)
    event = feed["events"][0]
    assert event["action_type"] == ACTION_DATA_FILTER_APPLIED
    assert event["detail"] == "AWS Access Key credential masked"
    # No raw secret material leaks into the normalized event.
    serialized = repr(event)
    assert "AKIA" not in serialized
    assert "redacted_preview" not in serialized


def test_pii_detector_maps_to_data_filter() -> None:
    alert = {
        "ts": 5.0,
        "agent_name": "a",
        "detector": "pii",
        "tool_name": "lookup",
        "details": {"pii_type": "SSN"},
        "message": "pii redacted",
    }
    feed = build_gateway_feed(tenant_id="t1", alerts=[alert], llm_records=[], limit=100)
    assert feed["events"][0]["action_type"] == ACTION_DATA_FILTER_APPLIED
    assert feed["events"][0]["detail"] == "SSN PII redacted"


# ── Shadow-AI rollup ─────────────────────────────────────────────────────────


def test_kpis_shadow_ai_counts_only_undeclared_blocks() -> None:
    alerts = [
        _authorized_alert(),
        _blocked_alert(reason="policy: denied tool"),  # ordinary block, not shadow
        _shadow_alert(),  # undeclared agent block → shadow
        _dlp_alert(),
    ]
    kpis = build_gateway_feed_kpis(tenant_id="t1", alerts=alerts, llm_records=[], uptime_seconds=None)
    assert kpis["blocked_today"] == 2
    assert kpis["shadow_ai_blocked"] == 1
    assert kpis["data_filters_applied"] == 1
    assert kpis["tool_calls_authorized"] == 1


def test_shadow_block_event_flagged_and_labeled() -> None:
    feed = build_gateway_feed(tenant_id="t1", alerts=[_shadow_alert()], llm_records=[], limit=100)
    event = feed["events"][0]
    assert event["action_type"] == ACTION_TOOL_CALL_BLOCKED
    assert event["shadow"] is True
    assert "undeclared" in event["detail"]


def test_shadow_markers_cover_unknown_agent_and_shadow_server() -> None:
    alerts = [
        {"ts": 1.0, "agent_name": "x", "action": "gateway.policy_blocked", "details": {"reason": "unknown agent"}},
        {"ts": 2.0, "agent_name": "y", "action": "gateway.policy_blocked", "details": {"reason": "shadow MCP server"}},
    ]
    kpis = build_gateway_feed_kpis(tenant_id="t1", alerts=alerts, llm_records=[], uptime_seconds=None)
    assert kpis["shadow_ai_blocked"] == 2


def test_shadow_detected_via_redaction_safe_fields() -> None:
    """After tier-A redaction strips free text, shadow detection must still fire.

    The persisted ring buffer drops ``action`` / ``reason`` / ``message`` and
    empties ``details``; only whitelisted fields (event_type, detector,
    reason_code, decision) survive. Shadow rollup must ride on those.
    """
    alerts = [
        {  # event_type carries the marker
            "ts": 1.0,
            "agent_name": "x",
            "event_type": "gateway.undeclared_blocked",
            "decision": "deny",
            "details": {},
        },
        {  # detector carries the marker
            "ts": 2.0,
            "agent_name": "y",
            "event_type": "gateway.policy_blocked",
            "detector": "shadow_runtime_server",
            "decision": "deny",
            "details": {},
        },
        {  # reason_code carries the marker
            "ts": 3.0,
            "agent_name": "z",
            "event_type": "gateway.policy_blocked",
            "reason_code": "undeclared_tool",
            "decision": "deny",
            "details": {},
        },
    ]
    kpis = build_gateway_feed_kpis(tenant_id="t1", alerts=alerts, llm_records=[], uptime_seconds=None)
    assert kpis["blocked_today"] == 3
    assert kpis["shadow_ai_blocked"] == 3


def test_classifier_rides_on_event_type_and_decision_after_redaction() -> None:
    """Classification survives redaction that strips free-text action/message."""
    alerts = [
        {"ts": 1.0, "agent_name": "a", "event_type": "gateway.policy_allowed", "decision": "allow", "tool_name": "read"},
        {"ts": 2.0, "agent_name": "b", "event_type": "gateway.policy_blocked", "decision": "deny", "tool_name": "exec"},
    ]
    feed = build_gateway_feed(tenant_id="t1", alerts=alerts, llm_records=[], limit=100)
    by_target = {e["target"]: e["action_type"] for e in feed["events"]}
    assert by_target["read"] == ACTION_TOOL_CALL_AUTHORIZED
    assert by_target["exec"] == ACTION_TOOL_CALL_BLOCKED


# ── KPI rollup totals + no fabricated uptime ─────────────────────────────────


def test_kpis_calls_today_sums_tool_calls_and_llm_calls() -> None:
    alerts = [_authorized_alert(), _authorized_alert(tool="t2"), _blocked_alert(), _dlp_alert()]
    records = [
        _FakeCostRecord("t1", "a", "anthropic", "claude", 1, 1, 0.001, True, "2026-06-20T00:00:00+00:00"),
        _FakeCostRecord("t1", "b", "anthropic", "claude", 1, 1, 0.001, True, "2026-06-20T00:01:00+00:00"),
    ]
    kpis = build_gateway_feed_kpis(tenant_id="t1", alerts=alerts, llm_records=records, uptime_seconds=None)
    # 2 authorized + 1 blocked + 2 llm = 5 (DLP events are not tool calls).
    assert kpis["calls_today"] == 5
    assert kpis["llm_calls"] == 2


def test_kpis_omit_uptime_when_unreported() -> None:
    kpis = build_gateway_feed_kpis(tenant_id="t1", alerts=[], llm_records=[], uptime_seconds=None)
    assert "uptime_seconds" not in kpis
    kpis_zero = build_gateway_feed_kpis(tenant_id="t1", alerts=[], llm_records=[], uptime_seconds=0.0)
    assert "uptime_seconds" not in kpis_zero


def test_kpis_include_uptime_when_reported() -> None:
    kpis = build_gateway_feed_kpis(tenant_id="t1", alerts=[], llm_records=[], uptime_seconds=42.0)
    assert kpis["uptime_seconds"] == 42.0


# ── HTTP-level tenant isolation over the proxy ring buffer ───────────────────


def _headers(tenant: str) -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": "viewer",
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


def test_feed_http_is_tenant_scoped() -> None:
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    try:
        from agent_bom.api.routes import proxy as proxy_routes
        from agent_bom.api.server import app

        proxy_routes._proxy_alerts.clear()
        # Use the realistic post-redaction shape: tier-A whitelist strips
        # free-text action/reason, so classification must ride on event_type /
        # decision (which survive the ring buffer).
        proxy_routes.push_proxy_alert(
            {
                "ts": 10.0,
                "tenant_id": "tenant-x",
                "agent_name": "x-agent",
                "event_type": "gateway.policy_blocked",
                "decision": "deny",
                "detector": "gateway_policy",
                "tool_name": "exec",
            }
        )
        proxy_routes.push_proxy_alert(
            {
                "ts": 11.0,
                "tenant_id": "tenant-y",
                "agent_name": "y-agent",
                "event_type": "gateway.policy_allowed",
                "decision": "allow",
                "tool_name": "read",
            }
        )

        client = TestClient(app)
        resp_x = client.get("/v1/gateway/feed", headers=_headers("tenant-x"))
        assert resp_x.status_code == 200, resp_x.text
        body_x = resp_x.json()
        agents_x = {e["agent"] for e in body_x["events"]}
        assert agents_x == {"x-agent"}
        assert all(e["tenant"] == "tenant-x" for e in body_x["events"])

        resp_y = client.get("/v1/gateway/feed", headers=_headers("tenant-y"))
        body_y = resp_y.json()
        agents_y = {e["agent"] for e in body_y["events"]}
        assert agents_y == {"y-agent"}

        kpis_x = client.get("/v1/gateway/feed/kpis", headers=_headers("tenant-x")).json()
        assert kpis_x["blocked_today"] == 1
        assert kpis_x["tenant_id"] == "tenant-x"
    finally:
        os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH", None)
        os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", None)
        from agent_bom.api.routes import proxy as proxy_routes

        proxy_routes._proxy_alerts.clear()
