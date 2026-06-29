"""Tests for the gateway policy-engine hardening.

Covers the five shipped capabilities and the cross-cutting acceptance criteria:

1. Fail-closed mode — missing/unloadable policy DENIES by default and still
   ALLOWS only under explicit ``open`` mode.
2. Quarantine decision tier — a conditional ``quarantine`` rule blocks the tool
   with a distinct, client-safe reason while flagging + auditing the agent.
3. Conditional access — declarative time-window / risk-score / required-attribute
   gates, evaluated deterministically from an injected ``now``.
4. Plugin policy/detector registry — a registered evaluator composes into the
   pipeline; a raising plugin is isolated, not fatal.
5. Interop OCSF + webhook — a normalized OCSF event is POSTed on deny/quarantine
   with an idempotency key; 429 is retried then dropped with a warning; the
   relay is never blocked by a webhook failure.

Plus determinism (same request → identical decision + identical event id) and
the non-enforcement default-allow guarantee.
"""

from __future__ import annotations

import logging
import random
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.proxy_policy import (
    DecisionContext,
    GatewayDecision,
    PluginDecision,
    _reset_policy_evaluators_for_tests,
    build_policy_ocsf_event,
    context_from_now,
    deliver_policy_webhook,
    evaluate_conditional_rules,
    evaluate_conditions,
    policy_event_id,
    register_policy_evaluator,
    resolve_fail_mode,
)

# A fixed UTC instant: 2026-06-15 (Monday) 10:00 → minute_of_day 600, weekday 0.
_MONDAY_10AM = 1781517600.0


def _registry() -> UpstreamRegistry:
    return UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")])


def _call(tool: str = "run_shell") -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": {}}}


async def _ok_caller(upstream, message, extra_headers):
    return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}


def _settings(audit: list[dict[str, Any]] | None = None, **kwargs: Any) -> GatewaySettings:
    async def _sink(event: dict[str, Any]) -> None:
        if audit is not None:
            audit.append(event)

    return GatewaySettings(
        registry=_registry(),
        policy=kwargs.pop("policy", {"rules": []}),
        upstream_caller=_ok_caller,
        audit_sink=_sink if audit is not None else None,
        **kwargs,
    )


def _is_blocked(resp) -> bool:
    body = resp.json()
    return resp.status_code == 200 and isinstance(body.get("error"), dict) and body["error"].get("code") == -32001


@pytest.fixture(autouse=True)
def _clean_plugin_registry():
    _reset_policy_evaluators_for_tests()
    yield
    _reset_policy_evaluators_for_tests()


# ─── Fail-closed mode ──────────────────────────────────────────────────────


def test_resolve_fail_mode_default_closed(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_GATEWAY_FAIL_MODE", raising=False)
    assert resolve_fail_mode(None) == "closed"
    assert resolve_fail_mode("closed") == "closed"
    assert resolve_fail_mode("open") == "open"
    assert resolve_fail_mode("garbage") == "closed"


def test_fail_closed_denies_when_policy_file_unloadable(tmp_path):
    missing = tmp_path / "does-not-exist.json"
    audit: list[dict[str, Any]] = []
    settings = _settings(audit=audit, policy_path=missing, fail_mode="closed")
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call())
    assert _is_blocked(resp)
    assert resp.json()["error"]["data"]["policy_source"] == "fail_closed"
    assert any(e["action"] == "gateway.policy_fail_closed" for e in audit)


def test_fail_closed_default_denies_when_policy_file_unloadable(tmp_path):
    missing = tmp_path / "does-not-exist.json"
    audit: list[dict[str, Any]] = []
    settings = _settings(audit=audit, policy_path=missing)
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call())
    assert _is_blocked(resp)
    assert resp.json()["error"]["data"]["policy_source"] == "fail_closed"
    assert any(e["action"] == "gateway.policy_fail_closed" for e in audit)


def test_explicit_fail_open_allows_when_policy_file_unloadable(tmp_path):
    missing = tmp_path / "does-not-exist.json"
    settings = _settings(policy_path=missing, fail_mode="open")
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call())
    # Local/dev compatibility: explicit fail-open still forwards.
    assert resp.status_code == 200
    assert resp.json().get("result") == {"ok": True}


# ─── Conditional access (declarative, deterministic) ───────────────────────


def test_evaluate_conditions_time_window():
    inside = context_from_now(now=_MONDAY_10AM)  # Monday 10:00 UTC
    ok, _ = evaluate_conditions({"time_window": {"start": "08:00", "end": "20:00"}}, inside)
    assert ok
    bad, reason = evaluate_conditions({"time_window": {"start": "11:00", "end": "20:00"}}, inside)
    assert not bad and "time window" in reason


def test_evaluate_conditions_weekday_and_risk_and_attrs():
    ctx = context_from_now(now=_MONDAY_10AM, risk_score=0.4, attributes={"mfa": "true"})
    assert ctx.weekday == 0
    ok, _ = evaluate_conditions({"weekdays": [0, 1, 2, 3, 4]}, ctx)
    assert ok
    bad, _ = evaluate_conditions({"weekdays": [5, 6]}, ctx)
    assert not bad
    deny, reason = evaluate_conditions({"max_risk_score": 0.3}, ctx)
    assert not deny and "risk score" in reason
    miss, reason = evaluate_conditions({"required_attributes": {"mfa": "false"}}, ctx)
    assert not miss and "mfa" in reason


def test_conditional_rule_required_attribute_denies_in_relay():
    audit: list[dict[str, Any]] = []
    policy = {"rules": [{"id": "need-mfa", "action": "block", "conditions": {"required_attributes": {"mfa": "true"}}}]}
    settings = _settings(audit=audit, policy=policy)
    client = TestClient(create_gateway_app(settings))
    # No mfa context attribute → the required-attribute gate is not satisfied.
    resp = client.post("/mcp/filesystem", json=_call())
    assert _is_blocked(resp)
    assert resp.json()["error"]["data"]["policy_source"] == "conditional_access"
    # With the attribute asserted, the same call passes.
    ok = client.post("/mcp/filesystem", json=_call(), headers={"x-agent-ctx-mfa": "true"})
    assert ok.status_code == 200 and ok.json().get("result") == {"ok": True}


def test_conditional_rule_risk_score_denies_in_relay():
    audit: list[dict[str, Any]] = []
    policy = {"rules": [{"id": "risk-cap", "action": "block", "conditions": {"max_risk_score": 0.5}}]}
    settings = _settings(audit=audit, policy=policy)
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call(), headers={"x-agent-risk-score": "0.9"})
    assert _is_blocked(resp)
    assert resp.json()["error"]["data"]["policy_source"] == "conditional_access"
    assert any(e["action"] == "gateway.policy_blocked" for e in audit)


# ─── Quarantine tier ───────────────────────────────────────────────────────


def test_quarantine_rule_returns_distinct_decision():
    audit: list[dict[str, Any]] = []
    policy = {"rules": [{"id": "q-high-risk", "action": "quarantine", "conditions": {"max_risk_score": 0.5}}]}
    settings = _settings(audit=audit, policy=policy)
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call(), headers={"x-agent-risk-score": "0.95"})
    body = resp.json()
    assert resp.status_code == 200
    assert body["error"]["code"] == -32002  # distinct from -32001 deny
    assert body["error"]["data"]["decision"] == "quarantine"
    # Client-safe reason — no internal rule text leaked.
    assert "under review" in body["error"]["data"]["reason"]
    assert any(e["action"] == "gateway.policy_quarantined" for e in audit)


# ─── Plugin registry ───────────────────────────────────────────────────────


def test_plugin_evaluator_can_deny_in_relay():
    def _deny_evaluator(ctx: DecisionContext, policy: dict) -> PluginDecision | None:
        if ctx.tool_name == "run_shell":
            return PluginDecision(GatewayDecision.DENY, "plugin blocked run_shell")
        return None

    register_policy_evaluator("deny-shell", _deny_evaluator)
    audit: list[dict[str, Any]] = []
    settings = _settings(audit=audit)
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call(tool="run_shell"))
    assert _is_blocked(resp)
    assert resp.json()["error"]["data"]["policy_source"] == "policy_plugin"


def test_raising_plugin_fails_closed_by_default():
    def _boom(ctx: DecisionContext, policy: dict) -> PluginDecision | None:
        raise RuntimeError("plugin exploded")

    register_policy_evaluator("boom", _boom)
    audit: list[dict[str, Any]] = []
    settings = _settings(audit=audit)
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call())
    assert _is_blocked(resp)
    body = resp.json()
    assert body["error"]["data"]["policy_source"] == "policy_plugin"
    assert body["error"]["data"]["reason"] == "A gateway policy plugin blocked this request"
    assert any(
        event["policy_source"] == "policy_plugin"
        and event["reason"] == "policy evaluator unavailable; fail-closed mode denies"
        for event in audit
    )


def test_raising_plugin_is_isolated_in_explicit_fail_open_mode():
    def _boom(ctx: DecisionContext, policy: dict) -> PluginDecision | None:
        raise RuntimeError("plugin exploded")

    register_policy_evaluator("boom", _boom)
    settings = _settings(fail_mode="open")
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call())
    # Decision still returned — the call forwards only under explicit fail-open.
    assert resp.status_code == 200
    assert resp.json().get("result") == {"ok": True}


# ─── Determinism + deterministic ids ───────────────────────────────────────


def test_decision_and_event_id_are_deterministic():
    ctx = context_from_now(
        tenant_id="acme",
        source_agent="agent-a",
        tool_name="run_shell",
        now=_MONDAY_10AM,
        risk_score=0.9,
    )
    policy = {"rules": [{"id": "risk-cap", "action": "block", "conditions": {"max_risk_score": 0.5}}]}
    d1 = evaluate_conditional_rules(policy, ctx)
    d2 = evaluate_conditional_rules(policy, ctx)
    assert d1 == d2 == (GatewayDecision.DENY, d1[1], "risk-cap")

    id1 = policy_event_id(
        tenant_id="acme", source_agent="agent-a", tool_name="run_shell", decision=GatewayDecision.DENY, reason=d1[1], now=_MONDAY_10AM
    )
    id2 = policy_event_id(
        tenant_id="acme", source_agent="agent-a", tool_name="run_shell", decision=GatewayDecision.DENY, reason=d1[1], now=_MONDAY_10AM
    )
    assert id1 == id2 and id1.startswith("gwpol-")

    e1 = build_policy_ocsf_event(decision=GatewayDecision.DENY, reason=d1[1], ctx=ctx)
    e2 = build_policy_ocsf_event(decision=GatewayDecision.DENY, reason=d1[1], ctx=ctx)
    assert e1 == e2  # byte-identical events
    assert e1["idempotency_key"] == id1
    assert e1["class_uid"] == 2004


# ─── OCSF + webhook interop ────────────────────────────────────────────────


def test_webhook_no_url_is_noop(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_POLICY_WEBHOOK_URL", raising=False)
    event = {"idempotency_key": "k"}
    posted: list[int] = []
    assert deliver_policy_webhook(event, url="", poster=lambda *a: posted.append(1) or 200) is False
    assert deliver_policy_webhook(event, url=None, poster=lambda *a: posted.append(1) or 200) is False
    assert posted == []  # never attempted a POST


def test_webhook_429_retried_then_dropped_with_warning(caplog):
    calls: list[dict[str, str]] = []

    def _poster(url: str, event: dict[str, Any], headers: dict[str, str]) -> int:
        calls.append(headers)
        return 429

    sleeps: list[float] = []
    with caplog.at_level(logging.WARNING, logger="agent_bom.proxy_policy"):
        delivered = deliver_policy_webhook(
            {"idempotency_key": "evt-1", "metadata": {"uid": "evt-1"}},
            url="https://siem.example/ingest",
            max_attempts=3,
            poster=_poster,
            sleep=sleeps.append,
            rng=random.Random(7),
        )
    assert delivered is False
    assert len(calls) == 3  # retried up to max_attempts
    assert len(sleeps) == 2  # backoff between the 3 attempts
    # Idempotency key carried so retries don't double-record downstream.
    assert all(h.get("Idempotency-Key") == "evt-1" for h in calls)
    warnings = [r.getMessage().lower() for r in caplog.records if r.levelname == "WARNING"]
    assert any("rate limited" in m for m in warnings)


def test_webhook_auth_failure_not_retried(caplog):
    calls = []

    def _poster(url, event, headers):
        calls.append(1)
        return 403

    with caplog.at_level(logging.WARNING, logger="agent_bom.proxy_policy"):
        delivered = deliver_policy_webhook(
            {"idempotency_key": "evt-2"}, url="https://siem.example/ingest", max_attempts=3, poster=_poster, sleep=lambda _s: None
        )
    assert delivered is False
    assert len(calls) == 1  # 401/403 is terminal, not retried
    warnings = [r.getMessage().lower() for r in caplog.records if r.levelname == "WARNING"]
    assert any("auth" in m for m in warnings)


def test_webhook_success_returns_true():
    def _poster(url, event, headers):
        return 202

    assert deliver_policy_webhook({"idempotency_key": "evt-3"}, url="https://siem.example/ingest", poster=_poster) is True


def test_webhook_failure_does_not_block_relay():
    # A webhook that always errors must not prevent the deny response.
    def _boom_poster(url, event, headers):
        raise ConnectionError("siem unreachable")

    audit: list[dict[str, Any]] = []
    policy = {"rules": [{"id": "deny-shell", "action": "block", "block_tools": ["run_shell"]}]}
    settings = _settings(audit=audit, policy=policy, policy_webhook_url="https://siem.example/ingest")
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call(tool="run_shell"))
    assert _is_blocked(resp)  # relay still denies even though the webhook would fail


# ─── Non-enforcement default behaviour unchanged ───────────────────────────


def test_defaults_preserve_existing_allow_behaviour():
    # No policy_path, no webhook, no conditional rules, no plugins: an unmatched
    # inline policy is still non-enforcement and forwards.
    settings = _settings(policy={"rules": []})
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call())
    assert resp.status_code == 200
    assert resp.json().get("result") == {"ok": True}


def test_defaults_preserve_existing_block_behaviour():
    # A plain allow/deny policy with the new engine present still denies with the
    # original -32001 code and policy_source "file".
    policy = {"rules": [{"id": "no-shell", "action": "block", "block_tools": ["run_shell"]}]}
    settings = _settings(policy=policy)
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call(tool="run_shell"))
    body = resp.json()
    assert body["error"]["code"] == -32001
    assert body["error"]["data"]["policy_source"] == "file"
