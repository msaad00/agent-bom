"""Tests for the published gateway fail-open/fail-closed posture matrix.

The matrix in ``agent_bom.runtime.fail_mode`` is the single honest inventory
of what each gateway subsystem does when its own machinery fails. These tests
pin the documented posture to the behavior actually implemented in
``gateway_server.py`` — if enforcement code changes posture, the matrix (and
these tests) must change with it.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom import agent_identity, gateway_server
from agent_bom.api import agent_identity_store
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.runtime.fail_mode import (
    GATEWAY_FAIL_MODE_MATRIX,
    FailPosture,
    SubsystemFailMode,
    gateway_fail_mode_matrix,
)

_BY_NAME = {entry.subsystem: entry for entry in GATEWAY_FAIL_MODE_MATRIX}


def test_matrix_covers_every_gateway_enforcement_subsystem() -> None:
    assert set(_BY_NAME) == {
        "policy_engine",
        "firewall_policy",
        "control_plane_policy_bundle",
        "policy_plugins",
        "conditional_access",
        "caller_identity",
        "runtime_rate_limit",
        "spend_budgets",
        "cost_anomaly_enforcement",
        "fleet_quarantine_enforcement",
        "drift_enforcement",
        "graph_reachability_enforcement",
        "device_posture_enrichment",
        "audit_export",
    }


def test_every_entry_is_fully_documented() -> None:
    for entry in GATEWAY_FAIL_MODE_MATRIX:
        assert isinstance(entry, SubsystemFailMode)
        assert entry.subsystem
        assert entry.on_failure, f"{entry.subsystem} must describe its failure behavior"
        assert entry.control, f"{entry.subsystem} must name the operator control (or state there is none)"
        assert entry.default_posture in (FailPosture.OPEN, FailPosture.CLOSED)


def test_advisory_enrichment_paths_are_documented_fail_open() -> None:
    for subsystem in (
        "spend_budgets",
        "cost_anomaly_enforcement",
        "fleet_quarantine_enforcement",
        "drift_enforcement",
        "graph_reachability_enforcement",
        "audit_export",
    ):
        assert _BY_NAME[subsystem].default_posture is FailPosture.OPEN, subsystem
        assert not _BY_NAME[subsystem].follows_gateway_fail_mode, subsystem


def test_security_decision_paths_are_documented_fail_closed() -> None:
    for subsystem in (
        "control_plane_policy_bundle",
        "conditional_access",
        "caller_identity",
        "runtime_rate_limit",
        "device_posture_enrichment",
    ):
        assert _BY_NAME[subsystem].default_posture is FailPosture.CLOSED, subsystem
        assert not _BY_NAME[subsystem].follows_gateway_fail_mode, subsystem


def test_fail_mode_governed_subsystems_default_closed() -> None:
    for subsystem in ("policy_engine", "firewall_policy", "policy_plugins"):
        entry = _BY_NAME[subsystem]
        assert entry.follows_gateway_fail_mode, subsystem
        assert entry.default_posture is FailPosture.CLOSED, subsystem
        assert "AGENT_BOM_GATEWAY_FAIL_MODE" in entry.control, subsystem


def test_matrix_summary_resolves_configurable_entries() -> None:
    closed = {row["subsystem"]: row for row in gateway_fail_mode_matrix("closed")}
    opened = {row["subsystem"]: row for row in gateway_fail_mode_matrix("open")}

    assert closed["policy_engine"]["posture"] == "fail_closed"
    assert opened["policy_engine"]["posture"] == "fail_open"
    assert opened["policy_engine"]["follows_gateway_fail_mode"] is True

    # Fixed postures never flip with the gateway fail mode.
    assert closed["caller_identity"]["posture"] == "fail_closed"
    assert opened["caller_identity"]["posture"] == "fail_closed"
    assert closed["drift_enforcement"]["posture"] == "fail_open"
    assert opened["drift_enforcement"]["posture"] == "fail_open"


def test_matrix_summary_rows_are_json_shaped() -> None:
    rows = gateway_fail_mode_matrix("closed")
    assert len(rows) == len(GATEWAY_FAIL_MODE_MATRIX)
    for row in rows:
        assert set(row) == {"subsystem", "posture", "follows_gateway_fail_mode", "control", "on_failure"}
        assert row["posture"] in ("fail_open", "fail_closed")
        assert isinstance(row["follows_gateway_fail_mode"], bool)


def test_matrix_summary_rejects_unresolved_fail_mode() -> None:
    with pytest.raises(ValueError):
        gateway_fail_mode_matrix("maybe")


# ── Behavior tests: the relay must implement the documented postures ────────
#
# The tests above pin the published matrix DATA. These drive the actual relay
# and assert the runtime honors it: conditional-access eval errors fail closed
# regardless of the knob, plugin eval errors follow the knob, and a managed
# identity whose store is unavailable is not forwarded unscoped.


async def _ok_caller(upstream: Any, message: dict[str, Any], extra_headers: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}


def _settings(*, fail_mode: str, policy: dict[str, Any] | None = None) -> GatewaySettings:
    return GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
        policy=policy if policy is not None else {"agent_tokens": {"token-a": "agent-a"}},
        upstream_caller=_ok_caller,
        fail_mode=fail_mode,
    )


def _call(*, token: str = "token-a", tool: str = "read_file") -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}, "_meta": {"agent_identity": token}},
    }


def _blocked_source(resp: Any) -> str | None:
    body = resp.json()
    error = body.get("error")
    if not isinstance(error, dict) or error.get("code") != -32001:
        return None
    return error.get("data", {}).get("policy_source")


def _boom(*_args: Any, **_kwargs: Any) -> Any:
    raise RuntimeError("evaluator exploded")


def test_conditional_rules_eval_error_denies_even_under_fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    # docs/RUNTIME_FAIL_MODES.md: a conditional-access eval error ALWAYS denies
    # and is never softened by AGENT_BOM_GATEWAY_FAIL_MODE=open.
    monkeypatch.setattr(gateway_server, "evaluate_conditional_rules", _boom)
    client = TestClient(create_gateway_app(_settings(fail_mode="open")))
    resp = client.post("/mcp/filesystem", json=_call())
    assert _blocked_source(resp) == "conditional_access", resp.text


def test_plugin_eval_error_follows_fail_mode_knob(monkeypatch: pytest.MonkeyPatch) -> None:
    # Policy plugins DO follow the knob: fail-open forwards on a plugin engine
    # error, fail-closed denies. (Guards against over-tightening the split.)
    monkeypatch.setattr(gateway_server, "evaluate_policy_plugins", _boom)

    open_client = TestClient(create_gateway_app(_settings(fail_mode="open")))
    open_resp = open_client.post("/mcp/filesystem", json=_call())
    assert _blocked_source(open_resp) is None, open_resp.text
    assert open_resp.json().get("result") == {"ok": True}, open_resp.text

    closed_client = TestClient(create_gateway_app(_settings(fail_mode="closed")))
    closed_resp = closed_client.post("/mcp/filesystem", json=_call())
    assert _blocked_source(closed_resp) == "conditional_access", closed_resp.text


def test_managed_identity_lookup_outage_denies_scoped_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    # A managed (abi_) token resolves to an agent via the policy mapping, but the
    # identity store is down so its per-identity tool scope cannot be loaded. The
    # call must fail closed instead of forwarding unscoped.
    monkeypatch.setattr(agent_identity, "_LOCAL_IDENTITY_VERIFIER", None)
    monkeypatch.setattr(agent_identity_store, "identity_for_token", _boom)
    token = "abi_deadbeef_topsecret"
    settings = _settings(fail_mode="open", policy={"agent_tokens": {token: "agent-a"}})
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call(token=token))
    assert _blocked_source(resp) == "identity_scope", resp.text


def test_non_managed_token_unaffected_by_identity_store_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    # A non-managed (opaque) token legitimately has no identity scope; an
    # identity-store error must not turn its call into a denial (distinguish
    # "lookup errored" from "no scope configured").
    monkeypatch.setattr(agent_identity, "_LOCAL_IDENTITY_VERIFIER", None)
    monkeypatch.setattr(agent_identity_store, "identity_for_token", _boom)
    settings = _settings(fail_mode="open", policy={"agent_tokens": {"token-a": "agent-a"}})
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_call(token="token-a"))
    assert _blocked_source(resp) is None, resp.text
    assert resp.json().get("result") == {"ok": True}, resp.text
