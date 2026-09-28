"""Gateway policy reload and lookup behavior before service extraction."""

from __future__ import annotations

import json
import time

import pytest
from starlette.testclient import TestClient

from agent_bom import gateway_server as gateway
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _settings(**overrides):
    async def caller(*_args):
        return {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}

    async def sink(_event):
        pass

    return gateway.GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="fixture", url="https://fixture.invalid/mcp")]),
        policy={},
        allow_insecure_no_auth=True,
        allow_anonymous_agents=True,
        fail_mode="closed",
        upstream_caller=caller,
        audit_sink=sink,
        **overrides,
    )


def _until(client, section, predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        state = client.get("/healthz").json()[section]
        if predicate(state):
            return state
        time.sleep(0.02)
    pytest.fail(f"Expected reload state was not reached for {section}")


@pytest.mark.parametrize("firewall", [False, True])
def test_reload_failure_preserves_last_policy_but_only_firewall_invalidates_it(tmp_path, firewall):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 1, "rules": []}))
    prefix = "firewall_" if firewall else ""
    settings = _settings(**{prefix + "policy_path": path, prefix + "policy_reload_interval_seconds": 1})
    section = "firewall_runtime" if firewall else "policy_runtime"
    with TestClient(gateway.create_gateway_app(settings)) as client:
        initial = client.get("/healthz").json()[section]
        assert initial["last_error"] is None
        assert initial["last_loaded_at"] is not None
        path.write_text("{broken")
        failed = _until(client, section, lambda state: state["last_error"] is not None)
        assert failed["last_loaded_at"] == initial["last_loaded_at"]
        if firewall:
            assert failed["load_failed"] is True
            result = client.post("/v1/firewall/check", json={"source_agent": "a", "target_agent": "b"})
            assert result.json()["effective_decision"] == "deny"
        else:
            result = client.post("/mcp/fixture", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert result.json()["result"] == {"ok": True}
        path.write_text(json.dumps({"version": 1, "rules": []}))
        restored = _until(client, section, lambda state: state["last_error"] is None)
        assert restored["last_loaded_at"] >= initial["last_loaded_at"]
        if firewall:
            assert restored["load_failed"] is False


@pytest.mark.parametrize("payload", ["[]", "null", '"policy"'])
def test_policy_file_requires_an_object(tmp_path, payload):
    path = tmp_path / "policy.json"
    path.write_text(payload)
    with pytest.raises(ValueError, match="JSON object"):
        gateway._load_policy_file(path)


@pytest.mark.parametrize(
    "outcome,expected",
    [
        (None, (False, "conditional access evaluation failed", "")),
        ([], (True, "", "")),
        ([object()], (False, "conditional access evaluation failed", "")),
    ],
)
def test_conditional_failure_only_allows_a_confirmed_empty_gate(monkeypatch, outcome, expected):
    class Store:
        def list_conditional_policies(self, tenant, **kwargs):
            assert tenant == "tenant-exact"
            assert kwargs == {"include_disabled": False, "limit": 1}
            if outcome is None:
                raise RuntimeError("synthetic store failure")
            return outcome

    monkeypatch.setattr("agent_bom.api.agent_identity_store.get_agent_identity_store", Store)
    assert gateway._conditional_access_fail_closed("tenant-exact") == expected


@pytest.mark.asyncio
async def test_reload_serializes_publication_and_skips_unchanged_files(tmp_path):
    import asyncio
    import logging

    from agent_bom.runtime.gateway_policy_reload import GatewayPolicyReloader, GatewayPolicyState
    from agent_bom.security import sanitize_text

    path = tmp_path / "policy.json"
    path.write_text('{"rules": []}')
    loads = []

    def load(current):
        loads.append(current)
        return json.loads(current.read_text())

    reloader = GatewayPolicyReloader(
        state=GatewayPolicyState(policy={}, source=str(path), load_failed=True),
        path=lambda: path,
        interval=lambda: 0.1,
        load=load,
        logger=logging.getLogger(__name__),
        log_prefix="gateway policy",
        sanitize_log=sanitize_text,
    )
    results = await asyncio.gather(*(reloader.reload() for _ in range(8)))
    assert results.count(True) == 1
    assert loads == [path]
    assert reloader.state.policy == {"rules": []}
    assert reloader.state.load_failed is False
    assert await reloader.reload(force=True)
    assert loads == [path, path]

    sleeps = []

    async def sleep(delay):
        sleeps.append(delay)
        raise asyncio.CancelledError()

    from unittest.mock import patch

    with patch("agent_bom.runtime.gateway_policy_reload.asyncio.sleep", sleep), pytest.raises(asyncio.CancelledError):
        await reloader.run()
    assert sleeps == [1]
