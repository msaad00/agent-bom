from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from starlette.testclient import TestClient

from agent_bom.api.policy_store import GatewayPolicy, PolicyMode
from agent_bom.cli import main
from agent_bom.gateway import evaluate_gateway_policies_detail
from agent_bom.gateway_policy_templates import (
    BASELINE_GATEWAY_POLICY_ID,
    BASELINE_GATEWAY_SCHEMA_VERSION,
    baseline_gateway_policy,
    render_gateway_baseline_policy,
)
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.proxy_policy import check_policy, summarize_policy_bundle


def test_baseline_gateway_policy_validates_as_gateway_policy() -> None:
    rendered = render_gateway_baseline_policy(output_format="control-plane")
    schema_version = rendered.pop("schema_version")

    policy = GatewayPolicy(**rendered)

    assert schema_version == BASELINE_GATEWAY_SCHEMA_VERSION
    assert policy.policy_id == BASELINE_GATEWAY_POLICY_ID
    assert policy.mode == PolicyMode.AUDIT
    assert policy.enabled is True
    assert {rule.id for rule in policy.rules} >= {
        "baseline-dangerous-tool-classes",
        "baseline-read-only",
        "baseline-secret-paths",
        "baseline-screen-capture",
        "baseline-unknown-egress",
    }


def test_baseline_proxy_render_defaults_to_advisory_rules() -> None:
    rendered = render_gateway_baseline_policy()
    summary = summarize_policy_bundle(rendered)

    assert rendered["schema_version"] == BASELINE_GATEWAY_SCHEMA_VERSION
    assert rendered["mode"] == "audit"
    assert {rule["action"] for rule in rendered["rules"]} == {"warn"}
    assert summary["rollout_mode"] == "advisory_only"
    assert summary["blocks_requests"] is False
    assert summary["protects_secret_paths"] is True


def test_baseline_gateway_audit_mode_warns_on_dangerous_tool() -> None:
    policy = baseline_gateway_policy()

    allowed, reason, policy_id, rule_id, policy_name, policy_mode = evaluate_gateway_policies_detail(
        [policy],
        "run_shell",
        {"command": "rm -rf /"},
    )

    assert allowed is True
    assert "[audit]" in reason
    assert policy_id == BASELINE_GATEWAY_POLICY_ID
    assert rule_id in {"baseline-dangerous-tool-classes", "baseline-read-only"}
    assert policy_name == policy.name
    assert policy_mode == "audit"


def test_baseline_gateway_enforce_mode_blocks_dangerous_tool() -> None:
    policy = baseline_gateway_policy(mode="enforce")

    allowed, reason, policy_id, rule_id, _policy_name, policy_mode = evaluate_gateway_policies_detail(
        [policy],
        "run_shell",
        {"command": "rm -rf /"},
    )

    assert allowed is False
    assert "run_shell" in reason
    assert policy_id == BASELINE_GATEWAY_POLICY_ID
    assert rule_id in {"baseline-dangerous-tool-classes", "baseline-read-only"}
    assert policy_mode == "enforce"


def test_baseline_proxy_enforce_render_blocks_dangerous_tool() -> None:
    rendered = render_gateway_baseline_policy(mode="enforce")

    allowed, reason = check_policy(rendered, "run_shell", {"command": "whoami"})

    assert allowed is False
    assert "run_shell" in reason


def test_gateway_init_policy_cli_writes_default_advisory_policy(tmp_path: Path) -> None:
    output = tmp_path / "gateway-baseline-policy.json"
    result = CliRunner().invoke(main, ["gateway", "init-policy", "--output", str(output)])

    assert result.exit_code == 0
    assert "gateway serve --policy" in result.output
    rendered = json.loads(output.read_text())
    assert rendered["mode"] == "audit"
    assert {rule["action"] for rule in rendered["rules"]} == {"warn"}


def test_gateway_server_with_baseline_warns_and_allows_dangerous_tool() -> None:
    audit_events: list[dict] = []
    upstream_calls: list[dict] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    async def audit_sink(event):
        audit_events.append(event)

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
        policy=render_gateway_baseline_policy(),
        upstream_caller=fake_caller,
        audit_sink=audit_sink,
    )
    client = TestClient(create_gateway_app(settings))

    resp = client.post(
        "/mcp/filesystem",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "run_shell", "arguments": {"command": "whoami"}},
        },
    )

    assert resp.status_code == 200
    assert resp.json()["result"]["ok"] is True
    assert upstream_calls
    warning_events = [event for event in audit_events if event["action"] == "gateway.policy_warned"]
    assert warning_events
    assert warning_events[0]["tool"] == "run_shell"
    assert warning_events[0]["rule_id"] in {"baseline-dangerous-tool-classes", "baseline-read-only"}
