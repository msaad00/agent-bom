"""Malformed policy regexes never disable enforcement silently."""

import json

import pytest

from agent_bom.api.policy_store import GatewayPolicy, GatewayRule
from agent_bom.gateway import evaluate_gateway_policies_detail
from agent_bom.proxy_policy import check_policy_detail, check_policy_warning


@pytest.mark.parametrize("field", ["tool_name_pattern", "arg_pattern"])
@pytest.mark.parametrize("pattern", ["private-pattern[", "x" * 501])
@pytest.mark.parametrize("mode", ["audit", "enforce"])
def test_existing_invalid_policy_is_denied_or_explicitly_audited(field, pattern, mode):
    fields = {field: pattern if field == "tool_name_pattern" else {"private-argument-name": pattern}}
    policy = GatewayPolicy(policy_id="policy", name="guard", mode=mode, rules=[GatewayRule(id="rule", action="block", **fields)])
    allowed, reason, policy_id, rule_id, _, _ = evaluate_gateway_policies_detail(
        [policy], "read", {"private-argument-name": "secret-value"}
    )
    assert allowed is (mode == "audit")
    assert "invalid" in reason.lower() and "policy" in reason.lower()
    assert policy_id == "policy" and rule_id == "rule"
    assert "private-argument-name" not in reason and "secret-value" not in reason and pattern not in reason


def test_local_policy_file_invalid_rule_is_fail_closed(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": [{"id": "broken", "action": "block", "tool_name_pattern": "["}]}))
    allowed, reason, rule_id = check_policy_detail(json.loads(path.read_text()), "read", {})
    assert not allowed and "invalid" in reason and rule_id == "broken"


def test_local_advisory_rule_explicitly_reports_invalid_regex():
    policy = {"rules": [{"id": "broken", "action": "warn", "arg_pattern": {"cmd": "["}}]}
    matched, reason, rule_id = check_policy_warning(policy, "read", {})
    assert matched and "invalid" in reason and rule_id == "broken"


def test_valid_regex_still_blocks_only_matching_calls():
    policy = {"rules": [{"id": "valid", "action": "block", "tool_name_pattern": "exec.*"}]}
    assert not check_policy_detail(policy, "execute", {})[0]
    assert check_policy_detail(policy, "read", {})[0]


@pytest.mark.parametrize("mode", ["enforce", "audit"])
def test_standalone_gateway_uses_same_invalid_policy_verdict(mode):
    from agent_bom.api.gateway_policy import _evaluate_control_plane_bundle

    row = GatewayPolicy(policy_id="broken", name="Broken", mode=mode, rules=[GatewayRule(id="rule", tool_name_pattern="[")])
    allowed, reason = _evaluate_control_plane_bundle([row.model_dump()], "agent", "read", {})
    assert allowed is (mode == "audit") and "invalid" in reason


def test_disabled_or_other_agent_invalid_policy_does_not_apply():
    from agent_bom.api.gateway_policy import _evaluate_control_plane_bundle

    row = GatewayPolicy(
        policy_id="broken", name="Broken", mode="enforce", bound_agents=["other"], rules=[GatewayRule(id="rule", tool_name_pattern="[")]
    )
    assert _evaluate_control_plane_bundle([row.model_dump()], "agent", "read", {}) == (True, "")
    row.bound_agents = []
    row.enabled = False
    assert _evaluate_control_plane_bundle([row.model_dump()], "agent", "read", {}) == (True, "")


@pytest.mark.parametrize("policy", [[], {"rules": {}}, {"rules": [None]}])
def test_malformed_local_policy_shape_fails_closed(policy):
    allowed, reason, _ = check_policy_detail(policy, "read", {})
    assert not allowed and "invalid" in reason
