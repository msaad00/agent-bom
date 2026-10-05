"""Policy regex failures remain explicit and cannot bypass enforcement."""

import json
import subprocess
import sys

import pytest

from agent_bom.api.policy_store import GatewayPolicy, GatewayRule
from agent_bom.gateway import evaluate_gateway_policies_detail
from agent_bom.proxy_policy import check_policy_detail
from agent_bom.runtime.policy_validation import validate_policy_rules


@pytest.mark.parametrize("pattern", [r"^(a+)+$", r"^(a|aa)+$", r"a{1000000000}", r"(?<=a+)b"])
def test_expensive_patterns_are_rejected_without_echoing_input(pattern):
    with pytest.raises(ValueError, match="Runtime policy invalid") as error:
        validate_policy_rules([{"id": "r", "action": "block", "arg_pattern": {"private-name": pattern}}])
    assert pattern not in str(error.value)
    assert "private-name" not in str(error.value)


@pytest.mark.parametrize("mode", ["enforce", "audit"])
@pytest.mark.parametrize("pattern,value", [(r"^(a+)+$", "a" * 25 + "!"), ("secret", "x" * 10001 + "secret")], ids=["nested", "oversize"])
def test_stored_policy_limits_deny_or_explicitly_audit(mode, pattern, value):
    policy = GatewayPolicy(
        policy_id="policy", name="guard", mode=mode, rules=[GatewayRule(id="r", action="block", arg_pattern={"private-name": pattern})]
    )
    allowed, reason, policy_id, rule_id, _, _ = evaluate_gateway_policies_detail([policy], "read", {"private-name": value})
    assert allowed is (mode == "audit")
    assert "policy" in reason.lower() and ("invalid" in reason.lower() or "limit" in reason.lower())
    assert (policy_id, rule_id) == ("policy", "r")
    assert value not in reason and "private-name" not in reason


def test_catastrophic_pattern_cannot_stall_local_proxy():
    script = """
import json
from agent_bom.proxy_policy import check_policy_detail
print(json.dumps(check_policy_detail({'rules':[{'id':'r','action':'block','tool_name_pattern':'^(a+)+$'}]}, 'a'*100+'!', {})))
"""
    try:
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=3, check=True)
    except subprocess.TimeoutExpired:
        pytest.fail("policy evaluation exceeded subprocess guard")
    allowed, reason, rule_id = json.loads(result.stdout)
    assert not allowed and "invalid" in reason and rule_id == "r"


@pytest.mark.parametrize(
    "pattern,match,miss",
    [(r"^exec.*", "execute", "read"), (r"(?i)delete", "DELETE", "read"), (r"\btoken\b", "token", "tokens"), (r"a{2,4}", "aaa", "b")],
)
def test_supported_policy_patterns_keep_matching_semantics(pattern, match, miss):
    validate_policy_rules([{"tool_name_pattern": pattern}])
    policy = {"rules": [{"id": "r", "action": "block", "tool_name_pattern": pattern}]}
    assert not check_policy_detail(policy, match, {})[0]
    assert check_policy_detail(policy, miss, {})[0]


def test_timeout_backstop_for_valid_adjacent_repeats():
    # This polynomial pattern passes the conservative grammar guard. Matching
    # still has an engine deadline; static validation is not the safety boundary.
    policy = {"rules": [{"id": "r", "action": "block", "arg_pattern": {"value": "a+a+$"}}]}
    validate_policy_rules(policy["rules"])
    allowed, reason, rule = check_policy_detail(policy, "read", {"value": "a" * 9999 + "!"})
    assert not allowed and "limit" in reason and rule == "r"


def test_exhausted_request_budget_is_not_a_nonmatch(monkeypatch):
    import agent_bom.proxy_policy as policy_module

    monkeypatch.setattr(policy_module, "POLICY_REGEX_BUDGET", 0.0)
    result = check_policy_detail({"rules": [{"id": "r", "action": "block", "tool_name_pattern": "exec"}]}, "read", {})
    assert result == (False, "Runtime policy evaluation limit exceeded", "r")


def test_input_boundary_and_cache_are_bounded():
    from agent_bom.runtime.policy_validation import PolicyEvaluationLimitError, bounded_pattern_match, compile_policy_pattern

    assert bounded_pattern_match("x+$", "x" * 10000)
    with pytest.raises(PolicyEvaluationLimitError):
        bounded_pattern_match("x+$", "x" * 10001)
    for n in range(600):
        compile_policy_pattern(f"tool{n}")
    assert compile_policy_pattern.cache_info().currsize <= 512


@pytest.mark.parametrize("mode", ["audit", "enforce"])
def test_standalone_bundle_preserves_timeout_posture(mode):
    from agent_bom.api.gateway_policy import _evaluate_control_plane_bundle

    row = GatewayPolicy(policy_id="p", name="guard", mode=mode, rules=[GatewayRule(id="r", arg_pattern={"value": "a+a+$"})])
    allowed, reason = _evaluate_control_plane_bundle([row.model_dump()], "agent", "read", {"value": "a" * 9999 + "!"})
    assert allowed is (mode == "audit") and "limit" in reason
