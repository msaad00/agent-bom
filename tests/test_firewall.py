"""Tests for the inter-agent firewall foundation (#982 PR 1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.firewall import (
    AgentFirewallPolicy,
    FirewallDecision,
    FirewallEnforcementMode,
    FirewallPolicyError,
    FirewallRule,
    evaluate,
    load_firewall_policy_file,
    parse_firewall_policy,
)


def test_empty_policy_default_allow():
    policy = AgentFirewallPolicy()
    result = evaluate(policy, source_agent="cursor", target_agent="claude-desktop")
    assert result.decision == FirewallDecision.ALLOW
    assert result.matched_rule is None


def test_pairwise_deny_wins():
    policy = AgentFirewallPolicy(rules=(FirewallRule(source="cursor", target="claude-desktop", decision=FirewallDecision.DENY),))
    result = evaluate(policy, source_agent="cursor", target_agent="claude-desktop")
    assert result.decision == FirewallDecision.DENY
    assert result.matched_rule is not None


def test_role_tag_match():
    policy = AgentFirewallPolicy(rules=(FirewallRule(source="role:trusted", target="role:data-plane", decision=FirewallDecision.DENY),))
    result = evaluate(
        policy,
        source_agent="cursor",
        target_agent="snowflake-cli",
        source_roles={"trusted"},
        target_roles={"data-plane"},
    )
    assert result.decision == FirewallDecision.DENY


def test_specific_rule_beats_role_rule():
    policy = AgentFirewallPolicy(
        rules=(
            FirewallRule(source="role:trusted", target="role:data-plane", decision=FirewallDecision.DENY),
            FirewallRule(source="cursor", target="snowflake-cli", decision=FirewallDecision.ALLOW),
        )
    )
    result = evaluate(
        policy,
        source_agent="cursor",
        target_agent="snowflake-cli",
        source_roles={"trusted"},
        target_roles={"data-plane"},
    )
    assert result.decision == FirewallDecision.ALLOW
    assert result.matched_rule is not None
    assert result.matched_rule.source == "cursor"


def test_deny_beats_allow_at_same_specificity():
    policy = AgentFirewallPolicy(
        rules=(
            FirewallRule(source="cursor", target="claude-desktop", decision=FirewallDecision.ALLOW),
            FirewallRule(source="cursor", target="claude-desktop", decision=FirewallDecision.DENY),
        )
    )
    result = evaluate(policy, source_agent="cursor", target_agent="claude-desktop")
    assert result.decision == FirewallDecision.DENY


def test_warn_only_decision_returns_warn():
    policy = AgentFirewallPolicy(rules=(FirewallRule(source="cursor", target="claude-desktop", decision=FirewallDecision.WARN),))
    result = evaluate(policy, source_agent="cursor", target_agent="claude-desktop")
    assert result.decision == FirewallDecision.WARN
    assert result.effective_decision == FirewallDecision.WARN


def test_dry_run_mode_converts_deny_to_warn():
    policy = AgentFirewallPolicy(
        enforcement_mode=FirewallEnforcementMode.DRY_RUN,
        rules=(FirewallRule(source="cursor", target="claude-desktop", decision=FirewallDecision.DENY),),
    )
    result = evaluate(policy, source_agent="cursor", target_agent="claude-desktop")
    assert result.decision == FirewallDecision.DENY
    assert result.effective_decision == FirewallDecision.WARN


def test_dry_run_mode_keeps_allow_and_warn_unchanged():
    policy = AgentFirewallPolicy(
        enforcement_mode=FirewallEnforcementMode.DRY_RUN,
        rules=(
            FirewallRule(source="a", target="b", decision=FirewallDecision.WARN),
            FirewallRule(source="c", target="d", decision=FirewallDecision.ALLOW),
        ),
    )
    warn_result = evaluate(policy, source_agent="a", target_agent="b")
    allow_result = evaluate(policy, source_agent="c", target_agent="d")
    assert warn_result.effective_decision == FirewallDecision.WARN
    assert allow_result.effective_decision == FirewallDecision.ALLOW


def test_wildcard_pattern_matches():
    policy = AgentFirewallPolicy(rules=(FirewallRule(source="*", target="snowflake-*", decision=FirewallDecision.DENY),))
    result = evaluate(policy, source_agent="cursor", target_agent="snowflake-cli")
    assert result.decision == FirewallDecision.DENY


def test_default_decision_deny():
    policy = AgentFirewallPolicy(default_decision=FirewallDecision.DENY)
    result = evaluate(policy, source_agent="cursor", target_agent="claude-desktop")
    assert result.decision == FirewallDecision.DENY
    assert result.matched_rule is None


def test_role_pattern_with_wildcard():
    policy = AgentFirewallPolicy(rules=(FirewallRule(source="role:trusted-*", target="*", decision=FirewallDecision.ALLOW),))
    result = evaluate(
        policy,
        source_agent="cursor",
        target_agent="claude-desktop",
        source_roles={"trusted-orchestrator"},
    )
    assert result.decision == FirewallDecision.ALLOW


def test_parse_minimal_policy():
    policy = parse_firewall_policy({"rules": []})
    assert policy.version == 1
    assert policy.default_decision == FirewallDecision.ALLOW
    assert policy.enforcement_mode == FirewallEnforcementMode.ENFORCE
    assert policy.rules == ()


def test_parse_full_policy():
    payload = {
        "version": 1,
        "tenant_id": "acme",
        "enforcement_mode": "dry_run",
        "default_decision": "deny",
        "rules": [
            {
                "source": "cursor",
                "target": "snowflake-cli",
                "decision": "allow",
                "description": "Cursor may delegate to Snowflake CLI",
            },
            {"source": "role:untrusted", "target": "*", "decision": "deny"},
        ],
    }
    policy = parse_firewall_policy(payload)
    assert policy.tenant_id == "acme"
    assert policy.enforcement_mode == FirewallEnforcementMode.DRY_RUN
    assert policy.default_decision == FirewallDecision.DENY
    assert len(policy.rules) == 2
    assert policy.rules[0].description == "Cursor may delegate to Snowflake CLI"


def test_parse_unknown_decision_raises():
    with pytest.raises(FirewallPolicyError, match="unknown decision"):
        parse_firewall_policy({"rules": [{"source": "a", "target": "b", "decision": "yikes"}]})


def test_parse_missing_source_raises():
    with pytest.raises(FirewallPolicyError, match="missing 'source'"):
        parse_firewall_policy({"rules": [{"target": "b", "decision": "deny"}]})


def test_parse_unknown_enforcement_mode_raises():
    with pytest.raises(FirewallPolicyError, match="unknown enforcement_mode"):
        parse_firewall_policy({"enforcement_mode": "audit-only", "rules": []})


def test_parse_unsupported_version_raises():
    with pytest.raises(FirewallPolicyError, match="unsupported firewall policy version"):
        parse_firewall_policy({"version": 2, "rules": []})


def test_parse_non_dict_raises():
    with pytest.raises(FirewallPolicyError, match="must be a JSON object"):
        parse_firewall_policy([])  # type: ignore[arg-type]


def test_load_file_round_trip(tmp_path: Path):
    payload = {
        "version": 1,
        "rules": [{"source": "*", "target": "snowflake-*", "decision": "warn"}],
    }
    policy_path = tmp_path / "firewall.json"
    policy_path.write_text(json.dumps(payload))
    policy = load_firewall_policy_file(policy_path)
    assert len(policy.rules) == 1
    assert policy.rules[0].decision == FirewallDecision.WARN


def test_load_invalid_json_raises(tmp_path: Path):
    policy_path = tmp_path / "firewall.json"
    policy_path.write_text("{not json")
    with pytest.raises(FirewallPolicyError, match="not valid JSON"):
        load_firewall_policy_file(policy_path)


def test_empty_source_raises():
    with pytest.raises(FirewallPolicyError, match="non-empty"):
        FirewallRule(source="", target="b", decision=FirewallDecision.DENY)


def test_role_only_prefix_does_not_match():
    """`role:` (empty role) should not blanket-match anything."""

    policy = AgentFirewallPolicy(rules=(FirewallRule(source="role:", target="*", decision=FirewallDecision.DENY),))
    result = evaluate(
        policy,
        source_agent="cursor",
        target_agent="claude-desktop",
        source_roles={"trusted"},
    )
    assert result.decision == FirewallDecision.ALLOW
