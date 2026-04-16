"""Tests for agent_bom.gateway — gateway evaluation engine."""

from agent_bom.api.policy_store import GatewayPolicy, GatewayRule, PolicyMode
from agent_bom.gateway import evaluate_gateway_policies, gateway_policy_to_proxy_format


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _policy(
    policy_id: str = "p-1",
    mode: PolicyMode = PolicyMode.ENFORCE,
    rules: list[GatewayRule] | None = None,
    enabled: bool = True,
) -> GatewayPolicy:
    ts = _now()
    return GatewayPolicy(
        policy_id=policy_id,
        name="test",
        mode=mode,
        rules=rules or [],
        enabled=enabled,
        created_at=ts,
        updated_at=ts,
    )


# ── Conversion ────────────────────────────────────────────────────────────────


def test_convert_block_tools():
    p = _policy(rules=[GatewayRule(id="r1", action="block", block_tools=["exec", "rm"])])
    fmt = gateway_policy_to_proxy_format(p)
    assert fmt["rules"][0]["block_tools"] == ["exec", "rm"]


def test_convert_pattern():
    p = _policy(rules=[GatewayRule(id="r1", action="block", tool_name_pattern="exec.*")])
    fmt = gateway_policy_to_proxy_format(p)
    assert fmt["rules"][0]["tool_name_pattern"] == "exec.*"


def test_convert_arg_pattern():
    p = _policy(rules=[GatewayRule(id="r1", action="block", arg_pattern={"cmd": "rm.*"})])
    fmt = gateway_policy_to_proxy_format(p)
    assert fmt["rules"][0]["arg_pattern"] == {"cmd": "rm.*"}


def test_convert_runtime_enforcement_fields():
    p = _policy(
        rules=[
            GatewayRule(
                id="r1",
                action="block",
                deny_tool_classes=["network"],
                read_only=True,
                block_secret_paths=True,
                block_unknown_egress=True,
                allowed_hosts=["api.openai.com"],
            )
        ]
    )
    fmt = gateway_policy_to_proxy_format(p)
    assert fmt["rules"][0]["deny_tool_classes"] == ["network"]
    assert fmt["rules"][0]["read_only"] is True
    assert fmt["rules"][0]["block_secret_paths"] is True
    assert fmt["rules"][0]["block_unknown_egress"] is True
    assert fmt["rules"][0]["allowed_hosts"] == ["api.openai.com"]


def test_convert_rate_limit():
    p = _policy(rules=[GatewayRule(id="r1", action="block", rate_limit=25)])
    fmt = gateway_policy_to_proxy_format(p)
    assert fmt["rules"][0]["rate_limit"] == 25


# ── Evaluation ────────────────────────────────────────────────────────────────


def test_allow_when_no_policies():
    allowed, reason, pid = evaluate_gateway_policies([], "exec", {})
    assert allowed is True
    assert reason == ""
    assert pid is None


def test_allow_when_no_matching_rules():
    p = _policy(rules=[GatewayRule(id="r1", action="block", block_tools=["dangerous"])])
    allowed, reason, pid = evaluate_gateway_policies([p], "safe_tool", {})
    assert allowed is True


def test_block_enforce_mode():
    p = _policy(
        mode=PolicyMode.ENFORCE,
        rules=[GatewayRule(id="r1", action="block", block_tools=["exec"])],
    )
    allowed, reason, pid = evaluate_gateway_policies([p], "exec", {})
    assert allowed is False
    assert "exec" in reason
    assert pid == "p-1"


def test_audit_mode_allows():
    p = _policy(
        mode=PolicyMode.AUDIT,
        rules=[GatewayRule(id="r1", action="block", block_tools=["exec"])],
    )
    allowed, reason, pid = evaluate_gateway_policies([p], "exec", {})
    assert allowed is True
    assert "[audit]" in reason
    assert pid == "p-1"


def test_disabled_policy_skipped():
    p = _policy(
        enabled=False,
        rules=[GatewayRule(id="r1", action="block", block_tools=["exec"])],
    )
    allowed, reason, pid = evaluate_gateway_policies([p], "exec", {})
    assert allowed is True


def test_multiple_policies_first_blocks():
    p1 = _policy(
        policy_id="p-1",
        mode=PolicyMode.ENFORCE,
        rules=[GatewayRule(id="r1", action="block", block_tools=["safe"])],
    )
    p2 = _policy(
        policy_id="p-2",
        mode=PolicyMode.ENFORCE,
        rules=[GatewayRule(id="r2", action="block", block_tools=["exec"])],
    )
    allowed, reason, pid = evaluate_gateway_policies([p1, p2], "exec", {})
    assert allowed is False
    assert pid == "p-2"


def test_tool_name_exact_match():
    p = _policy(rules=[GatewayRule(id="r1", action="block", tool_name="write_file")])
    allowed, _, _ = evaluate_gateway_policies([p], "write_file", {})
    assert allowed is False


def test_tool_name_pattern_match():
    p = _policy(rules=[GatewayRule(id="r1", action="block", tool_name_pattern="execute.*")])
    allowed, _, _ = evaluate_gateway_policies([p], "execute_command", {})
    assert allowed is False


def test_arg_pattern_match():
    p = _policy(rules=[GatewayRule(id="r1", action="block", arg_pattern={"path": r"/etc/.*"})])
    allowed, _, _ = evaluate_gateway_policies([p], "read_file", {"path": "/etc/passwd"})
    assert allowed is False
    # Non-matching arg
    allowed2, _, _ = evaluate_gateway_policies([p], "read_file", {"path": "/tmp/safe"})
    assert allowed2 is True


def test_gateway_read_only_blocks_write_tool():
    p = _policy(rules=[GatewayRule(id="r1", action="block", read_only=True)])
    allowed, reason, _ = evaluate_gateway_policies([p], "write_file", {"path": "/tmp/x"})
    assert allowed is False
    assert "read-only" in reason.lower()


def test_gateway_unknown_egress_blocks_unapproved_host():
    p = _policy(
        rules=[
            GatewayRule(
                id="r1",
                action="block",
                block_unknown_egress=True,
                allowed_hosts=["api.openai.com"],
            )
        ]
    )
    allowed, reason, _ = evaluate_gateway_policies([p], "web_fetch", {"url": "https://evil.example/"})
    assert allowed is False
    assert "allowlisted" in reason.lower()
