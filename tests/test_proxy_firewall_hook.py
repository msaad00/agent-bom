"""Proxy firewall hook integration tests (#982 PR 3).

These exercise the `_maybe_block_on_firewall` helper that the stdio + SSE
proxy paths share. Full end-to-end stdio loop tests would require spawning
a subprocess and a fake MCP server — out of scope for this PR. The helper
itself is the decision policy; the call sites in run_proxy / _proxy_sse_server
just unpack the result.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agent_bom.firewall import (
    AgentFirewallPolicy,
    FirewallDecision,
    FirewallEnforcementMode,
    FirewallEvaluation,
    FirewallRule,
)
from agent_bom.firewall import (
    evaluate as evaluate_firewall_policy,
)
from agent_bom.proxy import (
    _maybe_block_on_firewall,
    clear_firewall_evaluator,
    set_firewall_evaluator,
)


class _StubMetrics:
    def __init__(self) -> None:
        self.blocked: list[str] = []

    def record_blocked(self, reason: str) -> None:
        self.blocked.append(reason)


def _make_evaluator(policy: AgentFirewallPolicy):
    async def evaluator(
        source: str,
        target: str,
        source_roles: frozenset[str],
        target_roles: frozenset[str],
    ) -> FirewallEvaluation:
        return evaluate_firewall_policy(
            policy,
            source_agent=source,
            target_agent=target,
            source_roles=set(source_roles),
            target_roles=set(target_roles),
        )

    return evaluator


@pytest.fixture(autouse=True)
def _reset_evaluator():
    clear_firewall_evaluator()
    yield
    clear_firewall_evaluator()


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_helper_returns_none_when_no_evaluator_registered() -> None:
    metrics = _StubMetrics()
    result = _run(
        _maybe_block_on_firewall(
            source_agent="cursor",
            target_agent="snowflake-cli",
            tool_name="run_query",
            arguments={"sql": "SELECT 1"},
            log_file=None,
            payload_sha256=None,
            message_id="abc",
            tenant_id=None,
            metrics=metrics,
        )
    )
    assert result is None
    assert metrics.blocked == []


def test_helper_blocks_on_deny() -> None:
    policy = AgentFirewallPolicy(
        rules=(
            FirewallRule(
                source="cursor",
                target="snowflake-cli",
                decision=FirewallDecision.DENY,
                description="no direct DB",
            ),
        ),
    )
    set_firewall_evaluator(_make_evaluator(policy), target_id="snowflake-cli")
    metrics = _StubMetrics()

    reason = _run(
        _maybe_block_on_firewall(
            source_agent="cursor",
            target_agent="snowflake-cli",
            tool_name="run_query",
            arguments={"sql": "SELECT 1"},
            log_file=None,
            payload_sha256="abc",
            message_id=1,
            tenant_id="acme",
            metrics=metrics,
        )
    )
    assert reason is not None
    assert "blocked" in reason
    assert "cursor -> snowflake-cli" in reason
    assert "no direct DB" in reason
    assert metrics.blocked == ["firewall"]


def test_helper_warn_does_not_block() -> None:
    policy = AgentFirewallPolicy(
        rules=(
            FirewallRule(
                source="cursor",
                target="claude-desktop",
                decision=FirewallDecision.WARN,
            ),
        ),
    )
    set_firewall_evaluator(_make_evaluator(policy), target_id="claude-desktop")
    metrics = _StubMetrics()

    reason = _run(
        _maybe_block_on_firewall(
            source_agent="cursor",
            target_agent="claude-desktop",
            tool_name="ping",
            arguments={},
            log_file=None,
            payload_sha256=None,
            message_id=None,
            tenant_id=None,
            metrics=metrics,
        )
    )
    assert reason is None
    assert metrics.blocked == ["firewall_warn"]


def test_helper_dry_run_downgrades_deny_to_warn() -> None:
    policy = AgentFirewallPolicy(
        enforcement_mode=FirewallEnforcementMode.DRY_RUN,
        rules=(
            FirewallRule(
                source="cursor",
                target="snowflake-cli",
                decision=FirewallDecision.DENY,
            ),
        ),
    )
    set_firewall_evaluator(_make_evaluator(policy), target_id="snowflake-cli")
    metrics = _StubMetrics()

    reason = _run(
        _maybe_block_on_firewall(
            source_agent="cursor",
            target_agent="snowflake-cli",
            tool_name="run_query",
            arguments={},
            log_file=None,
            payload_sha256=None,
            message_id=None,
            tenant_id=None,
            metrics=metrics,
        )
    )
    # DENY in policy but effective WARN under dry_run -> caller does not block.
    assert reason is None
    assert metrics.blocked == ["firewall_warn"]


def test_helper_allow_does_nothing() -> None:
    policy = AgentFirewallPolicy(
        rules=(
            FirewallRule(
                source="cursor",
                target="claude-desktop",
                decision=FirewallDecision.ALLOW,
            ),
        ),
    )
    set_firewall_evaluator(_make_evaluator(policy), target_id="claude-desktop")
    metrics = _StubMetrics()

    reason = _run(
        _maybe_block_on_firewall(
            source_agent="cursor",
            target_agent="claude-desktop",
            tool_name="ping",
            arguments={},
            log_file=None,
            payload_sha256=None,
            message_id=None,
            tenant_id=None,
            metrics=metrics,
        )
    )
    assert reason is None
    assert metrics.blocked == []


def test_helper_evaluator_exception_fails_open() -> None:
    async def boom(*args: Any, **kwargs: Any) -> FirewallEvaluation:
        raise RuntimeError("network down")

    set_firewall_evaluator(boom, target_id="claude-desktop")
    metrics = _StubMetrics()

    reason = _run(
        _maybe_block_on_firewall(
            source_agent="cursor",
            target_agent="claude-desktop",
            tool_name="ping",
            arguments={},
            log_file=None,
            payload_sha256=None,
            message_id=None,
            tenant_id=None,
            metrics=metrics,
        )
    )
    assert reason is None
    assert metrics.blocked == []


def test_helper_metrics_optional() -> None:
    """SSE proxy path passes no metrics; helper must not crash."""
    policy = AgentFirewallPolicy(
        rules=(
            FirewallRule(
                source="*",
                target="*",
                decision=FirewallDecision.DENY,
            ),
        ),
    )
    set_firewall_evaluator(_make_evaluator(policy), target_id="t")

    reason = _run(
        _maybe_block_on_firewall(
            source_agent="cursor",
            target_agent="t",
            tool_name="ping",
            arguments={},
            log_file=None,
            payload_sha256=None,
            message_id=None,
            tenant_id=None,
        )
    )
    assert reason is not None
    assert "blocked" in reason
