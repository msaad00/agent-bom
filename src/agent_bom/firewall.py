"""Inter-agent firewall policy: pairwise + role-tag rules with allow/deny/warn tiers.

This module is the policy *foundation* (#982 PR 1). It defines the schema, loader,
and evaluator. Enforcement at the gateway and proxy enforcement points is wired up
in subsequent PRs (#982 PR 2, PR 3).
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class FirewallDecision(str, Enum):
    """Per-rule decision tier."""

    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"


class FirewallEnforcementMode(str, Enum):
    """Global enforcement mode controlling whether DENY actually blocks."""

    ENFORCE = "enforce"
    DRY_RUN = "dry_run"


class FirewallPolicyError(ValueError):
    """Raised when a firewall policy payload fails validation."""


_ROLE_PREFIX = "role:"


@dataclass(frozen=True)
class FirewallRule:
    """A single agent→agent rule.

    Patterns may name a concrete agent (`cursor`) or a role tag (`role:trusted`).
    `*` is a fnmatch wildcard.
    """

    source: str
    target: str
    decision: FirewallDecision
    description: str = ""

    def __post_init__(self) -> None:
        if not self.source.strip() or not self.target.strip():
            raise FirewallPolicyError("firewall rule source and target must be non-empty")


@dataclass(frozen=True)
class AgentFirewallPolicy:
    """A tenant-scoped firewall policy.

    `default_decision` applies when no rule matches. Defaults to ALLOW so an
    empty policy file is permissive — operators opt into deny by adding rules.
    """

    version: int = 1
    tenant_id: str | None = None
    enforcement_mode: FirewallEnforcementMode = FirewallEnforcementMode.ENFORCE
    rules: tuple[FirewallRule, ...] = field(default_factory=tuple)
    default_decision: FirewallDecision = FirewallDecision.ALLOW

    def __post_init__(self) -> None:
        if self.version != 1:
            raise FirewallPolicyError(f"unsupported firewall policy version: {self.version}")


@dataclass(frozen=True)
class FirewallEvaluation:
    """Result of evaluating a policy for a single agent→agent pair."""

    decision: FirewallDecision
    matched_rule: FirewallRule | None
    effective_decision: FirewallDecision
    """`decision` after applying enforcement_mode (DRY_RUN converts DENY → WARN)."""


def _matches(pattern: str, value: str, value_roles: frozenset[str]) -> bool:
    """Return True if `pattern` matches `value` directly or via role tag."""

    if pattern.startswith(_ROLE_PREFIX):
        role = pattern[len(_ROLE_PREFIX) :]
        if not role:
            return False
        for actual_role in value_roles:
            if fnmatch.fnmatchcase(actual_role, role):
                return True
        return False
    return fnmatch.fnmatchcase(value, pattern)


def _rule_specificity(rule: FirewallRule) -> int:
    """Higher = more specific. Concrete names beat role tags beat wildcards."""

    score = 0
    for side in (rule.source, rule.target):
        if "*" in side:
            score += 0
        elif side.startswith(_ROLE_PREFIX):
            score += 1
        else:
            score += 2
    return score


def evaluate(
    policy: AgentFirewallPolicy,
    *,
    source_agent: str,
    target_agent: str,
    source_roles: frozenset[str] | set[str] = frozenset(),
    target_roles: frozenset[str] | set[str] = frozenset(),
) -> FirewallEvaluation:
    """Evaluate the policy for a source → target pair.

    Precedence: most-specific matching rule wins. Within the same specificity,
    DENY beats WARN beats ALLOW (conservative default).
    """

    source_roles_fs = frozenset(source_roles)
    target_roles_fs = frozenset(target_roles)

    candidates: list[FirewallRule] = []
    for rule in policy.rules:
        if _matches(rule.source, source_agent, source_roles_fs) and _matches(rule.target, target_agent, target_roles_fs):
            candidates.append(rule)

    if not candidates:
        return FirewallEvaluation(
            decision=policy.default_decision,
            matched_rule=None,
            effective_decision=_apply_enforcement_mode(policy.default_decision, policy.enforcement_mode),
        )

    candidates.sort(
        key=lambda rule: (
            -_rule_specificity(rule),
            0 if rule.decision == FirewallDecision.DENY else (1 if rule.decision == FirewallDecision.WARN else 2),
        )
    )
    winner = candidates[0]
    return FirewallEvaluation(
        decision=winner.decision,
        matched_rule=winner,
        effective_decision=_apply_enforcement_mode(winner.decision, policy.enforcement_mode),
    )


def _apply_enforcement_mode(decision: FirewallDecision, mode: FirewallEnforcementMode) -> FirewallDecision:
    if mode == FirewallEnforcementMode.DRY_RUN and decision == FirewallDecision.DENY:
        return FirewallDecision.WARN
    return decision


def parse_firewall_policy(payload: dict) -> AgentFirewallPolicy:
    """Parse a JSON-decoded payload into a policy. Raises FirewallPolicyError on issues."""

    if not isinstance(payload, dict):
        raise FirewallPolicyError("firewall policy must be a JSON object")

    version = payload.get("version", 1)
    if not isinstance(version, int):
        raise FirewallPolicyError("firewall policy 'version' must be an integer")

    tenant_id = payload.get("tenant_id")
    if tenant_id is not None and not isinstance(tenant_id, str):
        raise FirewallPolicyError("firewall policy 'tenant_id' must be a string when set")

    mode_raw = payload.get("enforcement_mode", "enforce")
    if not isinstance(mode_raw, str):
        raise FirewallPolicyError("firewall policy 'enforcement_mode' must be a string")
    try:
        mode = FirewallEnforcementMode(mode_raw)
    except ValueError as exc:
        raise FirewallPolicyError(f"unknown enforcement_mode: {mode_raw!r}") from exc

    default_raw = payload.get("default_decision", "allow")
    if not isinstance(default_raw, str):
        raise FirewallPolicyError("firewall policy 'default_decision' must be a string")
    try:
        default_decision = FirewallDecision(default_raw)
    except ValueError as exc:
        raise FirewallPolicyError(f"unknown default_decision: {default_raw!r}") from exc

    raw_rules = payload.get("rules", [])
    if not isinstance(raw_rules, list):
        raise FirewallPolicyError("firewall policy 'rules' must be a list")

    rules: list[FirewallRule] = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise FirewallPolicyError(f"rule[{index}] must be an object")
        source = raw.get("source")
        target = raw.get("target")
        decision_raw = raw.get("decision")
        if not isinstance(source, str) or not isinstance(target, str):
            raise FirewallPolicyError(f"rule[{index}] missing 'source' / 'target' string")
        if not isinstance(decision_raw, str):
            raise FirewallPolicyError(f"rule[{index}] missing 'decision' string")
        try:
            decision = FirewallDecision(decision_raw)
        except ValueError as exc:
            raise FirewallPolicyError(f"rule[{index}] has unknown decision: {decision_raw!r}") from exc
        description = raw.get("description", "")
        if not isinstance(description, str):
            raise FirewallPolicyError(f"rule[{index}] 'description' must be a string when set")
        rules.append(FirewallRule(source=source, target=target, decision=decision, description=description))

    return AgentFirewallPolicy(
        version=version,
        tenant_id=tenant_id,
        enforcement_mode=mode,
        rules=tuple(rules),
        default_decision=default_decision,
    )


def load_firewall_policy_file(path: Path) -> AgentFirewallPolicy:
    """Load a firewall policy from a JSON file."""

    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise FirewallPolicyError(f"firewall policy {path} is not valid JSON: {exc.msg}") from exc
    return parse_firewall_policy(payload)
