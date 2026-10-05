"""Bounded regex validation shared by policy writes and runtime enforcement."""

import re
from typing import Any

MAX_POLICY_PATTERN_LENGTH = 500
INVALID_POLICY_REASON = "Runtime policy invalid: malformed or oversized regex"


def rule_patterns_valid(rule: dict[str, Any]) -> bool:
    pattern = rule.get("tool_name_pattern")
    arguments = rule.get("arg_pattern", {})
    if not isinstance(arguments, dict):
        return False
    patterns = list(arguments.values())
    if pattern is not None:
        patterns.append(pattern)
    for value in patterns:
        if not isinstance(value, str) or len(value) > MAX_POLICY_PATTERN_LENGTH:
            return False
        try:
            re.compile(value)
        except (re.error, RecursionError, OverflowError):
            return False
    return True


def validate_policy_rules(rules: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    """Validate write payloads without echoing patterns or argument names."""
    if rules is not None and any(not rule_patterns_valid(rule) for rule in rules):
        raise ValueError(INVALID_POLICY_REASON)
    return rules


def runtime_policy_error(policy: dict) -> tuple[str, str | None] | None:
    if not isinstance(policy, dict):
        return "Runtime policy invalid: expected an object", None
    rules = policy.get("rules", [])
    if not isinstance(rules, list):
        return "Runtime policy invalid: rules must be a list", None
    for rule in rules:
        if not isinstance(rule, dict):
            return "Runtime policy invalid: rule must be an object", None
        if not rule_patterns_valid(rule):
            return INVALID_POLICY_REASON, str(rule.get("id", "?"))
    return None
