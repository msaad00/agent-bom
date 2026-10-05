"""Bounded regex validation shared by policy writes and runtime enforcement."""

import re
import time
from functools import lru_cache
from re import _parser  # type: ignore[attr-defined]  # CPython parser; covered on supported Python versions.
from typing import Any

import regex

MAX_POLICY_PATTERN_LENGTH = 500
INVALID_POLICY_REASON = "Runtime policy invalid: malformed, oversized, or unsupported regex complexity"
POLICY_LIMIT_REASON = "Runtime policy evaluation limit exceeded"
MAX_POLICY_INPUT_LENGTH = 10_000
POLICY_MATCH_TIMEOUT = 0.025
POLICY_REGEX_BUDGET = 0.1


class PolicyEvaluationLimitError(ValueError):
    """An unevaluated pattern is an explicit failure, never a non-match."""


def _bounded_expression(nodes: Any, *, repeated: bool = False, depth: int = 0) -> bool:
    """Conservative grammar guard, with engine timeouts as the runtime backstop.

    Nested repetitions and alternation inside a repetition require rewriting.
    Limit counted expansion and nesting before the execution engine compiles.
    """
    if depth > 32:
        return False
    for opcode, value in nodes:
        name = str(opcode)
        if name in {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}:
            minimum, maximum, child = value
            if repeated or minimum > 1000 or (maximum != _parser.MAXREPEAT and maximum > 1000):
                return False
            if not _bounded_expression(child, repeated=True, depth=depth + 1):
                return False
        elif name == "BRANCH":
            if repeated or any(not _bounded_expression(branch, depth=depth + 1) for branch in value[1]):
                return False
        elif name in {"SUBPATTERN", "ASSERT", "ASSERT_NOT", "ATOMIC_GROUP"}:
            child = value if name == "ATOMIC_GROUP" else value[-1]
            if not _bounded_expression(child, repeated=repeated, depth=depth + 1):
                return False
        elif name == "GROUPREF_EXISTS":
            if any(not _bounded_expression(branch, repeated=repeated, depth=depth + 1) for branch in value[1:] if branch):
                return False
    return True


@lru_cache(maxsize=512)
def compile_policy_pattern(pattern: str) -> regex.Pattern[str]:
    """Keep Python re syntax while using timeout-capable VERSION0 execution."""
    if len(pattern) > MAX_POLICY_PATTERN_LENGTH:
        raise ValueError(INVALID_POLICY_REASON)
    try:
        parsed = _parser.parse(pattern, 0)
        if not _bounded_expression(parsed):
            raise ValueError(INVALID_POLICY_REASON)
        re.compile(pattern)  # Preserve compile-time Python constraints (for example fixed-width lookbehind).
        return regex.compile(pattern, regex.VERSION0)
    except (re.error, regex.error, RecursionError, OverflowError):
        raise ValueError(INVALID_POLICY_REASON) from None


def bounded_pattern_match(pattern: str, text: str, *, search: bool = False, deadline: float | None = None) -> bool:
    if len(text) > MAX_POLICY_INPUT_LENGTH:
        raise PolicyEvaluationLimitError(POLICY_LIMIT_REASON)
    compiled = compile_policy_pattern(pattern)
    timeout = POLICY_MATCH_TIMEOUT if deadline is None else min(POLICY_MATCH_TIMEOUT, deadline - time.monotonic())
    if timeout <= 0:
        raise PolicyEvaluationLimitError(POLICY_LIMIT_REASON)
    try:
        operation = compiled.search if search else compiled.match
        return operation(text, timeout=timeout) is not None
    except TimeoutError:
        raise PolicyEvaluationLimitError(POLICY_LIMIT_REASON) from None


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
            compile_policy_pattern(value)
        except ValueError:
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
