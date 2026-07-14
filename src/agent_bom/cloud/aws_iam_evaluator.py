"""Fail-closed evaluation of normalized AWS IAM identity policies."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import Mapping, Sequence

from agent_bom.cloud.aws_iam_evidence import EvidenceCompleteness, NormalizedIamPolicy, NormalizedIamStatement


class IamDecision(StrEnum):
    ALLOW = "allow"
    EXPLICIT_DENY = "explicit_deny"
    IMPLICIT_DENY = "implicit_deny"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class IamEvaluation:
    decision: IamDecision
    matched_allow_sids: tuple[str, ...] = ()
    matched_deny_sids: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()


def _matches(value: str, patterns: Sequence[str], *, casefold: bool = False) -> bool:
    candidate = value.lower() if casefold else value
    return any(fnmatchcase(candidate, pattern.lower() if casefold else pattern) for pattern in patterns)


def _scope_matches(statement: NormalizedIamStatement, action: str, resource: str) -> bool:
    action_match = (
        _matches(action, statement.actions, casefold=True)
        if statement.actions
        else not _matches(action, statement.not_actions, casefold=True)
    )
    resource_match = (
        _matches(resource, statement.resources or ("*",))
        if not statement.not_resources
        else not _matches(resource, statement.not_resources)
    )
    return action_match and resource_match


def _condition_matches(operator: str, actual: tuple[str, ...] | None, expected: tuple[str, ...]) -> bool | None:
    base = operator.removeprefix("ForAnyValue:").removeprefix("ForAllValues:")
    if base == "Null":
        want_null = any(value.lower() == "true" for value in expected)
        return (actual is None) == want_null
    if actual is None:
        return True if base.endswith("IfExists") else None
    base = base.removesuffix("IfExists")
    if base in {"StringEquals", "ArnEquals"}:
        return any(item == wanted for item in actual for wanted in expected)
    if base in {"StringNotEquals", "ArnNotEquals"}:
        return all(item != wanted for item in actual for wanted in expected)
    if base in {"StringLike", "ArnLike"}:
        return any(fnmatchcase(item, wanted) for item in actual for wanted in expected)
    if base in {"StringNotLike", "ArnNotLike"}:
        return all(not fnmatchcase(item, wanted) for item in actual for wanted in expected)
    if base == "Bool":
        return any(item.lower() == wanted.lower() for item in actual for wanted in expected)
    return None


def _conditions_match(statement: NormalizedIamStatement, context: Mapping[str, str | Sequence[str]]) -> bool | None:
    uncertain = False
    folded = {key.lower(): value for key, value in context.items()}
    for operator, key, expected in statement.conditions:
        raw = folded.get(key.lower())
        actual = (raw,) if isinstance(raw, str) else tuple(raw) if raw is not None else None
        result = _condition_matches(operator, actual, expected)
        if result is False:
            return False
        if result is None:
            uncertain = True
    return None if uncertain else True


def evaluate_identity_policies(
    policies: Sequence[NormalizedIamPolicy],
    *,
    action: str,
    resource: str,
    context: Mapping[str, str | Sequence[str]] | None = None,
) -> IamEvaluation:
    """Apply explicit-deny precedence; never turn incomplete evidence into allow."""
    if not action.strip() or not resource.strip():
        return IamEvaluation(IamDecision.INDETERMINATE, diagnostics=("invalid_request",))
    incomplete = any(policy.completeness is not EvidenceCompleteness.COMPLETE for policy in policies)
    allows: list[str] = []
    denies: list[str] = []
    uncertain_deny = False
    uncertain_allow = False
    for policy_index, policy in enumerate(policies):
        for statement_index, statement in enumerate(policy.statements):
            if not _scope_matches(statement, action, resource):
                continue
            condition = _conditions_match(statement, context or {})
            sid = statement.sid or f"policy_{policy_index}_statement_{statement_index}"
            if condition is True:
                (denies if statement.effect == "Deny" else allows).append(sid)
            elif condition is None:
                if statement.effect == "Deny":
                    uncertain_deny = True
                else:
                    uncertain_allow = True
    if denies:
        return IamEvaluation(IamDecision.EXPLICIT_DENY, matched_deny_sids=tuple(denies))
    if uncertain_deny or incomplete:
        return IamEvaluation(IamDecision.INDETERMINATE, diagnostics=("incomplete_or_unsupported_evidence",))
    if allows:
        return IamEvaluation(IamDecision.ALLOW, matched_allow_sids=tuple(allows))
    if uncertain_allow:
        return IamEvaluation(IamDecision.INDETERMINATE, diagnostics=("missing_or_unsupported_condition_context",))
    return IamEvaluation(IamDecision.IMPLICIT_DENY)
