"""Normalized, non-secret AWS IAM policy and usage evidence contracts.

This module deliberately does not decide whether an action is allowed. It
canonicalizes the evidence needed by the policy-simulation and NHI-governance
layers so deny statements, condition keys, resource scope, and missing
telemetry cannot be flattened into the existing reachability heuristic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal, Mapping


class EvidenceCompleteness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class UsageEvidenceState(StrEnum):
    AVAILABLE = "available"
    ACCESS_DENIED = "access_denied"
    NOT_SUPPORTED = "not_supported"
    UNAVAILABLE = "unavailable"


def _strings(value: Any) -> tuple[str, ...]:
    values = value if isinstance(value, list) else [value]
    return tuple(sorted({item.strip() for item in values if isinstance(item, str) and item.strip()}))


def _conditions(value: Any) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    if not isinstance(value, Mapping):
        return ()
    normalized: list[tuple[str, str, tuple[str, ...]]] = []
    for operator, entries in value.items():
        if not isinstance(operator, str) or not isinstance(entries, Mapping):
            continue
        for key, raw_values in entries.items():
            if not isinstance(key, str):
                continue
            values = _strings(raw_values)
            if values:
                normalized.append((operator.strip(), key.strip(), values))
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class NormalizedIamStatement:
    effect: Literal["Allow", "Deny"]
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    conditions: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    sid: str | None = None


@dataclass(frozen=True)
class NormalizedIamPolicy:
    version: str | None
    statements: tuple[NormalizedIamStatement, ...]
    completeness: EvidenceCompleteness
    diagnostics: tuple[str, ...] = ()
    source_policy_arn: str | None = None


def normalize_iam_policy_document(
    document: Any,
    *,
    source_policy_arn: str | None = None,
) -> NormalizedIamPolicy:
    """Canonicalize an IAM policy document without raising on provider input."""
    if not isinstance(document, Mapping):
        return NormalizedIamPolicy(
            version=None,
            statements=(),
            completeness=EvidenceCompleteness.UNAVAILABLE,
            diagnostics=("policy_document_not_mapping",),
            source_policy_arn=source_policy_arn,
        )

    version_value = document.get("Version")
    version = version_value.strip() if isinstance(version_value, str) and version_value.strip() else None
    raw_statements = document.get("Statement", [])
    if isinstance(raw_statements, Mapping):
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list):
        raw_statements = []

    statements: list[NormalizedIamStatement] = []
    diagnostics: list[str] = []
    for index, raw in enumerate(raw_statements):
        if not isinstance(raw, Mapping):
            diagnostics.append(f"statement_{index}_not_mapping")
            continue
        effect = raw.get("Effect")
        if effect not in {"Allow", "Deny"}:
            diagnostics.append(f"statement_{index}_invalid_effect")
            continue
        actions = _strings(raw.get("Action"))
        not_actions = _strings(raw.get("NotAction"))
        resources = _strings(raw.get("Resource"))
        not_resources = _strings(raw.get("NotResource"))
        if bool(actions) == bool(not_actions):
            diagnostics.append(f"statement_{index}_requires_exactly_one_action_form")
            continue
        if resources and not_resources:
            diagnostics.append(f"statement_{index}_conflicting_resource_forms")
            continue
        sid_value = raw.get("Sid")
        statements.append(
            NormalizedIamStatement(
                effect=effect,
                actions=actions,
                not_actions=not_actions,
                resources=resources,
                not_resources=not_resources,
                conditions=_conditions(raw.get("Condition")),
                sid=sid_value.strip() if isinstance(sid_value, str) and sid_value.strip() else None,
            )
        )

    if not statements:
        completeness = EvidenceCompleteness.UNAVAILABLE
        if not diagnostics:
            diagnostics.append("policy_has_no_statements")
    elif diagnostics:
        completeness = EvidenceCompleteness.PARTIAL
    else:
        completeness = EvidenceCompleteness.COMPLETE
    return NormalizedIamPolicy(
        version=version,
        statements=tuple(statements),
        completeness=completeness,
        diagnostics=tuple(diagnostics),
        source_policy_arn=source_policy_arn,
    )


@dataclass(frozen=True)
class IamServiceUsageEvidence:
    service_namespace: str
    state: UsageEvidenceState
    last_accessed_at: datetime | None = None
    last_accessed_region: str | None = None
    source: Literal["access_advisor", "role_last_used", "credential_report"] = "access_advisor"
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def observed(self) -> bool | None:
        """True/False only when telemetry exists; None means not assessable."""
        if self.state is not UsageEvidenceState.AVAILABLE:
            return None
        return self.last_accessed_at is not None


@dataclass(frozen=True)
class IamPrincipalEvidence:
    principal_arn: str
    policies: tuple[NormalizedIamPolicy, ...] = ()
    usage: tuple[IamServiceUsageEvidence, ...] = ()
    policy_completeness: EvidenceCompleteness = EvidenceCompleteness.UNAVAILABLE
    usage_state: UsageEvidenceState = UsageEvidenceState.UNAVAILABLE

