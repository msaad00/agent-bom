"""Provider-neutral, non-secret cloud authorization evidence contracts.

Collection and decision-making stay deliberately separate.  A bundle records
which provider feeds were complete, partial, or unavailable so an evaluator can
distinguish a proven empty policy set from evidence that was never collected.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any


class AuthorizationProvider(StrEnum):
    AZURE = "azure"
    GCP = "gcp"


class EvidenceSourceState(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    ACCESS_DENIED = "access_denied"
    DISABLED = "disabled"
    SDK_MISSING = "sdk_missing"
    UNSUPPORTED = "unsupported"
    STALE = "stale"
    TRUNCATED = "truncated"
    UNAVAILABLE = "unavailable"


_SOURCE_STATE_SEVERITY: dict[EvidenceSourceState, int] = {
    EvidenceSourceState.COMPLETE: 0,
    EvidenceSourceState.PARTIAL: 1,
    EvidenceSourceState.STALE: 2,
    EvidenceSourceState.TRUNCATED: 3,
    EvidenceSourceState.UNSUPPORTED: 4,
    EvidenceSourceState.DISABLED: 5,
    EvidenceSourceState.SDK_MISSING: 6,
    EvidenceSourceState.UNAVAILABLE: 7,
    EvidenceSourceState.ACCESS_DENIED: 8,
}


class AuthorizationDecision(StrEnum):
    ALLOW = "allow"
    EXPLICIT_DENY = "explicit_deny"
    IMPLICIT_DENY = "implicit_deny"
    INDETERMINATE = "indeterminate"


class AuthorizationEffect(StrEnum):
    """Normalized effects.

    ``BOUNDARY`` represents Google Cloud principal access boundaries only.
    Multiple matching GCP boundaries are additive: any unconditional boundary
    that establishes eligibility is sufficient. Other providers must not emit
    this effect until their boundary semantics have a dedicated evaluator.
    """

    ALLOW = "allow"
    DENY = "deny"
    BOUNDARY = "boundary"


class AuthorizationPlane(StrEnum):
    CONTROL = "control"
    DATA = "data"
    ANY = "any"


class ConditionLanguage(StrEnum):
    AZURE_ABAC = "azure_abac"
    CEL = "cel"


@dataclass(frozen=True)
class EvidenceSource:
    name: str
    state: EvidenceSourceState
    diagnostics: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "diagnostics": list(self.diagnostics),
            "provenance": list(self.provenance),
        }


@dataclass(frozen=True)
class AuthorizationCondition:
    language: ConditionLanguage
    expression: str
    version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language.value,
            "expression": self.expression,
            "version": self.version,
        }


@dataclass(frozen=True)
class RoleDefinitionEvidence:
    role_id: str
    permissions: tuple[str, ...] = ()
    excluded_permissions: tuple[str, ...] = ()
    data_permissions: tuple[str, ...] = ()
    excluded_data_permissions: tuple[str, ...] = ()
    completeness: EvidenceSourceState = EvidenceSourceState.UNAVAILABLE
    source: str = ""
    diagnostics: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "role_id": self.role_id,
            "permissions": list(self.permissions),
            "excluded_permissions": list(self.excluded_permissions),
            "data_permissions": list(self.data_permissions),
            "excluded_data_permissions": list(self.excluded_data_permissions),
            "completeness": self.completeness.value,
            "source": self.source,
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True)
class AuthorizationBinding:
    binding_id: str
    effect: AuthorizationEffect
    principal_id: str
    principal_type: str
    scope: str
    role_id: str | None = None
    permissions: tuple[str, ...] = ()
    excluded_permissions: tuple[str, ...] = ()
    data_permissions: tuple[str, ...] = ()
    excluded_data_permissions: tuple[str, ...] = ()
    excluded_principals: tuple[str, ...] = ()
    plane: AuthorizationPlane = AuthorizationPlane.ANY
    condition: AuthorizationCondition | None = None
    applies_to_children: bool = True
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "effect": self.effect.value,
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "scope": self.scope,
            "role_id": self.role_id,
            "permissions": list(self.permissions),
            "excluded_permissions": list(self.excluded_permissions),
            "data_permissions": list(self.data_permissions),
            "excluded_data_permissions": list(self.excluded_data_permissions),
            "excluded_principals": list(self.excluded_principals),
            "plane": self.plane.value,
            "condition": self.condition.to_dict() if self.condition else None,
            "applies_to_children": self.applies_to_children,
            "source": self.source,
        }


@dataclass(frozen=True)
class PrincipalMembership:
    principal_id: str
    group_id: str
    source: str

    def to_dict(self) -> dict[str, str]:
        return {
            "principal_id": self.principal_id,
            "group_id": self.group_id,
            "source": self.source,
        }


@dataclass(frozen=True)
class ResourceAncestry:
    """Canonical provider resource and its proven containing scopes."""

    resource: str
    ancestors: tuple[str, ...]
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "ancestors": list(self.ancestors),
            "source": self.source,
        }


@dataclass(frozen=True)
class AuthorizationEvidenceBundle:
    provider: AuthorizationProvider
    scope: str
    observed_at: datetime | None = None
    sources: tuple[EvidenceSource, ...] = ()
    required_sources: tuple[str, ...] = ()
    bindings: tuple[AuthorizationBinding, ...] = ()
    role_definitions: tuple[RoleDefinitionEvidence, ...] = ()
    memberships: tuple[PrincipalMembership, ...] = ()
    resource_ancestry: tuple[ResourceAncestry, ...] = ()
    diagnostics: tuple[str, ...] = ()

    def source_state(self, name: str) -> EvidenceSourceState | None:
        matches = tuple(source.state for source in self.sources if source.name == name)
        if not matches:
            return None
        if len(matches) == 1:
            return matches[0]
        # Duplicate source records are an invalid/partial contract even when
        # both claim COMPLETE. Preserve a more severe explicit failure state
        # deterministically when one exists.
        worst = max(matches, key=lambda state: (_SOURCE_STATE_SEVERITY[state], state.value))
        return EvidenceSourceState.PARTIAL if worst is EvidenceSourceState.COMPLETE else worst

    def duplicate_source_names(self) -> tuple[str, ...]:
        counts: dict[str, int] = {}
        for source in self.sources:
            counts[source.name] = counts.get(source.name, 0) + 1
        return tuple(sorted(name for name, count in counts.items() if count > 1))

    def incomplete_required_sources(self) -> tuple[str, ...]:
        duplicate_names = set(self.duplicate_source_names())
        incomplete: list[str] = []
        for name in self.required_sources:
            if name in duplicate_names:
                incomplete.append(f"{name}:duplicate")
                continue
            state = self.source_state(name)
            if state is None:
                incomplete.append(f"{name}:missing")
            elif state is not EvidenceSourceState.COMPLETE:
                incomplete.append(f"{name}:{state.value}")
        return tuple(sorted(set(incomplete)))

    def role_definition(self, role_id: str) -> RoleDefinitionEvidence | None:
        matches = tuple(role for role in self.role_definitions if role.role_id == role_id)
        return matches[0] if len(matches) == 1 else None

    def duplicate_role_ids(self) -> tuple[str, ...]:
        counts: dict[str, int] = {}
        for role in self.role_definitions:
            counts[role.role_id] = counts.get(role.role_id, 0) + 1
        return tuple(sorted(role_id for role_id, count in counts.items() if count > 1))

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider.value,
            "scope": self.scope,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "sources": [source.to_dict() for source in self.sources],
            "required_sources": list(self.required_sources),
            "bindings": [binding.to_dict() for binding in self.bindings],
            "role_definitions": [role.to_dict() for role in self.role_definitions],
            "memberships": [membership.to_dict() for membership in self.memberships],
            "resource_ancestry": [item.to_dict() for item in self.resource_ancestry],
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True)
class AuthorizationRequest:
    provider: AuthorizationProvider
    principal_id: str
    action: str
    resource: str
    plane: AuthorizationPlane = AuthorizationPlane.ANY


@dataclass(frozen=True)
class AuthorizationEvaluation:
    decision: AuthorizationDecision
    matched_allow_bindings: tuple[str, ...] = ()
    matched_deny_bindings: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()


__all__ = [
    "AuthorizationBinding",
    "AuthorizationCondition",
    "AuthorizationDecision",
    "AuthorizationEffect",
    "AuthorizationEvaluation",
    "AuthorizationEvidenceBundle",
    "AuthorizationPlane",
    "AuthorizationProvider",
    "AuthorizationRequest",
    "ConditionLanguage",
    "EvidenceSource",
    "EvidenceSourceState",
    "PrincipalMembership",
    "ResourceAncestry",
    "RoleDefinitionEvidence",
]
