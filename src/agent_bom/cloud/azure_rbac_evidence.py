"""Normalize the current Azure inventory payload into authorization evidence."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from typing import Any, Mapping

from agent_bom.cloud.authorization_evidence import (
    AuthorizationBinding,
    AuthorizationCondition,
    AuthorizationEffect,
    AuthorizationEvidenceBundle,
    AuthorizationPlane,
    AuthorizationProvider,
    ConditionLanguage,
    EvidenceSource,
    EvidenceSourceState,
    RoleDefinitionEvidence,
)


def _records(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _stable_id(*parts: str) -> str:
    digest = sha256("\x1f".join(parts).encode()).hexdigest()[:24]
    return f"azure:legacy-role-assignment:{digest}"


def _unavailable_state(status: str) -> EvidenceSourceState:
    if status == "disabled":
        return EvidenceSourceState.DISABLED
    if status == "sdk_missing":
        return EvidenceSourceState.SDK_MISSING
    return EvidenceSourceState.UNAVAILABLE


def _observed_at(payload: Mapping[str, Any]) -> datetime | None:
    value = payload.get("observed_at")
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_azure_rbac_inventory(payload: Mapping[str, Any]) -> AuthorizationEvidenceBundle:
    """Adapt today's lossy Azure inventory without overstating completeness."""
    status = _text(payload.get("status")) or "unavailable"
    subscription_id = _text(payload.get("subscription_id")) or _text(payload.get("account_id"))
    scope = f"/subscriptions/{subscription_id}" if subscription_id else ""
    assignments = _records(payload.get("role_assignments"))

    if status == "ok":
        assignment_state = EvidenceSourceState.PARTIAL
        role_state = EvidenceSourceState.PARTIAL if assignments else EvidenceSourceState.UNAVAILABLE
    else:
        assignment_state = _unavailable_state(status)
        role_state = assignment_state

    bindings: list[AuthorizationBinding] = []
    roles: dict[str, RoleDefinitionEvidence] = {}
    has_group_assignment = False
    for assignment in assignments:
        principal_id = _text(assignment.get("principal_id"))
        principal_type = _text(assignment.get("principal_type")).lower()
        role_id = _text(assignment.get("role_definition_id")) or _text(assignment.get("role_name"))
        assignment_scope = _text(assignment.get("scope"))
        if not principal_id or not role_id or not assignment_scope:
            continue
        has_group_assignment = has_group_assignment or principal_type == "group"
        condition_text = _text(assignment.get("condition"))
        condition = (
            AuthorizationCondition(
                ConditionLanguage.AZURE_ABAC,
                condition_text,
                _text(assignment.get("condition_version")) or None,
            )
            if condition_text
            else None
        )
        binding_id = _text(assignment.get("id")) or _stable_id(principal_id, principal_type, role_id, assignment_scope)
        bindings.append(
            AuthorizationBinding(
                binding_id=binding_id,
                effect=AuthorizationEffect.ALLOW,
                principal_id=principal_id,
                principal_type=principal_type,
                scope=assignment_scope,
                role_id=role_id,
                plane=AuthorizationPlane.ANY,
                condition=condition,
                source="azure.roleAssignments.listForSubscription",
            )
        )
        roles.setdefault(
            role_id,
            RoleDefinitionEvidence(
                role_id=role_id,
                completeness=EvidenceSourceState.PARTIAL,
                source="azure.roleDefinitions.getById",
                diagnostics=("legacy_payload_omits_role_permissions",),
            ),
        )

    sources = [
        EvidenceSource(
            "role_assignments",
            assignment_state,
            diagnostics=(("legacy_payload_omits_assignment_metadata",) if status == "ok" else (status,)),
            provenance=("azure.roleAssignments.listForSubscription",),
        ),
        EvidenceSource(
            "role_definitions",
            role_state,
            diagnostics=(("legacy_payload_retains_role_name_only",) if status == "ok" else (status,)),
            provenance=("azure.roleDefinitions.getById",),
        ),
        EvidenceSource(
            "deny_assignments",
            EvidenceSourceState.UNSUPPORTED if status == "ok" else _unavailable_state(status),
            diagnostics=("collector_does_not_read_deny_assignments",),
        ),
    ]
    required_sources = ["role_assignments", "role_definitions", "deny_assignments"]
    if has_group_assignment:
        groups = _records(payload.get("entra_groups"))
        membership_state = EvidenceSourceState.PARTIAL if groups else EvidenceSourceState.UNAVAILABLE
        sources.append(
            EvidenceSource(
                "group_memberships",
                membership_state,
                diagnostics=("legacy_payload_memberships_are_direct_and_bounded",),
                provenance=("microsoft_graph.groups.members",),
            )
        )
        required_sources.append("group_memberships")

    return AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.AZURE,
        scope=scope,
        observed_at=_observed_at(payload),
        sources=tuple(sources),
        required_sources=tuple(required_sources),
        bindings=tuple(sorted(bindings, key=lambda item: item.binding_id)),
        role_definitions=tuple(sorted(roles.values(), key=lambda item: item.role_id)),
        diagnostics=("legacy_azure_inventory_is_not_decision_complete",),
    )


__all__ = ["normalize_azure_rbac_inventory"]
