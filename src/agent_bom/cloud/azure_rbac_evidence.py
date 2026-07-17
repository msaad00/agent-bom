"""Normalize the current Azure inventory payload into authorization evidence."""

from __future__ import annotations

from dataclasses import replace
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

_ALL_PRINCIPALS_ID = "00000000-0000-0000-0000-000000000000"


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
    value = payload.get("authorization_observed_at") or payload.get("observed_at")
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _state(value: Any, default: EvidenceSourceState = EvidenceSourceState.UNAVAILABLE) -> EvidenceSourceState:
    try:
        return EvidenceSourceState(_text(value))
    except ValueError:
        return default


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(sorted({_text(item) for item in value if _text(item)}))


def _source_records(payload: Mapping[str, Any]) -> tuple[EvidenceSource, ...]:
    sources: list[EvidenceSource] = []
    for item in _records(payload.get("authorization_sources")):
        name = _text(item.get("name"))
        if not name:
            continue
        sources.append(
            EvidenceSource(
                name=name,
                state=_state(item.get("state")),
                diagnostics=_string_tuple(item.get("diagnostics")),
                provenance=_string_tuple(item.get("provenance")),
            )
        )
    return tuple(sorted(sources, key=lambda item: item.name))


def _downgrade_source(
    sources: tuple[EvidenceSource, ...],
    name: str,
    diagnostic: str,
) -> tuple[EvidenceSource, ...]:
    updated: list[EvidenceSource] = []
    for source in sources:
        if source.name != name:
            updated.append(source)
            continue
        state = EvidenceSourceState.PARTIAL if source.state is EvidenceSourceState.COMPLETE else source.state
        updated.append(replace(source, state=state, diagnostics=tuple(sorted({*source.diagnostics, diagnostic}))))
    return tuple(updated)


def _permission_fields(permission_blocks: Any) -> tuple[tuple[str, ...], ...]:
    actions: set[str] = set()
    not_actions: set[str] = set()
    data_actions: set[str] = set()
    not_data_actions: set[str] = set()
    for permission in _records(permission_blocks):
        actions.update(_string_tuple(permission.get("actions")))
        not_actions.update(_string_tuple(permission.get("not_actions")))
        data_actions.update(_string_tuple(permission.get("data_actions")))
        not_data_actions.update(_string_tuple(permission.get("not_data_actions")))
    return (
        tuple(sorted(actions)),
        tuple(sorted(not_actions)),
        tuple(sorted(data_actions)),
        tuple(sorted(not_data_actions)),
    )


def _condition(expression: Any, version: Any) -> AuthorizationCondition | None:
    text = _text(expression)
    if not text:
        return None
    return AuthorizationCondition(ConditionLanguage.AZURE_ABAC, text, _text(version) or None)


def _deny_principal_id(principal: Mapping[str, Any]) -> str:
    principal_id = _text(principal.get("id"))
    principal_type = _text(principal.get("type")).casefold()
    if principal_id.casefold() == _ALL_PRINCIPALS_ID and principal_type == "systemdefined":
        return "*"
    return principal_id


def _authoritative_bundle(payload: Mapping[str, Any], sources: tuple[EvidenceSource, ...]) -> AuthorizationEvidenceBundle:
    subscription_id = _text(payload.get("subscription_id")) or _text(payload.get("account_id"))
    scope = f"/subscriptions/{subscription_id}" if subscription_id else ""

    roles: list[RoleDefinitionEvidence] = []
    for role in _records(payload.get("role_definitions")):
        role_id = _text(role.get("id"))
        if not role_id:
            continue
        permissions, excluded, data_permissions, excluded_data = _permission_fields(role.get("permissions"))
        roles.append(
            RoleDefinitionEvidence(
                role_id=role_id,
                permissions=permissions,
                excluded_permissions=excluded,
                data_permissions=data_permissions,
                excluded_data_permissions=excluded_data,
                completeness=_state(role.get("completeness")),
                source="azure.roleDefinitions.getById",
            )
        )

    bindings: list[AuthorizationBinding] = []
    has_group_reference = False
    for assignment in _records(payload.get("role_assignments")):
        principal_id = _text(assignment.get("principal_id"))
        principal_type = _text(assignment.get("principal_type")).lower()
        role_id = _text(assignment.get("role_definition_id"))
        assignment_scope = _text(assignment.get("scope"))
        if not principal_id or not role_id or not assignment_scope:
            continue
        has_group_reference = has_group_reference or principal_type == "group"
        bindings.append(
            AuthorizationBinding(
                binding_id=_text(assignment.get("id")) or _stable_id(principal_id, principal_type, role_id, assignment_scope),
                effect=AuthorizationEffect.ALLOW,
                principal_id=principal_id,
                principal_type=principal_type,
                scope=assignment_scope,
                role_id=role_id,
                condition=_condition(assignment.get("condition"), assignment.get("condition_version")),
                source="azure.roleAssignments.listForSubscription",
            )
        )

    for deny in _records(payload.get("deny_assignments")):
        deny_id = _text(deny.get("id")) or _text(deny.get("name"))
        deny_scope = _text(deny.get("scope"))
        if not deny_id or not deny_scope:
            sources = _downgrade_source(sources, "deny_assignments", "malformed_deny_assignment")
            continue
        principals = _records(deny.get("principals"))
        if not principals:
            sources = _downgrade_source(sources, "deny_assignments", f"malformed_deny_principals:{deny_id}")
            continue
        excluded_principals = tuple(
            sorted({_text(item.get("id")) for item in _records(deny.get("exclude_principals")) if _text(item.get("id"))})
        )
        permission_blocks = _records(deny.get("permissions"))
        if not permission_blocks:
            sources = _downgrade_source(sources, "deny_assignments", f"malformed_deny_permissions:{deny_id}")
            continue
        for block_index, permission in enumerate(permission_blocks):
            permissions = _string_tuple(permission.get("actions"))
            excluded = _string_tuple(permission.get("not_actions"))
            data_permissions = _string_tuple(permission.get("data_actions"))
            excluded_data = _string_tuple(permission.get("not_data_actions"))
            if not permissions and not data_permissions:
                sources = _downgrade_source(
                    sources,
                    "deny_assignments",
                    f"malformed_deny_permission_block:{deny_id}:{block_index}",
                )
                continue
            condition = _condition(
                permission.get("condition") or deny.get("condition"),
                permission.get("condition_version") or deny.get("condition_version"),
            )
            for principal in principals:
                principal_id = _deny_principal_id(principal)
                if not principal_id:
                    sources = _downgrade_source(
                        sources,
                        "deny_assignments",
                        f"malformed_deny_principal:{deny_id}:{block_index}",
                    )
                    continue
                principal_type = _text(principal.get("type")).lower()
                has_group_reference = has_group_reference or principal_type == "group"
                bindings.append(
                    AuthorizationBinding(
                        binding_id=f"{deny_id}:permission-{block_index}:principal-{principal_id}",
                        effect=AuthorizationEffect.DENY,
                        principal_id=principal_id,
                        principal_type=principal_type,
                        scope=deny_scope,
                        permissions=permissions,
                        excluded_permissions=excluded,
                        data_permissions=data_permissions,
                        excluded_data_permissions=excluded_data,
                        excluded_principals=excluded_principals,
                        condition=condition,
                        applies_to_children=not bool(deny.get("do_not_apply_to_child_scopes", False)),
                        source="azure.denyAssignments.list",
                    )
                )

    required_sources = ["role_assignments", "role_definitions", "deny_assignments"]
    mutable_sources = list(sources)
    if has_group_reference:
        mutable_sources.append(
            EvidenceSource(
                "group_memberships",
                EvidenceSourceState.PARTIAL if _records(payload.get("entra_groups")) else EvidenceSourceState.UNAVAILABLE,
                diagnostics=("transitive_group_memberships_not_collected",),
                provenance=("microsoft_graph.groups.members",),
            )
        )
        required_sources.append("group_memberships")

    return AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.AZURE,
        scope=scope,
        observed_at=_observed_at(payload),
        sources=tuple(sorted(mutable_sources, key=lambda item: item.name)),
        required_sources=tuple(required_sources),
        bindings=tuple(sorted(bindings, key=lambda item: item.binding_id)),
        role_definitions=tuple(sorted(roles, key=lambda item: item.role_id)),
    )


def normalize_azure_rbac_inventory(payload: Mapping[str, Any]) -> AuthorizationEvidenceBundle:
    """Adapt today's lossy Azure inventory without overstating completeness."""
    authoritative_sources = _source_records(payload)
    if authoritative_sources:
        return _authoritative_bundle(payload, authoritative_sources)

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
        condition = _condition(assignment.get("condition"), assignment.get("condition_version"))
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
