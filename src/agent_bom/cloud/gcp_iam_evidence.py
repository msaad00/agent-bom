"""Normalize the current GCP inventory payload into authorization evidence."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from typing import Any, Mapping

from agent_bom.cloud.authorization_evidence import (
    AuthorizationBinding,
    AuthorizationEffect,
    AuthorizationEvidenceBundle,
    AuthorizationPlane,
    AuthorizationProvider,
    EvidenceSource,
    EvidenceSourceState,
    PrincipalMembership,
    RoleDefinitionEvidence,
)


def _records(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, Mapping))


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(sorted({_text(item) for item in value if _text(item)}))


def _stable_id(*parts: str) -> str:
    digest = sha256("\x1f".join(parts).encode()).hexdigest()[:24]
    return f"gcp:legacy-iam-binding:{digest}"


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


def _principal_id(principal: Mapping[str, Any], *, is_group: bool) -> str:
    email = _text(principal.get("email")) or _text(principal.get("arn")) or _text(principal.get("principal_id"))
    if not email:
        return ""
    if ":" in email:
        return email
    return f"group:{email}" if is_group else f"serviceAccount:{email}"


def normalize_gcp_iam_inventory(payload: Mapping[str, Any]) -> AuthorizationEvidenceBundle:
    """Adapt today's flattened GCP IAM view without treating it as complete."""
    status = _text(payload.get("status")) or "unavailable"
    project_id = _text(payload.get("project_id")) or _text(payload.get("account_id"))
    scope = f"projects/{project_id}" if project_id else ""
    service_accounts = _records(payload.get("service_accounts"))
    groups = _records(payload.get("groups"))

    if status == "ok":
        allow_state = EvidenceSourceState.PARTIAL
        role_state = EvidenceSourceState.PARTIAL
    else:
        allow_state = _unavailable_state(status)
        role_state = allow_state

    bindings: dict[str, AuthorizationBinding] = {}
    role_permissions: dict[str, set[str]] = {}
    memberships: list[PrincipalMembership] = []
    for is_group, principals in ((False, service_accounts), (True, groups)):
        for principal in principals:
            normalized_principal = _principal_id(principal, is_group=is_group)
            if not normalized_principal:
                continue
            principal_type = "group" if is_group else "serviceaccount"
            for policy in _records(principal.get("policies")):
                role_id = _text(policy.get("policy_id")) or _text(policy.get("policy_name"))
                if not role_id:
                    continue
                permissions = _strings(policy.get("permissions"))
                role_permissions.setdefault(role_id, set()).update(permissions)
                binding_id = _stable_id(normalized_principal, principal_type, role_id, scope)
                bindings[binding_id] = AuthorizationBinding(
                    binding_id=binding_id,
                    effect=AuthorizationEffect.ALLOW,
                    principal_id=normalized_principal,
                    principal_type=principal_type,
                    scope=scope,
                    role_id=role_id,
                    plane=AuthorizationPlane.ANY,
                    source="gcp.projects.getIamPolicy.flattened",
                )
            if is_group:
                for member in _records(principal.get("members")):
                    member_id = _text(member.get("id")) or _text(member.get("email"))
                    if member_id:
                        memberships.append(
                            PrincipalMembership(
                                principal_id=member_id,
                                group_id=normalized_principal,
                                source="gcp.legacy_group_members",
                            )
                        )

    roles = tuple(
        RoleDefinitionEvidence(
            role_id=role_id,
            permissions=tuple(sorted(permissions)),
            completeness=EvidenceSourceState.PARTIAL,
            source="gcp.iam.roles.get",
            diagnostics=("legacy_payload_may_truncate_or_omit_role_permissions",),
        )
        for role_id, permissions in sorted(role_permissions.items())
    )
    sources = [
        EvidenceSource(
            "allow_policies",
            allow_state,
            diagnostics=(("legacy_payload_flattens_project_bindings_and_conditions",) if status == "ok" else (status,)),
            provenance=("gcp.projects.getIamPolicy",),
        ),
        EvidenceSource(
            "role_definitions",
            role_state,
            diagnostics=(("legacy_payload_role_permissions_are_bounded",) if status == "ok" else (status,)),
            provenance=("gcp.iam.roles.get",),
        ),
        EvidenceSource(
            "resource_hierarchy",
            EvidenceSourceState.PARTIAL if status == "ok" else _unavailable_state(status),
            diagnostics=("legacy_payload_does_not_prove_effective_policy_ancestry",),
        ),
        EvidenceSource(
            "deny_policies",
            EvidenceSourceState.UNSUPPORTED if status == "ok" else _unavailable_state(status),
            diagnostics=("collector_does_not_read_iam_v2_deny_policies",),
        ),
        EvidenceSource(
            "principal_access_boundaries",
            EvidenceSourceState.UNSUPPORTED if status == "ok" else _unavailable_state(status),
            diagnostics=("collector_does_not_read_iam_v3_pab_policies",),
        ),
    ]
    required_sources = [
        "allow_policies",
        "role_definitions",
        "resource_hierarchy",
        "deny_policies",
        "principal_access_boundaries",
    ]
    if groups:
        unresolved = any(_text(group.get("members_expansion")) == "unresolved" for group in groups)
        membership_state = EvidenceSourceState.UNAVAILABLE if unresolved or not memberships else EvidenceSourceState.PARTIAL
        sources.append(
            EvidenceSource(
                "group_memberships",
                membership_state,
                diagnostics=("legacy_payload_does_not_prove_transitive_membership",),
            )
        )
        required_sources.append("group_memberships")

    return AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.GCP,
        scope=scope,
        observed_at=_observed_at(payload),
        sources=tuple(sources),
        required_sources=tuple(required_sources),
        bindings=tuple(bindings[key] for key in sorted(bindings)),
        role_definitions=roles,
        memberships=tuple(sorted(memberships, key=lambda item: (item.group_id, item.principal_id))),
        diagnostics=("legacy_gcp_inventory_is_not_decision_complete",),
    )


__all__ = ["normalize_gcp_iam_inventory"]
