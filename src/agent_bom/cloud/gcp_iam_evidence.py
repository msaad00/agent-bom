"""Normalize the current GCP inventory payload into authorization evidence."""

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
    PrincipalMembership,
    ResourceAncestry,
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


def _ordered_strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict.fromkeys(_text(item) for item in value if _text(item)))


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
    value = payload.get("iam_observed_at") or payload.get("observed_at")
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


def _state(value: Any, default: EvidenceSourceState = EvidenceSourceState.UNAVAILABLE) -> EvidenceSourceState:
    try:
        return EvidenceSourceState(_text(value))
    except ValueError:
        return default


def _source_records(payload: Mapping[str, Any]) -> tuple[EvidenceSource, ...]:
    sources: list[EvidenceSource] = []
    for item in _records(payload.get("iam_sources")):
        name = _text(item.get("name"))
        if not name:
            continue
        sources.append(
            EvidenceSource(
                name=name,
                state=_state(item.get("state")),
                diagnostics=_strings(item.get("diagnostics")),
                provenance=_strings(item.get("provenance")),
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


def _condition(value: Any) -> AuthorizationCondition | None:
    if not isinstance(value, Mapping):
        return None
    expression = _text(value.get("expression"))
    if not expression:
        return None
    return AuthorizationCondition(ConditionLanguage.CEL, expression)


def _deny_principal(value: Any) -> str:
    principal = _text(value)
    if principal.casefold() == "principalset://goog/public:all":
        return "*"
    marker = "/serviceAccounts/"
    if marker in principal:
        return f"serviceAccount:{principal.rsplit(marker, 1)[-1]}"
    return principal


def _deny_permission(value: Any) -> str:
    permission = _text(value)
    if ".googleapis.com/" not in permission:
        return permission
    service, suffix = permission.split(".googleapis.com/", 1)
    return f"{service}.{suffix}"


def _authoritative_bundle(payload: Mapping[str, Any], sources: tuple[EvidenceSource, ...]) -> AuthorizationEvidenceBundle:
    project_id = _text(payload.get("project_id")) or _text(payload.get("account_id"))
    scope = _text(payload.get("iam_scope")) or (f"projects/{project_id}" if project_id else "")
    bindings: list[AuthorizationBinding] = []
    roles: list[RoleDefinitionEvidence] = []
    resource_ancestry: list[ResourceAncestry] = []
    has_group_binding = False

    for role in _records(payload.get("role_definitions")):
        role_id = _text(role.get("id"))
        if not role_id:
            continue
        deleted = bool(role.get("deleted", False))
        disabled = _text(role.get("stage")).casefold() == "disabled"
        completeness = EvidenceSourceState.UNAVAILABLE if deleted or disabled else _state(role.get("completeness"))
        diagnostics = tuple(item for item, applies in (("role_deleted", deleted), ("role_disabled", disabled)) if applies)
        roles.append(
            RoleDefinitionEvidence(
                role_id=role_id,
                permissions=() if deleted or disabled else _strings(role.get("permissions")),
                completeness=completeness,
                source="gcp.iam.roles.get",
                diagnostics=diagnostics,
            )
        )

    for policy in _records(payload.get("allow_policies")):
        resource = _text(policy.get("resource"))
        if not resource:
            sources = _downgrade_source(sources, "allow_policies", "malformed_allow_policy_resource")
            continue
        ancestors = _ordered_strings(policy.get("ancestors"))
        if ancestors:
            resource_ancestry.append(
                ResourceAncestry(
                    resource=resource,
                    ancestors=ancestors,
                    source="gcp.cloudasset.assets.listIamPolicy",
                )
            )
        elif resource.startswith("//"):
            sources = _downgrade_source(sources, "allow_policies", f"missing_resource_ancestry:{resource}")
        for binding in _records(policy.get("bindings")):
            role_id = _text(binding.get("role"))
            binding_id = _text(binding.get("id"))
            if not role_id or not binding_id:
                continue
            for member in _strings(binding.get("members")):
                principal_type = (
                    "public" if member.casefold() in {"allusers", "allauthenticatedusers"} else member.partition(":")[0].lower()
                )
                has_group_binding = has_group_binding or principal_type == "group"
                bindings.append(
                    AuthorizationBinding(
                        binding_id=f"{binding_id}:{member}",
                        effect=AuthorizationEffect.ALLOW,
                        principal_id=member,
                        principal_type=principal_type,
                        scope=resource,
                        role_id=role_id,
                        condition=_condition(binding.get("condition")),
                        source="gcp.cloudasset.assets.listIamPolicy",
                    )
                )

    for policy in _records(payload.get("deny_policies")):
        policy_id = _text(policy.get("name"))
        attachment = _text(policy.get("attachment_point"))
        deny_scope = attachment.removeprefix("cloudresourcemanager.googleapis.com/")
        if not policy_id or not deny_scope:
            sources = _downgrade_source(sources, "deny_policies", "malformed_deny_policy")
            continue
        for rule_index, rule in enumerate(_records(policy.get("rules"))):
            permissions = tuple(sorted({_deny_permission(item) for item in _strings(rule.get("denied_permissions"))}))
            exceptions = tuple(sorted({_deny_permission(item) for item in _strings(rule.get("exception_permissions"))}))
            excluded_principals = tuple(sorted({_deny_principal(item) for item in _strings(rule.get("exception_principals"))}))
            condition = _condition(rule.get("condition"))
            raw_principals = _strings(rule.get("denied_principals"))
            if not raw_principals or not permissions:
                sources = _downgrade_source(sources, "deny_policies", f"malformed_deny_rule:{policy_id}:{rule_index}")
                continue
            for raw_principal in raw_principals:
                principal = _deny_principal(raw_principal)
                if not principal:
                    sources = _downgrade_source(sources, "deny_policies", f"malformed_deny_principal:{policy_id}:{rule_index}")
                    continue
                if principal.casefold().startswith("principalset://") and principal != "*":
                    sources = _downgrade_source(
                        sources,
                        "deny_policies",
                        f"unresolved_deny_principal_set:{principal}",
                    )
                bindings.append(
                    AuthorizationBinding(
                        binding_id=f"{policy_id}:rule-{rule_index}:principal-{principal}",
                        effect=AuthorizationEffect.DENY,
                        principal_id=principal,
                        principal_type="deny-principal",
                        scope=deny_scope,
                        permissions=permissions,
                        excluded_permissions=exceptions,
                        excluded_principals=excluded_principals,
                        condition=condition,
                        source="gcp.iam.v2.policies.list",
                    )
                )

    mutable_sources = list(sources)
    required_sources = [
        "allow_policies",
        "role_definitions",
        "resource_hierarchy",
        "deny_policies",
        "principal_access_boundaries",
    ]
    if has_group_binding:
        mutable_sources.append(
            EvidenceSource(
                "group_memberships",
                EvidenceSourceState.UNAVAILABLE,
                diagnostics=("transitive_google_group_memberships_not_collected",),
            )
        )
        required_sources.append("group_memberships")

    if _records(payload.get("pab_policies")) or _records(payload.get("pab_bindings")):
        sources = _downgrade_source(
            sources,
            "principal_access_boundaries",
            "pab_targets_not_yet_resolved_to_principals",
        )

    return AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.GCP,
        scope=scope,
        observed_at=_observed_at(payload),
        sources=tuple(sorted(mutable_sources, key=lambda item: item.name)),
        required_sources=tuple(required_sources),
        bindings=tuple(sorted(bindings, key=lambda item: item.binding_id)),
        role_definitions=tuple(sorted(roles, key=lambda item: item.role_id)),
        resource_ancestry=tuple(sorted(resource_ancestry, key=lambda item: item.resource)),
    )


def normalize_gcp_iam_inventory(payload: Mapping[str, Any]) -> AuthorizationEvidenceBundle:
    """Adapt today's flattened GCP IAM view without treating it as complete."""
    authoritative_sources = _source_records(payload)
    if authoritative_sources:
        return _authoritative_bundle(payload, authoritative_sources)

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
