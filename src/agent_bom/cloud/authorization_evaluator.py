"""Fail-closed evaluation of normalized cloud authorization evidence."""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Sequence

from agent_bom.cloud.authorization_evidence import (
    AuthorizationBinding,
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationEvaluation,
    AuthorizationEvidenceBundle,
    AuthorizationPlane,
    AuthorizationProvider,
    AuthorizationRequest,
    EvidenceSourceState,
    RoleDefinitionEvidence,
)


def _identity_matches(left: str, right: str) -> bool:
    return left.strip().casefold() == right.strip().casefold()


def _principal_identifier_matches(bundle: AuthorizationEvidenceBundle, identifier: str, principal_id: str) -> bool:
    normalized = identifier.strip()
    if normalized == "*":
        return True
    if bundle.provider is AuthorizationProvider.GCP and normalized.casefold() in {
        "allusers",
        "allauthenticatedusers",
        "principalset://goog/public:all",
    }:
        return True
    if _identity_matches(normalized, principal_id):
        return True
    return any(
        _identity_matches(membership.principal_id, principal_id) and _identity_matches(membership.group_id, normalized)
        for membership in bundle.memberships
    )


def _principal_matches(bundle: AuthorizationEvidenceBundle, binding: AuthorizationBinding, principal_id: str) -> bool:
    return _principal_identifier_matches(bundle, binding.principal_id, principal_id)


def _principal_is_excluded(bundle: AuthorizationEvidenceBundle, binding: AuthorizationBinding, principal_id: str) -> bool:
    return any(_principal_identifier_matches(bundle, excluded, principal_id) for excluded in binding.excluded_principals)


def _scope_contains(
    provider: AuthorizationProvider,
    scope: str,
    resource: str,
    *,
    applies_to_children: bool,
    allow_wildcard: bool,
) -> bool:
    normalized_scope = scope.strip().rstrip("/")
    candidate = resource.strip().rstrip("/")
    if allow_wildcard and normalized_scope == "*":
        return True
    if not normalized_scope or normalized_scope == "*" or not candidate:
        return False
    if provider is AuthorizationProvider.AZURE:
        normalized_scope = normalized_scope.casefold()
        candidate = candidate.casefold()
    if candidate == normalized_scope:
        return True
    return applies_to_children and candidate.startswith(f"{normalized_scope}/")


def _resource_within_bundle(bundle: AuthorizationEvidenceBundle, resource: str) -> bool:
    """Constrain every decision to the concrete evidence boundary.

    A binding-level ``*`` means every resource *inside* the bundle, never every
    tenant/account. Cross-hierarchy ancestry must be normalized by a provider
    adapter before reaching this foundation evaluator.
    """
    if _scope_contains(
        bundle.provider,
        bundle.scope,
        resource,
        applies_to_children=True,
        allow_wildcard=False,
    ):
        return True
    return bundle.scope in _resource_scope_chain(bundle, resource)


def _resource_scope_chain(bundle: AuthorizationEvidenceBundle, resource: str) -> tuple[str, ...]:
    """Return ancestry only when one unambiguous canonical record applies."""
    candidate = resource.strip().rstrip("/")
    matches = [
        item
        for item in bundle.resource_ancestry
        if candidate == item.resource.rstrip("/") or candidate.startswith(f"{item.resource.rstrip('/')}/")
    ]
    if not matches:
        return ()
    longest = max(len(item.resource.rstrip("/")) for item in matches)
    most_specific = [item for item in matches if len(item.resource.rstrip("/")) == longest]
    if len(most_specific) != 1:
        return ()
    item = most_specific[0]
    return (item.resource.rstrip("/"), *item.ancestors)


def _scope_matches(bundle: AuthorizationEvidenceBundle, binding: AuthorizationBinding, resource: str) -> bool:
    if _scope_contains(
        bundle.provider,
        binding.scope,
        resource,
        applies_to_children=binding.applies_to_children,
        allow_wildcard=True,
    ):
        return True
    return binding.applies_to_children and binding.scope in _resource_scope_chain(bundle, resource)


def _plane_matches(binding_plane: AuthorizationPlane, request_plane: AuthorizationPlane) -> bool:
    return AuthorizationPlane.ANY in {binding_plane, request_plane} or binding_plane is request_plane


def _pattern_matches(provider: AuthorizationProvider, value: str, patterns: Sequence[str]) -> bool:
    if provider is AuthorizationProvider.AZURE:
        candidate = value.casefold()
        return any(fnmatchcase(candidate, pattern.casefold()) for pattern in patterns)
    return any(fnmatchcase(value, pattern) for pattern in patterns)


def _permission_sets(
    bundle: AuthorizationEvidenceBundle,
    binding: AuthorizationBinding,
    plane: AuthorizationPlane,
) -> tuple[tuple[str, ...], tuple[str, ...], RoleDefinitionEvidence | None]:
    role = bundle.role_definition(binding.role_id) if binding.role_id else None
    if plane is AuthorizationPlane.DATA:
        included = binding.data_permissions or (role.data_permissions if role else ())
        excluded = binding.excluded_data_permissions or (role.excluded_data_permissions if role else ())
    elif plane is AuthorizationPlane.CONTROL:
        included = binding.permissions or (role.permissions if role else ())
        excluded = binding.excluded_permissions or (role.excluded_permissions if role else ())
    else:
        included = binding.permissions + binding.data_permissions
        excluded = binding.excluded_permissions + binding.excluded_data_permissions
        if not included and role:
            included = role.permissions + role.data_permissions
            excluded = role.excluded_permissions + role.excluded_data_permissions
    return included, excluded, role


def _action_matches(
    bundle: AuthorizationEvidenceBundle,
    binding: AuthorizationBinding,
    request: AuthorizationRequest,
) -> tuple[bool, RoleDefinitionEvidence | None]:
    included, excluded, role = _permission_sets(bundle, binding, request.plane)
    matches = bool(included) and _pattern_matches(bundle.provider, request.action, included)
    if matches and excluded and _pattern_matches(bundle.provider, request.action, excluded):
        matches = False
    return matches, role


def _applicable(
    bundle: AuthorizationEvidenceBundle,
    binding: AuthorizationBinding,
    request: AuthorizationRequest,
) -> tuple[bool, RoleDefinitionEvidence | None]:
    if not _context_applies(bundle, binding, request):
        return False, None
    return _action_matches(bundle, binding, request)


def _context_applies(
    bundle: AuthorizationEvidenceBundle,
    binding: AuthorizationBinding,
    request: AuthorizationRequest,
) -> bool:
    if not _principal_matches(bundle, binding, request.principal_id):
        return False
    if _principal_is_excluded(bundle, binding, request.principal_id):
        return False
    if not _scope_matches(bundle, binding, request.resource):
        return False
    return _plane_matches(binding.plane, request.plane)


def _target_principal_applies(
    bundle: AuthorizationEvidenceBundle,
    binding: AuthorizationBinding,
    request: AuthorizationRequest,
) -> bool:
    return _principal_matches(bundle, binding, request.principal_id) and not _principal_is_excluded(
        bundle,
        binding,
        request.principal_id,
    )


def _record_role_diagnostic(
    diagnostics: list[str],
    duplicate_role_ids: set[str],
    binding: AuthorizationBinding,
    role: RoleDefinitionEvidence | None,
) -> None:
    if not binding.role_id:
        return
    if binding.role_id in duplicate_role_ids:
        diagnostics.append(f"role:{binding.role_id}:duplicate")
    elif role is None:
        diagnostics.append(f"role:{binding.role_id}:missing")
    elif role.completeness is not EvidenceSourceState.COMPLETE:
        diagnostics.append(f"role:{role.role_id}:{role.completeness.value}")


def evaluate_authorization(bundle: AuthorizationEvidenceBundle, request: AuthorizationRequest) -> AuthorizationEvaluation:
    """Evaluate one request without converting absent evidence into a decision.

    Matching explicit denies are useful even in a partial bundle.  An allow or
    implicit deny, however, requires a non-empty ``required_sources`` contract,
    every named source, and every referenced role definition to be complete.
    """
    if (
        request.provider is not bundle.provider
        or not request.principal_id.strip()
        or not request.action.strip()
        or not request.resource.strip()
    ):
        return AuthorizationEvaluation(AuthorizationDecision.INDETERMINATE, diagnostics=("invalid_request",))
    if not _resource_within_bundle(bundle, request.resource):
        return AuthorizationEvaluation(
            AuthorizationDecision.INDETERMINATE,
            diagnostics=("resource_outside_bundle_scope",),
        )
    if bundle.provider is not AuthorizationProvider.GCP and any(
        binding.effect is AuthorizationEffect.BOUNDARY for binding in bundle.bindings
    ):
        return AuthorizationEvaluation(
            AuthorizationDecision.INDETERMINATE,
            diagnostics=("unsupported_boundary_provider",),
        )

    duplicate_role_ids = set(bundle.duplicate_role_ids())
    diagnostics = [f"source:{name}:duplicate" for name in bundle.duplicate_source_names()]
    diagnostics.extend(f"role:{role_id}:duplicate" for role_id in duplicate_role_ids)
    diagnostics.extend(item for item in bundle.incomplete_required_sources() if not item.endswith(":duplicate"))

    uncertain_deny = False
    matched_denies: list[str] = []
    for binding in bundle.bindings:
        if binding.effect is not AuthorizationEffect.DENY:
            continue
        if not _context_applies(bundle, binding, request):
            continue
        matches, role = _action_matches(bundle, binding, request)
        _record_role_diagnostic(diagnostics, duplicate_role_ids, binding, role)
        if not matches:
            continue
        if binding.condition is None:
            matched_denies.append(binding.binding_id)
        else:
            uncertain_deny = True
    if matched_denies:
        return AuthorizationEvaluation(
            AuthorizationDecision.EXPLICIT_DENY,
            matched_deny_bindings=tuple(sorted(set(matched_denies))),
        )

    if uncertain_deny:
        diagnostics.append("unevaluated_deny_condition")

    matched_allows: list[str] = []
    uncertain_allow = False
    applicable_boundaries: list[tuple[AuthorizationBinding, bool]] = []
    for binding in bundle.bindings:
        if binding.effect not in {AuthorizationEffect.ALLOW, AuthorizationEffect.BOUNDARY}:
            continue
        if binding.effect is AuthorizationEffect.BOUNDARY and not _target_principal_applies(bundle, binding, request):
            continue
        matches, role = _applicable(bundle, binding, request)
        if _context_applies(bundle, binding, request):
            _record_role_diagnostic(diagnostics, duplicate_role_ids, binding, role)
        if binding.effect is AuthorizationEffect.BOUNDARY:
            applicable_boundaries.append((binding, matches))
        if not matches or binding.effect is not AuthorizationEffect.ALLOW:
            continue
        if binding.condition is not None:
            uncertain_allow = True
        else:
            matched_allows.append(binding.binding_id)

    # GCP PABs are additive. One matching unconditional boundary establishes
    # resource eligibility. If none does, an unevaluated conditional binding
    # prevents a hard boundary decision even when its allowed scope did not
    # match: the condition might be false, in which case the PAB does not apply.
    if applicable_boundaries and not any(matches and binding.condition is None for binding, matches in applicable_boundaries):
        if any(binding.condition is not None for binding, _matches in applicable_boundaries):
            diagnostics.append("unevaluated_boundary_condition")
        elif not diagnostics:
            return AuthorizationEvaluation(AuthorizationDecision.IMPLICIT_DENY, diagnostics=("boundary_excluded",))

    if diagnostics:
        return AuthorizationEvaluation(
            AuthorizationDecision.INDETERMINATE,
            diagnostics=tuple(sorted(set(diagnostics))),
        )
    if matched_allows:
        return AuthorizationEvaluation(
            AuthorizationDecision.ALLOW,
            matched_allow_bindings=tuple(sorted(set(matched_allows))),
        )
    if uncertain_allow:
        return AuthorizationEvaluation(AuthorizationDecision.INDETERMINATE, diagnostics=("unevaluated_allow_condition",))
    return AuthorizationEvaluation(AuthorizationDecision.IMPLICIT_DENY)


__all__ = ["evaluate_authorization"]
