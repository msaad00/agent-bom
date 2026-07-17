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


def _principal_matches(bundle: AuthorizationEvidenceBundle, binding: AuthorizationBinding, principal_id: str) -> bool:
    if _identity_matches(binding.principal_id, principal_id):
        return True
    return any(
        _identity_matches(membership.principal_id, principal_id) and _identity_matches(membership.group_id, binding.principal_id)
        for membership in bundle.memberships
    )


def _scope_matches(provider: AuthorizationProvider, binding: AuthorizationBinding, resource: str) -> bool:
    scope = binding.scope.strip().rstrip("/")
    candidate = resource.strip().rstrip("/")
    if scope == "*":
        return True
    if provider is AuthorizationProvider.AZURE:
        scope = scope.casefold()
        candidate = candidate.casefold()
    if candidate == scope:
        return True
    return binding.applies_to_children and candidate.startswith(f"{scope}/")


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
    if not _principal_matches(bundle, binding, request.principal_id):
        return False, None
    if any(_identity_matches(excluded, request.principal_id) for excluded in binding.excluded_principals):
        return False, None
    if not _scope_matches(bundle.provider, binding, request.resource):
        return False, None
    if not _plane_matches(binding.plane, request.plane):
        return False, None
    return _action_matches(bundle, binding, request)


def evaluate_authorization(bundle: AuthorizationEvidenceBundle, request: AuthorizationRequest) -> AuthorizationEvaluation:
    """Evaluate one request without converting absent evidence into a decision.

    Matching explicit denies are useful even in a partial bundle.  An allow or
    implicit deny, however, requires every source named by ``required_sources``
    and every referenced role definition to be complete.
    """
    if (
        request.provider is not bundle.provider
        or not request.principal_id.strip()
        or not request.action.strip()
        or not request.resource.strip()
    ):
        return AuthorizationEvaluation(AuthorizationDecision.INDETERMINATE, diagnostics=("invalid_request",))

    uncertain_deny = False
    matched_denies: list[str] = []
    for binding in bundle.bindings:
        if binding.effect is not AuthorizationEffect.DENY:
            continue
        matches, _role = _applicable(bundle, binding, request)
        if not matches:
            continue
        if binding.condition is None or bundle.provider is AuthorizationProvider.GCP:
            matched_denies.append(binding.binding_id)
        else:
            uncertain_deny = True
    if matched_denies:
        return AuthorizationEvaluation(
            AuthorizationDecision.EXPLICIT_DENY,
            matched_deny_bindings=tuple(sorted(set(matched_denies))),
        )

    diagnostics = list(bundle.incomplete_required_sources())
    if uncertain_deny:
        diagnostics.append("unevaluated_deny_condition")

    matched_allows: list[str] = []
    uncertain_allow = False
    applicable_boundaries: list[tuple[AuthorizationBinding, bool]] = []
    for binding in bundle.bindings:
        if binding.effect not in {AuthorizationEffect.ALLOW, AuthorizationEffect.BOUNDARY}:
            continue
        matches, role = _applicable(bundle, binding, request)
        if role is not None and role.completeness is not EvidenceSourceState.COMPLETE:
            diagnostics.append(f"role:{role.role_id}:{role.completeness.value}")
        if binding.effect is AuthorizationEffect.BOUNDARY and _principal_matches(bundle, binding, request.principal_id):
            applicable_boundaries.append((binding, matches))
        if not matches or binding.effect is not AuthorizationEffect.ALLOW:
            continue
        if binding.condition is not None:
            uncertain_allow = True
        else:
            matched_allows.append(binding.binding_id)

    if applicable_boundaries and not any(matches and binding.condition is None for binding, matches in applicable_boundaries):
        if any(matches and binding.condition is not None for binding, matches in applicable_boundaries):
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
