from __future__ import annotations

from dataclasses import replace

import pytest

from agent_bom.cloud.authorization_evaluator import evaluate_authorization
from agent_bom.cloud.authorization_evidence import (
    AuthorizationBinding,
    AuthorizationCondition,
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationEvidenceBundle,
    AuthorizationPlane,
    AuthorizationProvider,
    AuthorizationRequest,
    ConditionLanguage,
    EvidenceSource,
    EvidenceSourceState,
    PrincipalMembership,
    ResourceAncestry,
    RoleDefinitionEvidence,
)

_PRINCIPAL = "serviceAccount:ci@proj-1.iam.gserviceaccount.com"


def _bundle(
    *, role_state: EvidenceSourceState = EvidenceSourceState.COMPLETE, deny_state: EvidenceSourceState = EvidenceSourceState.COMPLETE
) -> AuthorizationEvidenceBundle:
    return AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.GCP,
        scope="projects/proj-1",
        sources=(
            EvidenceSource("allow_policies", EvidenceSourceState.COMPLETE),
            EvidenceSource("role_definitions", role_state),
            EvidenceSource("deny_policies", deny_state),
            EvidenceSource("principal_access_boundaries", EvidenceSourceState.COMPLETE),
        ),
        required_sources=("allow_policies", "role_definitions", "deny_policies", "principal_access_boundaries"),
        bindings=(
            AuthorizationBinding(
                binding_id="allow-storage-read",
                effect=AuthorizationEffect.ALLOW,
                principal_id=_PRINCIPAL,
                principal_type="serviceaccount",
                scope="projects/proj-1",
                role_id="roles/storage.objectViewer",
                plane=AuthorizationPlane.DATA,
                source="projects.getIamPolicy",
            ),
        ),
        role_definitions=(
            RoleDefinitionEvidence(
                role_id="roles/storage.objectViewer",
                data_permissions=("storage.objects.get",),
                completeness=role_state,
                source="iam.roles.get",
            ),
        ),
    )


def _request(action: str = "storage.objects.get") -> AuthorizationRequest:
    return AuthorizationRequest(
        provider=AuthorizationProvider.GCP,
        principal_id=_PRINCIPAL,
        action=action,
        resource="projects/proj-1/buckets/private-data/objects/report.csv",
        plane=AuthorizationPlane.DATA,
    )


def test_complete_matching_evidence_allows() -> None:
    result = evaluate_authorization(_bundle(), _request())

    assert result.decision is AuthorizationDecision.ALLOW
    assert result.matched_allow_bindings == ("allow-storage-read",)


def _thin_bundle(effect: AuthorizationEffect = AuthorizationEffect.ALLOW) -> AuthorizationEvidenceBundle:
    return AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.GCP,
        scope="projects/proj-1",
        bindings=(
            AuthorizationBinding(
                binding_id=f"thin-{effect.value}",
                effect=effect,
                principal_id=_PRINCIPAL,
                principal_type="serviceaccount",
                scope="projects/proj-1",
                data_permissions=("storage.objects.get",),
                plane=AuthorizationPlane.DATA,
            ),
        ),
    )


def test_empty_required_sources_can_never_allow() -> None:
    result = evaluate_authorization(_thin_bundle(), _request())

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("required_sources:missing",)
    assert result.matched_allow_bindings == ()


def test_empty_required_sources_can_never_imply_deny() -> None:
    result = evaluate_authorization(_thin_bundle(), _request("storage.objects.delete"))

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("required_sources:missing",)


def test_explicit_deny_remains_authoritative_without_required_source_contract() -> None:
    result = evaluate_authorization(_thin_bundle(AuthorizationEffect.DENY), _request())

    assert result.decision is AuthorizationDecision.EXPLICIT_DENY
    assert result.matched_deny_bindings == ("thin-deny",)


@pytest.mark.parametrize("state", [EvidenceSourceState.PARTIAL, EvidenceSourceState.UNAVAILABLE])
def test_incomplete_role_evidence_can_never_allow(state: EvidenceSourceState) -> None:
    result = evaluate_authorization(_bundle(role_state=state), _request())

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert f"role_definitions:{state.value}" in result.diagnostics


def test_unavailable_deny_feed_can_never_allow() -> None:
    result = evaluate_authorization(_bundle(deny_state=EvidenceSourceState.UNAVAILABLE), _request())

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert "deny_policies:unavailable" in result.diagnostics


def test_matching_explicit_deny_wins_even_when_other_sources_are_partial() -> None:
    base = _bundle(role_state=EvidenceSourceState.PARTIAL, deny_state=EvidenceSourceState.PARTIAL)
    denied = AuthorizationEvidenceBundle(
        provider=base.provider,
        scope=base.scope,
        sources=base.sources,
        required_sources=base.required_sources,
        bindings=base.bindings
        + (
            AuthorizationBinding(
                binding_id="deny-storage-read",
                effect=AuthorizationEffect.DENY,
                principal_id=_PRINCIPAL,
                principal_type="serviceaccount",
                scope="projects/proj-1",
                data_permissions=("storage.objects.get",),
                plane=AuthorizationPlane.DATA,
                source="iam.v2.denyPolicies",
            ),
        ),
        role_definitions=base.role_definitions,
    )

    result = evaluate_authorization(denied, _request())

    assert result.decision is AuthorizationDecision.EXPLICIT_DENY
    assert result.matched_deny_bindings == ("deny-storage-read",)


def test_complete_evidence_without_match_is_implicit_deny() -> None:
    result = evaluate_authorization(_bundle(), _request("storage.objects.delete"))

    assert result.decision is AuthorizationDecision.IMPLICIT_DENY


def test_wildcard_binding_cannot_escape_bundle_scope() -> None:
    base = _bundle()
    binding = replace(base.bindings[0], scope="*")
    request = replace(_request(), resource="projects/other/buckets/private-data/objects/report.csv")

    result = evaluate_authorization(replace(base, bindings=(binding,)), request)

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("resource_outside_bundle_scope",)


def test_wildcard_binding_is_confined_to_bundle_scope() -> None:
    base = _bundle()
    binding = replace(base.bindings[0], scope="*")

    result = evaluate_authorization(replace(base, bindings=(binding,)), _request())

    assert result.decision is AuthorizationDecision.ALLOW


@pytest.mark.parametrize(
    "duplicates",
    [
        (
            EvidenceSource("deny_policies", EvidenceSourceState.PARTIAL),
            EvidenceSource("deny_policies", EvidenceSourceState.COMPLETE),
        ),
        (
            EvidenceSource("deny_policies", EvidenceSourceState.COMPLETE),
            EvidenceSource("deny_policies", EvidenceSourceState.PARTIAL),
        ),
    ],
)
def test_duplicate_source_names_are_order_independent_and_fail_closed(
    duplicates: tuple[EvidenceSource, EvidenceSource],
) -> None:
    base = _bundle()
    other_sources = tuple(source for source in base.sources if source.name != "deny_policies")

    result = evaluate_authorization(replace(base, sources=other_sources + duplicates), _request())

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("source:deny_policies:duplicate",)


def test_duplicate_role_ids_fail_closed() -> None:
    base = _bundle()
    conflicting = replace(base.role_definitions[0], data_permissions=("storage.objects.delete",))

    result = evaluate_authorization(replace(base, role_definitions=base.role_definitions + (conflicting,)), _request())

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("role:roles/storage.objectViewer:duplicate",)


def test_missing_referenced_role_is_indeterminate() -> None:
    base = _bundle()

    result = evaluate_authorization(replace(base, role_definitions=()), _request())

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("role:roles/storage.objectViewer:missing",)


def test_conditional_gcp_deny_is_indeterminate() -> None:
    base = _bundle()
    conditional_deny = AuthorizationBinding(
        binding_id="conditional-deny",
        effect=AuthorizationEffect.DENY,
        principal_id=_PRINCIPAL,
        principal_type="serviceaccount",
        scope="projects/proj-1",
        data_permissions=("storage.objects.get",),
        plane=AuthorizationPlane.DATA,
        condition=AuthorizationCondition(ConditionLanguage.CEL, "resource.name.endsWith('/private')"),
    )

    result = evaluate_authorization(replace(base, bindings=base.bindings + (conditional_deny,)), _request())

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("unevaluated_deny_condition",)


def test_boundary_is_rejected_for_non_gcp_provider() -> None:
    boundary = AuthorizationBinding(
        binding_id="unsupported-boundary",
        effect=AuthorizationEffect.BOUNDARY,
        principal_id="principal-1",
        principal_type="serviceprincipal",
        scope="/subscriptions/sub-1",
        permissions=("Microsoft.Storage/storageAccounts/read",),
    )
    bundle = AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.AZURE,
        scope="/subscriptions/sub-1",
        bindings=(boundary,),
    )
    request = AuthorizationRequest(
        provider=AuthorizationProvider.AZURE,
        principal_id="principal-1",
        action="Microsoft.Storage/storageAccounts/read",
        resource="/subscriptions/sub-1/resourceGroups/prod",
        plane=AuthorizationPlane.CONTROL,
    )

    result = evaluate_authorization(bundle, request)

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("unsupported_boundary_provider",)


def test_gcp_boundaries_are_additive() -> None:
    base = _bundle()
    excluded = AuthorizationBinding(
        binding_id="other-project-boundary",
        effect=AuthorizationEffect.BOUNDARY,
        principal_id=_PRINCIPAL,
        principal_type="serviceaccount",
        scope="projects/other",
        data_permissions=("storage.objects.get",),
        plane=AuthorizationPlane.DATA,
    )
    eligible = replace(excluded, binding_id="current-project-boundary", scope="projects/proj-1")

    result = evaluate_authorization(replace(base, bindings=base.bindings + (excluded, eligible)), _request())

    assert result.decision is AuthorizationDecision.ALLOW


def test_unmatched_conditional_boundary_is_indeterminate() -> None:
    base = _bundle()
    boundary = AuthorizationBinding(
        binding_id="conditional-boundary",
        effect=AuthorizationEffect.BOUNDARY,
        principal_id=_PRINCIPAL,
        principal_type="serviceaccount",
        scope="projects/other",
        data_permissions=("storage.objects.get",),
        plane=AuthorizationPlane.DATA,
        condition=AuthorizationCondition(ConditionLanguage.CEL, "principal.type == 'iam.googleapis.com/ServiceAccount'"),
    )

    result = evaluate_authorization(replace(base, bindings=base.bindings + (boundary,)), _request())

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("unevaluated_boundary_condition",)


def test_excluded_group_membership_prevents_deny_match() -> None:
    base = _bundle()
    deny = AuthorizationBinding(
        binding_id="deny-everyone-except-breakglass",
        effect=AuthorizationEffect.DENY,
        principal_id="*",
        principal_type="all",
        scope="projects/proj-1",
        data_permissions=("storage.objects.get",),
        excluded_principals=("group:breakglass@example.com",),
        plane=AuthorizationPlane.DATA,
    )
    membership = PrincipalMembership(
        principal_id=_PRINCIPAL,
        group_id="group:breakglass@example.com",
        source="directory.groups.members",
    )

    result = evaluate_authorization(
        replace(base, bindings=base.bindings + (deny,), memberships=(membership,)),
        _request(),
    )

    assert result.decision is AuthorizationDecision.ALLOW


def test_gcp_all_users_allow_matches_an_arbitrary_principal() -> None:
    base = _bundle()
    public = replace(base.bindings[0], binding_id="public", principal_id="allUsers", principal_type="public")

    result = evaluate_authorization(replace(base, bindings=(public,)), _request())

    assert result.decision is AuthorizationDecision.ALLOW


def test_gcp_all_authenticated_users_allow_matches_an_authenticated_principal() -> None:
    base = _bundle()
    public = replace(base.bindings[0], binding_id="authenticated-public", principal_id="allAuthenticatedUsers", principal_type="public")

    result = evaluate_authorization(replace(base, bindings=(public,)), _request())

    assert result.decision is AuthorizationDecision.ALLOW


def test_gcp_resource_ancestry_confines_and_applies_parent_policy() -> None:
    base = _bundle()
    resource = "//storage.googleapis.com/projects/_/buckets/private-data/objects/report.csv"
    ancestry = ResourceAncestry(
        resource="//storage.googleapis.com/projects/_/buckets/private-data",
        ancestors=("projects/123", "folders/10", "organizations/20"),
        source="cloudasset.assets.list",
    )
    parent_allow = replace(base.bindings[0], binding_id="folder-allow", scope="folders/10")
    request = replace(_request(), resource=resource)

    result = evaluate_authorization(
        replace(base, scope="projects/123", bindings=(parent_allow,), resource_ancestry=(ancestry,)),
        request,
    )

    assert result.decision is AuthorizationDecision.ALLOW


def test_gcp_resource_without_proven_ancestry_cannot_escape_bundle_scope() -> None:
    base = _bundle()
    request = replace(_request(), resource="//storage.googleapis.com/projects/_/buckets/private-data")

    result = evaluate_authorization(replace(base, scope="projects/123"), request)

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("resource_outside_bundle_scope",)


def test_gcp_public_all_deny_matches_an_arbitrary_principal() -> None:
    base = _bundle()
    public_deny = AuthorizationBinding(
        binding_id="public-deny",
        effect=AuthorizationEffect.DENY,
        principal_id="principalSet://goog/public:all",
        principal_type="public",
        scope="projects/proj-1",
        data_permissions=("storage.objects.get",),
        plane=AuthorizationPlane.DATA,
    )

    result = evaluate_authorization(replace(base, bindings=base.bindings + (public_deny,)), _request())

    assert result.decision is AuthorizationDecision.EXPLICIT_DENY
