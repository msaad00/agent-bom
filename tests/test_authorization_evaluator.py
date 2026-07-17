from __future__ import annotations

import pytest

from agent_bom.cloud.authorization_evaluator import evaluate_authorization
from agent_bom.cloud.authorization_evidence import (
    AuthorizationBinding,
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationEvidenceBundle,
    AuthorizationPlane,
    AuthorizationProvider,
    AuthorizationRequest,
    EvidenceSource,
    EvidenceSourceState,
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
