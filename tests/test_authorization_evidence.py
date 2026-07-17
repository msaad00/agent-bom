from __future__ import annotations

import json
from datetime import datetime, timezone

from agent_bom.cloud.authorization_evidence import (
    AuthorizationBinding,
    AuthorizationEffect,
    AuthorizationEvidenceBundle,
    AuthorizationPlane,
    AuthorizationProvider,
    EvidenceSource,
    EvidenceSourceState,
    RoleDefinitionEvidence,
)


def test_bundle_serializes_source_completeness_and_provenance() -> None:
    observed_at = datetime(2026, 7, 17, 16, 0, tzinfo=timezone.utc)
    bundle = AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.GCP,
        scope="projects/proj-1",
        observed_at=observed_at,
        sources=(
            EvidenceSource("allow_policies", EvidenceSourceState.COMPLETE, provenance=("projects.getIamPolicy",)),
            EvidenceSource("deny_policies", EvidenceSourceState.ACCESS_DENIED, diagnostics=("permission_denied",)),
        ),
        required_sources=("allow_policies", "deny_policies"),
        bindings=(
            AuthorizationBinding(
                binding_id="binding-1",
                effect=AuthorizationEffect.ALLOW,
                principal_id="serviceAccount:ci@proj-1.iam.gserviceaccount.com",
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
                completeness=EvidenceSourceState.COMPLETE,
                source="iam.roles.get",
            ),
        ),
    )

    payload = bundle.to_dict()
    assert payload["provider"] == "gcp"
    assert payload["observed_at"] == "2026-07-17T16:00:00+00:00"
    assert payload["sources"][1] == {
        "name": "deny_policies",
        "state": "access_denied",
        "diagnostics": ["permission_denied"],
        "provenance": [],
    }
    assert json.loads(json.dumps(payload)) == payload


def test_missing_required_source_is_not_complete() -> None:
    bundle = AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.AZURE,
        scope="/subscriptions/sub-1",
        sources=(EvidenceSource("role_assignments", EvidenceSourceState.COMPLETE),),
        required_sources=("role_assignments", "deny_assignments"),
    )

    assert bundle.incomplete_required_sources() == ("deny_assignments:missing",)
