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
    ResourceAncestry,
    RoleDefinitionEvidence,
    summarize_authorization_evidence,
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
        resource_ancestry=(
            ResourceAncestry(
                resource="//storage.googleapis.com/projects/_/buckets/private-data",
                ancestors=("projects/123", "folders/10", "organizations/20"),
                source="cloudasset.assets.list",
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
    assert payload["resource_ancestry"] == [
        {
            "resource": "//storage.googleapis.com/projects/_/buckets/private-data",
            "ancestors": ["projects/123", "folders/10", "organizations/20"],
            "source": "cloudasset.assets.list",
        }
    ]
    assert json.loads(json.dumps(payload)) == payload


def test_authorization_summary_counts_complete_partial_and_indeterminate_without_diagnostics() -> None:
    payload = {
        "provider": "gcp",
        "required_sources": ["allow_policies", "deny_policies", "role_definitions", "ancestry"],
        "sources": [
            {"name": "allow_policies", "state": "complete", "diagnostics": ["token=secret"]},
            {"name": "deny_policies", "state": "partial", "provenance": ["private/path"]},
            {"name": "role_definitions", "state": "access_denied", "diagnostics": ["arn:secret"]},
        ],
        "bindings": [{"binding_id": "sensitive-binding"}],
    }

    summary = summarize_authorization_evidence(payload)

    assert summary.to_dict() == {
        "status": "indeterminate",
        "required_source_count": 4,
        "complete_source_count": 1,
        "partial_source_count": 1,
        "indeterminate_source_count": 2,
    }
    assert "secret" not in json.dumps(summary.to_dict())


def test_authorization_summary_is_complete_only_when_every_required_source_is_complete() -> None:
    summary = summarize_authorization_evidence(
        {
            "required_sources": ["bindings", "roles"],
            "sources": [
                {"name": "bindings", "state": "complete"},
                {"name": "roles", "state": "complete"},
            ],
        }
    )

    assert summary.status == "complete"
    assert summary.complete_source_count == 2
    assert summary.partial_source_count == 0
    assert summary.indeterminate_source_count == 0


def test_missing_required_source_is_not_complete() -> None:
    bundle = AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.AZURE,
        scope="/subscriptions/sub-1",
        sources=(EvidenceSource("role_assignments", EvidenceSourceState.COMPLETE),),
        required_sources=("role_assignments", "deny_assignments"),
    )

    assert bundle.incomplete_required_sources() == ("deny_assignments:missing",)


def test_empty_required_source_contract_is_not_complete() -> None:
    bundle = AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.GCP,
        scope="projects/proj-1",
        sources=(EvidenceSource("allow_policies", EvidenceSourceState.COMPLETE),),
    )

    assert bundle.incomplete_required_sources() == ("required_sources:missing",)


def test_duplicate_source_state_is_deterministic_and_incomplete() -> None:
    bundle = AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.GCP,
        scope="projects/proj-1",
        sources=(
            EvidenceSource("deny_policies", EvidenceSourceState.COMPLETE),
            EvidenceSource("deny_policies", EvidenceSourceState.PARTIAL),
        ),
        required_sources=("deny_policies",),
    )

    assert bundle.source_state("deny_policies") is EvidenceSourceState.PARTIAL
    assert bundle.incomplete_required_sources() == ("deny_policies:duplicate",)


def test_duplicate_role_definition_is_not_selected_by_position() -> None:
    role = RoleDefinitionEvidence(
        role_id="roles/storage.objectViewer",
        data_permissions=("storage.objects.get",),
        completeness=EvidenceSourceState.COMPLETE,
    )
    bundle = AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.GCP,
        scope="projects/proj-1",
        role_definitions=(role, role),
    )

    assert bundle.role_definition(role.role_id) is None
    assert bundle.duplicate_role_ids() == (role.role_id,)
