from __future__ import annotations

from agent_bom.cloud.authorization_evaluator import evaluate_authorization
from agent_bom.cloud.authorization_evidence import (
    AuthorizationDecision,
    AuthorizationPlane,
    AuthorizationProvider,
    AuthorizationRequest,
    EvidenceSourceState,
)
from agent_bom.cloud.gcp_iam_evidence import normalize_gcp_iam_inventory


def _current_payload() -> dict[str, object]:
    return {
        "provider": "gcp",
        "status": "ok",
        "project_id": "proj-1",
        "account_id": "proj-1",
        "service_accounts": [
            {
                "principal_id": "sa-1",
                "email": "ci@proj-1.iam.gserviceaccount.com",
                "principal_type": "service-account",
                "roles": ["roles/storage.objectViewer"],
                "policies": [
                    {
                        "policy_id": "roles/storage.objectViewer",
                        "policy_name": "roles/storage.objectViewer",
                        "permissions": ["storage.objects.get", "storage.objects.list"],
                        "source_field": "projects.getIamPolicy.bindings",
                    }
                ],
            }
        ],
        "groups": [],
        "warnings": [],
        "missing_permissions": [],
    }


def test_current_gcp_flattened_policy_payload_is_partial_and_cannot_allow() -> None:
    bundle = normalize_gcp_iam_inventory(_current_payload())

    assert bundle.provider is AuthorizationProvider.GCP
    assert bundle.source_state("allow_policies") is EvidenceSourceState.PARTIAL
    assert bundle.source_state("role_definitions") is EvidenceSourceState.PARTIAL
    assert bundle.source_state("deny_policies") is EvidenceSourceState.UNSUPPORTED
    assert bundle.source_state("principal_access_boundaries") is EvidenceSourceState.UNSUPPORTED
    assert bundle.role_definitions[0].permissions == ("storage.objects.get", "storage.objects.list")

    result = evaluate_authorization(
        bundle,
        AuthorizationRequest(
            provider=AuthorizationProvider.GCP,
            principal_id="serviceAccount:ci@proj-1.iam.gserviceaccount.com",
            action="storage.objects.get",
            resource="projects/proj-1/buckets/private-data/objects/report.csv",
            plane=AuthorizationPlane.CONTROL,
        ),
    )
    assert result.decision is AuthorizationDecision.INDETERMINATE


def test_current_gcp_group_membership_is_explicitly_unavailable() -> None:
    payload = _current_payload()
    payload["groups"] = [
        {
            "principal_id": "admins@example.com",
            "principal_type": "group",
            "roles": ["roles/owner"],
            "policies": [{"policy_id": "roles/owner", "permissions": ["resourcemanager.projects.setIamPolicy"]}],
            "members": [],
            "members_expansion": "unresolved",
        }
    ]

    bundle = normalize_gcp_iam_inventory(payload)

    assert bundle.source_state("group_memberships") is EvidenceSourceState.UNAVAILABLE
    assert "group_memberships" in bundle.required_sources


def test_gcp_legacy_binding_id_is_stable() -> None:
    first = normalize_gcp_iam_inventory(_current_payload())
    second = normalize_gcp_iam_inventory(_current_payload())

    assert first.bindings[0].binding_id == second.bindings[0].binding_id
