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


def _authoritative_payload() -> dict[str, object]:
    return {
        "status": "ok",
        "project_id": "proj-1",
        "iam_observed_at": "2026-07-17T12:00:00+00:00",
        "iam_hierarchy": ["projects/proj-1", "folders/10", "organizations/20"],
        "allow_policies": [
            {
                "resource": "projects/proj-1",
                "version": 3,
                "bindings": [
                    {
                        "id": "binding-1",
                        "role": "roles/storage.objectViewer",
                        "members": ["serviceAccount:ci@proj-1.iam.gserviceaccount.com"],
                        "condition": None,
                    }
                ],
            }
        ],
        "role_definitions": [
            {
                "id": "roles/storage.objectViewer",
                "permissions": ["storage.objects.get"],
                "completeness": "complete",
            }
        ],
        "deny_policies": [],
        "pab_policies": [],
        "pab_bindings": [],
        "iam_sources": [
            {"name": name, "state": "complete", "diagnostics": [], "provenance": []}
            for name in (
                "allow_policies",
                "role_definitions",
                "resource_hierarchy",
                "deny_policies",
                "principal_access_boundaries",
            )
        ],
    }


def _request(action: str = "storage.objects.get") -> AuthorizationRequest:
    return AuthorizationRequest(
        provider=AuthorizationProvider.GCP,
        principal_id="serviceAccount:ci@proj-1.iam.gserviceaccount.com",
        action=action,
        resource="projects/proj-1/buckets/private-data/objects/report.csv",
        plane=AuthorizationPlane.CONTROL,
    )


def test_authoritative_v3_payload_can_allow() -> None:
    bundle = normalize_gcp_iam_inventory(_authoritative_payload())

    result = evaluate_authorization(bundle, _request())

    assert bundle.source_state("allow_policies") is EvidenceSourceState.COMPLETE
    assert bundle.bindings[0].binding_id == "binding-1:serviceAccount:ci@proj-1.iam.gserviceaccount.com"
    assert result.decision is AuthorizationDecision.ALLOW


def test_authoritative_cel_allow_condition_is_preserved_and_indeterminate() -> None:
    payload = _authoritative_payload()
    payload["allow_policies"][0]["bindings"][0]["condition"] = {  # type: ignore[index]
        "expression": "resource.name.startsWith('projects/proj-1')",
        "title": "project only",
    }
    bundle = normalize_gcp_iam_inventory(payload)

    result = evaluate_authorization(bundle, _request())

    assert bundle.bindings[0].condition is not None
    assert bundle.bindings[0].condition.expression.startswith("resource.name")
    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("unevaluated_allow_condition",)


def test_authoritative_deny_policy_is_normalized() -> None:
    payload = _authoritative_payload()
    payload["deny_policies"] = [
        {
            "name": "policies/project/denypolicies/protect",
            "attachment_point": "cloudresourcemanager.googleapis.com/projects/proj-1",
            "rules": [
                {
                    "denied_principals": ["principal://iam.googleapis.com/projects/-/serviceAccounts/ci@proj-1.iam.gserviceaccount.com"],
                    "exception_principals": [],
                    "denied_permissions": ["storage.googleapis.com/objects.delete"],
                    "exception_permissions": [],
                    "condition": None,
                }
            ],
        }
    ]
    bundle = normalize_gcp_iam_inventory(payload)

    result = evaluate_authorization(bundle, _request("storage.objects.delete"))

    assert result.decision is AuthorizationDecision.EXPLICIT_DENY


def test_authoritative_conditional_deny_is_indeterminate() -> None:
    payload = _authoritative_payload()
    payload["deny_policies"] = [
        {
            "name": "policies/project/denypolicies/protect",
            "attachment_point": "cloudresourcemanager.googleapis.com/projects/proj-1",
            "rules": [
                {
                    "denied_principals": ["principalSet://goog/public:all"],
                    "exception_principals": [],
                    "denied_permissions": ["storage.googleapis.com/objects.delete"],
                    "exception_permissions": [],
                    "condition": {"expression": "resource.name.endsWith('/private')"},
                }
            ],
        }
    ]
    bundle = normalize_gcp_iam_inventory(payload)

    result = evaluate_authorization(bundle, _request("storage.objects.delete"))

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("unevaluated_deny_condition",)


def test_unresolved_group_principal_set_deny_downgrades_evidence() -> None:
    payload = _authoritative_payload()
    payload["deny_policies"] = [
        {
            "name": "policies/project/denypolicies/group-protect",
            "attachment_point": "cloudresourcemanager.googleapis.com/projects/proj-1",
            "rules": [
                {
                    "denied_principals": ["principalSet://goog/group/security@example.com"],
                    "exception_principals": [],
                    "denied_permissions": ["storage.googleapis.com/objects.get"],
                    "exception_permissions": [],
                    "condition": None,
                }
            ],
        }
    ]

    bundle = normalize_gcp_iam_inventory(payload)
    result = evaluate_authorization(bundle, _request())

    assert bundle.source_state("deny_policies") is EvidenceSourceState.PARTIAL
    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert "deny_policies:partial" in result.diagnostics


def test_deleted_or_disabled_roles_cannot_authorize() -> None:
    for role_state in ({"deleted": True, "stage": "GA"}, {"deleted": False, "stage": "DISABLED"}):
        payload = _authoritative_payload()
        payload["role_definitions"][0].update(role_state)  # type: ignore[index]

        bundle = normalize_gcp_iam_inventory(payload)
        result = evaluate_authorization(bundle, _request())

        assert bundle.role_definitions[0].permissions == ()
        assert bundle.role_definitions[0].completeness is EvidenceSourceState.UNAVAILABLE
        assert result.decision is AuthorizationDecision.INDETERMINATE


def test_hierarchy_and_asset_ancestry_apply_parent_policy_to_canonical_resource() -> None:
    payload = _authoritative_payload()
    payload["iam_scope"] = "projects/123"
    payload["allow_policies"] = [
        {
            "resource": "folders/10",
            "version": 3,
            "bindings": [
                {
                    "id": "folder-binding",
                    "role": "roles/storage.objectViewer",
                    "members": ["serviceAccount:ci@proj-1.iam.gserviceaccount.com"],
                    "condition": None,
                }
            ],
        },
        {
            "resource": "//storage.googleapis.com/projects/_/buckets/private-data",
            "ancestors": ["projects/123", "folders/10", "organizations/20"],
            "version": 3,
            "bindings": [],
        },
    ]
    request = AuthorizationRequest(
        provider=AuthorizationProvider.GCP,
        principal_id="serviceAccount:ci@proj-1.iam.gserviceaccount.com",
        action="storage.objects.get",
        resource="//storage.googleapis.com/projects/_/buckets/private-data/objects/report.csv",
        plane=AuthorizationPlane.CONTROL,
    )

    bundle = normalize_gcp_iam_inventory(payload)
    result = evaluate_authorization(bundle, request)

    assert bundle.scope == "projects/123"
    assert bundle.resource_ancestry[0].ancestors == ("projects/123", "folders/10", "organizations/20")
    assert result.decision is AuthorizationDecision.ALLOW


def test_public_members_are_normalized_explicitly() -> None:
    payload = _authoritative_payload()
    payload["allow_policies"][0]["bindings"][0]["members"] = ["allUsers", "allAuthenticatedUsers"]  # type: ignore[index]

    bundle = normalize_gcp_iam_inventory(payload)

    assert {binding.principal_id for binding in bundle.bindings} == {"allAuthenticatedUsers", "allUsers"}
    assert {binding.principal_type for binding in bundle.bindings} == {"public"}


def test_missing_authoritative_role_is_indeterminate() -> None:
    payload = _authoritative_payload()
    payload["role_definitions"] = []
    bundle = normalize_gcp_iam_inventory(payload)

    result = evaluate_authorization(bundle, _request())

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert result.diagnostics == ("role:roles/storage.objectViewer:missing",)


def test_nonempty_pab_partial_state_blocks_allow() -> None:
    payload = _authoritative_payload()
    payload["iam_sources"][-1]["state"] = "partial"  # type: ignore[index]
    payload["pab_policies"] = [{"name": "organizations/20/locations/global/principalAccessBoundaryPolicies/pab"}]
    bundle = normalize_gcp_iam_inventory(payload)

    result = evaluate_authorization(bundle, _request())

    assert result.decision is AuthorizationDecision.INDETERMINATE
    assert "principal_access_boundaries:partial" in result.diagnostics
