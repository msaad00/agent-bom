"""Production graph integration for Azure/GCP authorization evidence."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import RelationshipType


def _complete_sources(*names: str) -> list[dict[str, object]]:
    return [{"name": name, "state": "complete", "diagnostics": [], "provenance": [f"test:{name}"]} for name in names]


def _azure_inventory(*, role_state: str = "complete") -> dict[str, object]:
    subscription = "/subscriptions/sub-1"
    storage_id = f"{subscription}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/prod"
    sources = _complete_sources("role_assignments", "role_definitions", "deny_assignments")
    if role_state != "complete":
        sources[1]["state"] = role_state
    return {
        "provider": "azure",
        "status": "ok",
        "subscription_id": "sub-1",
        "account_id": "sub-1",
        "storage_accounts": [{"name": "prod", "id": storage_id}],
        "managed_identities": [
            {
                "name": "scanner-mi",
                "arn": "sp-1",
                "principal_type": "serviceprincipal",
                # This legacy classifier must not create broad access when the
                # authoritative authorization evidence is incomplete.
                "privilege_level": "admin",
            }
        ],
        "role_assignments": [
            {
                "id": f"{subscription}/providers/Microsoft.Authorization/roleAssignments/a-1",
                "principal_id": "sp-1",
                "principal_type": "serviceprincipal",
                "role_definition_id": f"{subscription}/providers/Microsoft.Authorization/roleDefinitions/storage-reader",
                "scope": storage_id,
            }
        ],
        "role_definitions": [
            {
                "id": f"{subscription}/providers/Microsoft.Authorization/roleDefinitions/storage-reader",
                "completeness": role_state,
                "permissions": [
                    {
                        "actions": ["Microsoft.Storage/storageAccounts/read"],
                        "not_actions": [],
                        "data_actions": [],
                        "not_data_actions": [],
                    }
                ],
            }
        ],
        "deny_assignments": [],
        "authorization_sources": sources,
        "authorization_observed_at": "2026-07-17T12:00:00+00:00",
        "authorization_evidence": {"provider": "azure"},
    }


def _gcp_inventory(*, conditional: bool = False) -> dict[str, object]:
    resource = "//storage.googleapis.com/projects/_/buckets/prod-data"
    condition = {"expression": "request.time < timestamp('2026-01-01T00:00:00Z')"} if conditional else None
    return {
        "provider": "gcp",
        "status": "ok",
        "project_id": "proj-1",
        "account_id": "proj-1",
        "buckets": [{"name": "prod-data", "id": resource}],
        "service_accounts": [
            {
                "name": "Reader",
                "arn": "reader@proj-1.iam.gserviceaccount.com",
                "principal_id": "10001",
                "email": "reader@proj-1.iam.gserviceaccount.com",
                "principal_type": "service-account",
                "privilege_level": "admin",
            }
        ],
        "allow_policies": [
            {
                "resource": resource,
                "ancestors": ["projects/proj-1"],
                "bindings": [
                    {
                        "id": "binding-1",
                        "role": "roles/storage.objectViewer",
                        "members": ["serviceAccount:reader@proj-1.iam.gserviceaccount.com"],
                        "condition": condition,
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
        "iam_hierarchy": ["projects/proj-1"],
        "iam_scope": "projects/proj-1",
        "iam_sources": _complete_sources(
            "allow_policies",
            "role_definitions",
            "resource_hierarchy",
            "deny_policies",
            "principal_access_boundaries",
        ),
        "iam_observed_at": "2026-07-17T12:00:00+00:00",
        "authorization_evidence": {"provider": "gcp"},
    }


def _edges(graph, relationship: RelationshipType):
    return [edge for edge in graph.edges if edge.relationship is relationship]


def test_complete_azure_evidence_drives_effective_permission_and_json_status() -> None:
    graph = build_unified_graph_from_report({"scan_id": "scan-azure", "cloud_inventory": _azure_inventory()})

    proved = [edge for edge in _edges(graph, RelationshipType.CAN_ACCESS) if edge.evidence.get("source") == "authorization-evidence"]
    assert len(proved) == 1
    assert proved[0].evidence["decision"] == "allow"
    assert proved[0].evidence["action"] == "Microsoft.Storage/storageAccounts/read"
    assert any(
        edge.source == proved[0].source and edge.target == proved[0].target and edge.relationship is RelationshipType.HAS_PERMISSION
        for edge in graph.edges
    )
    assert graph.to_dict()["analysis_status"]["authorization_evidence:azure"] == {
        "status": "complete",
        "reason_codes": [],
        "limits": {"max_evaluations": 100000},
        "observed": {
            "allow_edges": 1,
            "denied_evaluations": 0,
            "evaluated_requests": 1,
            "indeterminate_evaluations": 0,
            "unmapped_resources": 0,
        },
    }


def test_incomplete_azure_evidence_never_falls_back_to_broad_classifier_edges() -> None:
    graph = build_unified_graph_from_report({"scan_id": "scan-azure-partial", "cloud_inventory": _azure_inventory(role_state="partial")})

    principal = "service_principal:azure:sp-1"
    assert not any(
        edge.source == principal and edge.relationship in {RelationshipType.CAN_ACCESS, RelationshipType.HAS_PERMISSION}
        for edge in graph.edges
    )
    status = graph.to_dict()["analysis_status"]["authorization_evidence:azure"]
    assert status["status"] == "limited"
    assert "incomplete_required_sources" in status["reason_codes"]
    assert status["observed"]["indeterminate_evaluations"] == 1


def test_complete_gcp_evidence_survives_provider_to_graph_to_json() -> None:
    graph = build_unified_graph_from_report({"scan_id": "scan-gcp", "cloud_inventory": _gcp_inventory()})
    payload = graph.to_dict()

    proved = [
        edge
        for edge in payload["edges"]
        if edge["relationship"] == "can_access" and edge["evidence"].get("source") == "authorization-evidence"
    ]
    assert len(proved) == 1
    assert proved[0]["evidence"]["provider"] == "gcp"
    assert proved[0]["evidence"]["action"] == "storage.objects.get"
    assert payload["analysis_status"]["authorization_evidence:gcp"]["status"] == "complete"


def test_conditional_gcp_allow_is_indeterminate_and_never_reachable() -> None:
    graph = build_unified_graph_from_report({"scan_id": "scan-gcp-conditional", "cloud_inventory": _gcp_inventory(conditional=True)})

    assert not any(
        edge.evidence.get("source") == "authorization-evidence"
        and edge.relationship in {RelationshipType.CAN_ACCESS, RelationshipType.HAS_PERMISSION}
        for edge in graph.edges
    )
    status = graph.to_dict()["analysis_status"]["authorization_evidence:gcp"]
    assert status["status"] == "limited"
    assert "indeterminate_evaluations" in status["reason_codes"]
    assert status["observed"]["allow_edges"] == 0


def _gcp_attachment_inventory() -> dict[str, object]:
    inventory = _gcp_inventory()
    assert isinstance(inventory["service_accounts"], list)
    inventory["service_accounts"] = [
        {
            "name": "Source",
            "arn": "source@proj-1.iam.gserviceaccount.com",
            "principal_id": "10002",
            "email": "source@proj-1.iam.gserviceaccount.com",
            "principal_type": "service-account",
            "privilege_level": "unknown",
        },
        {
            "name": "Target",
            "arn": "target@proj-1.iam.gserviceaccount.com",
            "principal_id": "10003",
            "email": "target@proj-1.iam.gserviceaccount.com",
            "principal_type": "service-account",
            "privilege_level": "unknown",
        },
    ]
    bucket_policy = inventory["allow_policies"][0]
    bucket_policy["bindings"][0]["members"] = ["serviceAccount:target@proj-1.iam.gserviceaccount.com"]
    inventory["allow_policies"].append(
        {
            "resource": "projects/proj-1",
            "bindings": [
                {
                    "id": "binding-act-as",
                    "role": "roles/iam.serviceAccountUser",
                    "members": ["serviceAccount:source@proj-1.iam.gserviceaccount.com"],
                    "condition": None,
                }
            ],
        }
    )
    inventory["role_definitions"].append(
        {
            "id": "roles/iam.serviceAccountUser",
            "permissions": ["iam.serviceAccounts.actAs"],
            "completeness": "complete",
        }
    )

    return inventory


def _azure_attachment_inventory() -> dict[str, object]:
    inventory = _azure_inventory()
    subscription = "/subscriptions/sub-1"
    identity_resource = f"{subscription}/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/reader"
    inventory["managed_identities"].append(
        {"name": "Target", "arn": identity_resource, "principal_id": "target-mi", "principal_type": "managed-identity"}
    )
    # The target identity may read storage. The source can only attach it.
    inventory["role_assignments"][0]["principal_id"] = "target-mi"
    inventory["role_assignments"].append(
        {
            "id": "attachment-binding",
            "principal_id": "sp-1",
            "principal_type": "serviceprincipal",
            "scope": identity_resource,
            "role_definition_id": "identity-operator",
        }
    )
    inventory["role_definitions"].append(
        {
            "id": "identity-operator",
            "completeness": "complete",
            "permissions": [{"actions": ["Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"]}],
        }
    )
    return inventory


@pytest.mark.parametrize("provider", ["gcp", "azure"])
def test_identity_attachment_retains_action_without_inheriting_target_authority(provider, tmp_path) -> None:
    inventory = _gcp_attachment_inventory() if provider == "gcp" else _azure_attachment_inventory()
    action = "iam.serviceAccounts.actAs" if provider == "gcp" else "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
    graph = build_unified_graph_from_report({"scan_id": "identity-attachment", "cloud_inventory": inventory})
    receipt_edge = next(edge for edge in graph.edges if edge.evidence.get("action") == action)

    assert receipt_edge.relationship is RelationshipType.CAN_ACCESS
    assert receipt_edge.traversable is False
    assert receipt_edge.evidence["authorization_decisions"][0]["decision"] == "allow"
    assert receipt_edge.evidence["authority_effect"] == "identity_attachment"
    assert receipt_edge.evidence["required_context"] == ["workload_control", "identity_attachment", "credential_access"]
    assert not any(
        edge.source == receipt_edge.source and edge.relationship in {RelationshipType.ASSUMES, RelationshipType.HAS_PERMISSION}
        for edge in graph.edges
    )
    assert graph.nodes[receipt_edge.source].attributes.get("can_escalate_privilege") is not True
    assert any(
        edge.source == receipt_edge.target and edge.relationship is RelationshipType.HAS_PERMISSION for edge in graph.edges
    )  # The target's independently proved access remains available.
    status = graph.analysis_status[f"authorization_evidence:{provider}"]
    assert status.status.value == "limited"
    assert "identity_attachment_requires_workload_context" in status.reason_codes

    # Preserve the exact receipt and negative traversal boundary through restart
    # and the shared graph JSON response consumed by CLI, SDK and dashboard.
    path = tmp_path / "attachment.db"
    SQLiteGraphStore(path).save_graph(graph)
    restored_store = SQLiteGraphStore(path)
    restored = restored_store.load_graph(scan_id="identity-attachment", tenant_id="default")
    restored_edge = next(edge for edge in restored.edges if edge.id == receipt_edge.id)
    assert restored_edge.evidence == receipt_edge.evidence
    assert restored_edge.relationship is RelationshipType.CAN_ACCESS
    assert restored_edge.traversable is False
    assert restored_edge.source_scan_id == graph.scan_id
    assert receipt_edge.target not in restored.reachable_from(receipt_edge.source, traversable_only=True)
    original = api_stores._graph_store
    try:
        set_graph_store(restored_store)
        response = TestClient(app).get("/v1/graph", params={"scan": "identity-attachment", "limit": 200})
    finally:
        set_graph_store(original)
    assert response.status_code == 200
    projected = next(edge for edge in response.json()["edges"] if edge["id"] == receipt_edge.id)
    assert projected["relationship"] == "can_access"
    assert projected["traversable"] is False
    assert projected["evidence"] == receipt_edge.evidence


@pytest.mark.parametrize("provider", ["gcp", "azure"])
def test_conditional_identity_attachment_never_emits_an_unconditional_receipt(provider) -> None:
    inventory = _gcp_attachment_inventory() if provider == "gcp" else _azure_attachment_inventory()
    if provider == "gcp":
        inventory["allow_policies"][-1]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2026-01-01T00:00:00Z')"}
    else:
        inventory["role_assignments"][-1]["condition"] = "@Resource[Example:environment] StringEquals 'production'"
        inventory["role_assignments"][-1]["condition_version"] = "2.0"
    graph = build_unified_graph_from_report({"scan_id": "conditional-attachment", "cloud_inventory": inventory})
    assert not any(edge.evidence.get("authority_effect") == "identity_attachment" for edge in graph.edges)
    assert not any(edge.relationship is RelationshipType.ASSUMES for edge in graph.edges)
    assert "indeterminate_evaluations" in graph.analysis_status[f"authorization_evidence:{provider}"].reason_codes


@pytest.mark.parametrize("provider", ["gcp", "azure"])
@pytest.mark.parametrize("change", ["revoked", "stale", "approval_condition"])
def test_attachment_refresh_does_not_reuse_unavailable_authority(provider, change) -> None:
    inventory = _gcp_attachment_inventory() if provider == "gcp" else _azure_attachment_inventory()
    before = build_unified_graph_from_report({"scan_id": "before", "cloud_inventory": inventory})
    assert any(edge.evidence.get("authority_effect") == "identity_attachment" for edge in before.edges)
    if change == "revoked":
        if provider == "gcp":
            inventory["allow_policies"][-1]["bindings"] = []
        else:
            inventory["role_assignments"].pop()
    elif change == "stale":
        sources = inventory["iam_sources"] if provider == "gcp" else inventory["authorization_sources"]
        sources[0]["state"] = "stale"
    elif provider == "gcp":
        inventory["allow_policies"][-1]["bindings"][0]["condition"] = {"expression": "request.auth.claims.approved == true"}
    else:
        inventory["role_assignments"][-1]["condition"] = "@Resource[Example:approved] BoolEquals true"
        inventory["role_assignments"][-1]["condition_version"] = "2.0"
    after = build_unified_graph_from_report({"scan_id": "after", "cloud_inventory": inventory})
    assert not any(edge.evidence.get("authority_effect") == "identity_attachment" for edge in after.edges)
    assert not any(edge.relationship is RelationshipType.ASSUMES for edge in after.edges)
    if change != "revoked":
        assert after.analysis_status[f"authorization_evidence:{provider}"].status.value == "limited"


def test_gcp_explicit_deny_never_becomes_access() -> None:
    inventory = _gcp_inventory()
    inventory["deny_policies"] = [
        {
            "name": "policies/project/denypolicies/protect",
            "attachment_point": "cloudresourcemanager.googleapis.com/projects/proj-1",
            "rules": [
                {
                    "denied_principals": [
                        "principal://iam.googleapis.com/projects/-/serviceAccounts/reader@proj-1.iam.gserviceaccount.com"
                    ],
                    "denied_permissions": ["storage.googleapis.com/objects.get"],
                    "exception_permissions": [],
                    "exception_principals": [],
                    "condition": None,
                }
            ],
        }
    ]

    graph = build_unified_graph_from_report({"scan_id": "scan-gcp-deny", "cloud_inventory": inventory})

    assert not any(
        edge.evidence.get("source") == "authorization-evidence"
        and edge.relationship in {RelationshipType.CAN_ACCESS, RelationshipType.HAS_PERMISSION}
        for edge in graph.edges
    )
    status = graph.to_dict()["analysis_status"]["authorization_evidence:gcp"]
    assert status["status"] == "complete"
    assert status["observed"]["denied_evaluations"] == 1


def test_authorization_decision_and_status_survive_persistence_and_graph_api(tmp_path) -> None:
    inventory = _gcp_inventory()
    inventory["role_definitions"][0]["permissions"] = ["storage.objects.get", "storage.objects.create"]
    graph = build_unified_graph_from_report(
        {"scan_id": "scan-authorization-api", "cloud_inventory": inventory},
        tenant_id="default",
    )
    store = SQLiteGraphStore(tmp_path / "authorization-graph.db")
    store.save_graph(graph)
    original = api_stores._graph_store
    try:
        set_graph_store(store)
        response = TestClient(app).get(
            "/v1/graph",
            params={"scan": "scan-authorization-api", "limit": 200},
        )
    finally:
        set_graph_store(original)

    assert response.status_code == 200
    body = response.json()
    allowed = next(
        edge
        for edge in body["edges"]
        if edge["relationship"] == "can_access" and edge["evidence"].get("source") == "authorization-evidence"
    )
    assert {record["action"] for record in allowed["evidence"]["authorization_decisions"]} == {
        "storage.objects.get",
        "storage.objects.create",
    }
    derived = next(
        edge
        for edge in body["edges"]
        if edge["relationship"] == "has_permission" and edge["source"] == allowed["source"] and edge["target"] == allowed["target"]
    )
    witness = derived["evidence"]["permission_derivation"]["paths"][0]
    assert witness["source_edge_ids"] == [allowed["id"]]
    assert witness["grant_principal_id"] == allowed["source"]
    assert body["stats"]["analysis_status"]["authorization_evidence:gcp"]["status"] == "complete"
    assert any(
        edge["relationship"] == "can_access"
        and edge["evidence"].get("source") == "authorization-evidence"
        and edge["evidence"].get("decision") == "allow"
        for edge in body["edges"]
    )


def test_authorization_evidence_graph_state_is_tenant_isolated(tmp_path) -> None:
    store = SQLiteGraphStore(tmp_path / "authorization-tenant-graph.db")
    alpha = build_unified_graph_from_report(
        {"scan_id": "shared-scan", "cloud_inventory": _azure_inventory()},
        tenant_id="tenant-alpha",
    )
    beta = build_unified_graph_from_report(
        {"scan_id": "shared-scan", "cloud_inventory": _gcp_inventory(conditional=True)},
        tenant_id="tenant-beta",
    )
    store.save_graph(alpha)
    store.save_graph(beta)

    loaded_alpha = store.load_graph(scan_id="shared-scan", tenant_id="tenant-alpha")
    loaded_beta = store.load_graph(scan_id="shared-scan", tenant_id="tenant-beta")

    assert "authorization_evidence:azure" in loaded_alpha.analysis_status
    assert "authorization_evidence:gcp" not in loaded_alpha.analysis_status
    assert "authorization_evidence:gcp" in loaded_beta.analysis_status
    assert "authorization_evidence:azure" not in loaded_beta.analysis_status


def test_authoritative_gcp_evidence_suppresses_legacy_org_role_reachability() -> None:
    inventory = _gcp_inventory(conditional=True)
    inventory["gcp_organization"] = {
        "status": "ok",
        "org_id": "organizations/20",
        "org_name": "example",
        "folders": [],
        "projects": [{"id": "proj-1", "name": "prod", "number": "123", "parent_id": "organizations/20"}],
        "iam_bindings": [
            {
                "role": "roles/owner",
                "scope_id": "organizations/20",
                "scope_level": "organization",
                "privilege_level": "admin",
                "members": ["serviceAccount:reader@proj-1.iam.gserviceaccount.com"],
            }
        ],
        "org_policies": [],
    }

    graph = build_unified_graph_from_report({"scan_id": "scan-gcp-org", "cloud_inventory": inventory})

    assert not any(
        edge.relationship is RelationshipType.HAS_PERMISSION and edge.evidence.get("source") == "gcp-organizations" for edge in graph.edges
    )
