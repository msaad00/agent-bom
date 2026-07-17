"""Production graph integration for Azure/GCP authorization evidence."""

from __future__ import annotations

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


def test_gcp_act_as_is_the_only_evidence_that_creates_an_assume_escalation() -> None:
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

    graph = build_unified_graph_from_report({"scan_id": "scan-gcp-act-as", "cloud_inventory": inventory})
    source = "service_account:gcp:source@proj-1.iam.gserviceaccount.com"
    target = "service_account:gcp:target@proj-1.iam.gserviceaccount.com"
    bucket = "cloud_resource:gcp:gcs:bucket:prod-data"

    assume = next(
        edge for edge in graph.edges if edge.source == source and edge.target == target and edge.relationship is RelationshipType.ASSUMES
    )
    assert assume.evidence["action"] == "iam.serviceAccounts.actAs"
    inherited = next(
        edge
        for edge in graph.edges
        if edge.source == source and edge.target == bucket and edge.relationship is RelationshipType.HAS_PERMISSION
    )
    assert inherited.evidence["access"] == "assume_chain"
    assert graph.nodes[source].attributes["can_escalate_privilege"] is True


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
    graph = build_unified_graph_from_report(
        {"scan_id": "scan-authorization-api", "cloud_inventory": _gcp_inventory()},
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
    assert body["stats"]["analysis_status"]["authorization_evidence:gcp"]["status"] == "complete"
    assert any(
        edge["relationship"] == "can_access"
        and edge["evidence"].get("source") == "authorization-evidence"
        and edge["evidence"].get("decision") == "allow"
        for edge in body["edges"]
    )
