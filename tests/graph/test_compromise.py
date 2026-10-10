"""A compromise assumption never converts connectivity into permission."""

from copy import deepcopy
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.compromise import CompromiseRequest, assess_direct_compromise

AT = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
STAMP = "2026-10-09T11:59:00+00:00"


def receipt(**overrides):
    return {
        "source": "authorization-evidence",
        "provider": "gcp",
        "decision": "allow",
        "principal_id": "reader",
        "action": "storage.objects.get",
        "resource": "projects/p/buckets/b",
        "binding_ids": ["binding:read"],
        "observed_at": STAMP,
        **overrides,
    }


def graph(*records, relationship=RelationshipType.CAN_ACCESS, **edge_fields):
    result = UnifiedGraph(scan_id="scan:one", tenant_id="tenant:a")
    result.add_node(
        UnifiedNode(
            id="principal:reader",
            entity_type=EntityType.SERVICE_ACCOUNT,
            label="Reader",
            attributes={"principal_id": "reader", "cloud_provider": "gcp"},
        )
    )
    result.add_node(
        UnifiedNode(
            id="data:b",
            entity_type=EntityType.DATA_STORE,
            label="Bucket",
            attributes={"resource_id": "projects/p/buckets/b", "cloud_provider": "gcp"},
        )
    )
    result.add_edge(
        UnifiedEdge(
            source="principal:reader",
            target="data:b",
            relationship=relationship,
            evidence={"authorization_decisions": list(records), "freshness": "fresh"},
            first_seen=STAMP,
            **edge_fields,
        )
    )
    return result


def assess(g, **request):
    return assess_direct_compromise(
        g, CompromiseRequest(root_node_id="principal:reader", assume_control=True, **request), tenant_id="tenant:a", at=AT
    )


def test_scoped_read_is_historical_support_not_execution_or_current_access():
    g = graph(receipt())
    before = deepcopy(g.to_dict())
    result = assess(g)
    action = result.actions[0]
    assert action.permission == "supported_at_collection"
    assert action.action == "storage.objects.get" and action.resource == "projects/p/buckets/b"
    assert action.principal_id == "reader" and action.source_edge_id == g.edges[0].id
    assert action.binding_ids == ["binding:read"] and action.observed_at == STAMP
    assert result.execution == "not_established" and result.current_access == "not_evaluated"
    assert result.collection_coverage == "unknown" and result.scope == "direct_outgoing_relationships"
    assert g.to_dict() == before
    assert result.model_dump(mode="json") == assess(g).model_dump(mode="json")


def test_denial_is_action_scoped_and_cannot_be_overridden_by_same_time_allow():
    result = assess(
        graph(receipt(), receipt(action="storage.objects.create", decision="explicit_deny"), receipt(action="storage.objects.create"))
    )
    by_action = {item.action: item for item in result.actions}
    assert by_action["storage.objects.get"].permission == "supported_at_collection"
    assert by_action["storage.objects.create"].permission == "denied_at_collection"


@pytest.mark.parametrize(
    "changes",
    [
        {"principal_id": "another-principal"},
        {"resource": "projects/p/buckets/other"},
        {"provider": "azure"},
        {"principal_id": None},
        {"resource": None},
        {"observed_at": None},
        {"observed_at": "not-a-date"},
        {"observed_at": "2026-10-09T11:59:00"},
        {"observed_at": "2026-10-09T12:01:00Z"},
        {"observed_at": "2026-10-08T11:59:00Z"},
        {"decision": "indeterminate"},
    ],
)
def test_missing_mismatched_conditional_or_old_evidence_cannot_support_access(changes):
    item = assess(graph(receipt(**changes))).actions[0]
    assert item.permission == "unknown"
    assert item.reason_codes


@pytest.mark.parametrize(
    "relationship", [RelationshipType.DEPENDS_ON, RelationshipType.TRUSTS, RelationshipType.CORRELATES_WITH, RelationshipType.EXPOSED_TO]
)
def test_inventory_trust_correlation_and_network_edges_do_not_grant_authority(relationship):
    item = assess(graph(receipt(), relationship=relationship)).actions[0]
    assert item.permission == "unknown"
    assert "relationship_does_not_establish_authority" in item.reason_codes


def test_reverse_dependency_is_not_forward_access_even_on_bidirectional_edges():
    g = graph(receipt(), direction="bidirectional")
    result = assess_direct_compromise(g, CompromiseRequest(root_node_id="data:b", assume_control=True), tenant_id="tenant:a", at=AT)
    assert result.actions == []
    assert result.collection_coverage == "unknown"


@pytest.mark.parametrize(
    "field,value", [("freshness", "stale"), ("freshness", "unknown"), ("required_context", ["credential_access"]), ("blocked", True)]
)
def test_edge_gaps_and_runtime_blockers_prevent_positive_permission_summary(field, value):
    g = graph(receipt())
    g.edges[0].evidence[field] = value
    assert assess(g).actions[0].permission == "unknown"


@pytest.mark.parametrize("fields", [{"valid_to": STAMP}, {"traversable": False}, {"direction": "unknown"}])
def test_expired_or_nontraversable_edges_do_not_support_access(fields):
    assert assess(graph(receipt(), **fields)).actions[0].permission == "unknown"


def test_native_grants_and_runtime_attempts_are_not_evaluated_allows():
    g = graph(relationship=RelationshipType.ACCESSED)
    g.edges[0].evidence = {
        "event_id": "event:one",
        "runtime_observed": True,
        "observation_count": 1,
        "failure_count": 1,
        "source": "snowflake-objects",
        "privilege": "SELECT",
        "role": "ANALYST",
        "object_fqn": "DB.S.T",
    }
    result = assess(g)
    assert result.actions[0].permission == "unknown"
    assert result.actions[0].observation == "failed_attempt"
    assert result.actions[0].runtime_references == [{"event_id": "event:one"}]


def test_truncated_authority_cannot_hide_a_denial_after_the_projection_limit():
    rows = [receipt(action=f"action:{i}") for i in range(16)] + [receipt(action="action:0", decision="explicit_deny")]
    result = assess(graph(*rows))
    assert result.truncated
    assert all(item.permission == "unknown" for item in result.actions)
    assert "authority_projection_partial" in result.reason_codes


def test_invalid_authority_rows_remain_visible_as_a_gap_and_raw_payloads_stay_private():
    result = assess(graph(receipt(raw_policy="secret-body"), receipt(action=False)))
    assert result.actions[0].permission == "unknown"
    assert "authority_projection_partial" in result.reason_codes
    assert "secret-body" not in result.model_dump_json()


def test_different_observation_times_are_not_collapsed_into_one_current_verdict():
    result = assess(graph(receipt(), receipt(decision="explicit_deny", observed_at="2026-10-09T11:58:00+00:00")))
    assert len(result.actions) == 2
    assert {item.observed_at for item in result.actions} == {STAMP, "2026-10-09T11:58:00+00:00"}
    assert result.current_access == "not_evaluated"


def test_finding_requires_explicit_affected_component_and_exploit_assumption():
    g = graph(receipt())
    g.add_node(UnifiedNode(id="finding:v", entity_type=EntityType.VULNERABILITY, label="Example"))
    g.add_edge(UnifiedEdge(source="principal:reader", target="finding:v", relationship=RelationshipType.VULNERABLE_TO))
    with pytest.raises(ValueError, match="affected component"):
        assess_direct_compromise(g, CompromiseRequest(root_node_id="finding:v", assume_control=True), tenant_id="tenant:a", at=AT)
    req = CompromiseRequest(root_node_id="finding:v", affected_node_id="principal:reader", assume_control=True, assume_exploitation=True)
    result = assess_direct_compromise(g, req, tenant_id="tenant:a", at=AT)
    assert result.root_node_id == "finding:v" and result.assumed_control_node_id == "principal:reader"
    assert result.exploitation == "assumed_not_verified"
    with pytest.raises(ValueError, match="affected component"):
        assess_direct_compromise(g, req.model_copy(update={"affected_node_id": "data:b"}), tenant_id="tenant:a", at=AT)


@pytest.mark.parametrize(
    "entity_type",
    [EntityType.AGENT, EntityType.SERVER, EntityType.PACKAGE, EntityType.CONTAINER, EntityType.DATA_STORE, EntityType.MANAGED_IDENTITY],
)
def test_root_types_do_not_invent_permissions_from_the_entity_label(entity_type):
    g = graph()
    g.nodes["principal:reader"].entity_type = entity_type
    assert assess(g).actions[0].permission == "unknown"


def test_tenant_mismatch_missing_root_and_naive_time_fail_closed():
    g = graph(receipt())
    request = CompromiseRequest(root_node_id="principal:reader", assume_control=True)
    with pytest.raises(ValueError, match="tenant"):
        assess_direct_compromise(g, request, tenant_id="tenant:b", at=AT)
    with pytest.raises(ValueError, match="root"):
        assess_direct_compromise(g, request.model_copy(update={"root_node_id": "missing"}), tenant_id="tenant:a", at=AT)
    with pytest.raises(ValueError, match="timezone"):
        assess_direct_compromise(g, request, tenant_id="tenant:a", at=AT.replace(tzinfo=None))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"assume_control": False},
        {"assume_control": 1},
        {"unknown": True},
        {"max_relationships": 0},
        {"max_relationships": 513},
        {"root_node_id": " "},
    ],
)
def test_request_rejects_implicit_assumptions_and_unbounded_or_unknown_inputs(kwargs):
    with pytest.raises(ValidationError):
        CompromiseRequest(**{"root_node_id": "root", "assume_control": True, **kwargs})


def test_relationship_budget_declares_incomplete_scope():
    g = graph(receipt())
    g.add_node(UnifiedNode(id="data:c", entity_type=EntityType.DATA_STORE, label="Other"))
    g.add_edge(UnifiedEdge(source="principal:reader", target="data:c", relationship=RelationshipType.CAN_ACCESS))
    result = assess(g, max_relationships=1)
    assert result.truncated and "relationship_limit" in result.reason_codes
    assert result.relationships_examined == 1


def test_static_denial_is_not_reported_as_runtime_activity():
    g = graph()
    g.edges[0].evidence = {**receipt(decision="explicit_deny"), "freshness": "fresh"}
    item = assess(g).actions[0]
    assert item.permission == "denied_at_collection"
    assert item.observation == "not_recorded" and item.runtime_references == []


def test_unstructured_scope_and_decision_fields_fail_closed_without_crashing():
    g = graph(receipt())
    g.nodes["principal:reader"].attributes["principal_id"] = ["reader"]
    g.edges[0].evidence.update(decision=["allow"], runtime_observed=True)
    assert assess(g).actions[0].permission == "unknown"


def test_receipts_survive_sqlite_restart_without_changing_the_assessment(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    g = graph(receipt(), receipt(action="storage.objects.create", decision="explicit_deny"))
    path = tmp_path / "assessment.db"
    SQLiteGraphStore(path).save_graph(g)
    restored = SQLiteGraphStore(path).load_graph(scan_id=g.scan_id, tenant_id=g.tenant_id)
    assert restored is not None and restored.nodes and restored.edges
    assert assess(restored).model_dump(mode="json") == assess(g).model_dump(mode="json")


def test_legacy_correlation_cannot_promote_an_unscoped_cross_environment_join():
    g = graph(receipt())
    g.edges[0].provenance = {"correlation": {"freshness": "fresh", "identity_version": "legacy"}}
    item = assess(g).actions[0]
    assert item.permission == "unknown" and "correlation_identity_unverified" in item.reason_codes


def test_direct_assessment_does_not_inherit_target_identity_permissions():
    g = graph(receipt(action="iam.serviceAccounts.actAs"), traversable=False)
    g.edges[0].evidence["required_context"] = ["workload_control", "identity_attachment", "credential_access"]
    g.nodes["data:b"].entity_type = EntityType.SERVICE_ACCOUNT
    g.add_node(UnifiedNode(id="asset:cross-cloud", entity_type=EntityType.DATA_STORE, label="Other cloud"))
    g.add_edge(UnifiedEdge(source="data:b", target="asset:cross-cloud", relationship=RelationshipType.HAS_PERMISSION))
    result = assess(g)
    assert all(item.target_node_id != "asset:cross-cloud" for item in result.actions)
    assert result.actions[0].permission == "unknown"


def test_requests_with_equivalent_timestamp_offsets_merge_for_deny_precedence():
    result = assess(graph(receipt(), receipt(decision="explicit_deny", observed_at="2026-10-09T07:59:00-04:00")))
    assert len(result.actions) == 1 and result.actions[0].permission == "denied_at_collection"
