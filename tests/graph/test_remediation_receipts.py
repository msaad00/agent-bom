"""Synthetic collection receipts prove only bounded recorded authorization changes."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agent_bom.cloud.authorization_evidence import (
    AuthorizationBinding,
    AuthorizationCondition,
    AuthorizationEffect,
    AuthorizationEvidenceBundle,
    AuthorizationProvider,
    ConditionLanguage,
    EvidenceSource,
    EvidenceSourceState,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation import correlation_graph_digest
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.remediation_receipts import (
    AccessCollectionReceipt,
    AccessComparisonLimits,
    AccessComparisonRequest,
    AccessEvidenceSnapshot,
    CoverageReceipt,
    IdentityHopReceipt,
    PrincipalReceipt,
    ResourceReceipt,
    RevocationReceipt,
    authorization_bundle_digest,
    compare_recorded_access,
)
from agent_bom.graph.types import EntityType, RelationshipType

NOW = datetime(2026, 9, 20, 15, tzinfo=timezone.utc)
READ = "storage.objects.get"
WRITE = "storage.objects.create"
RESOURCE = "projects/demo/buckets/private"
PRINCIPAL = "serviceAccount:reader@demo.iam.gserviceaccount.com"
OTHER = "serviceAccount:alternate@demo.iam.gserviceaccount.com"
SCOPE = "projects/demo"
CONFIG = "sha256:" + "a" * 64


def _binding(binding_id="read-grant", principal=PRINCIPAL, action=READ):
    return AuthorizationBinding(
        binding_id=binding_id,
        effect=AuthorizationEffect.ALLOW,
        principal_id=principal,
        principal_type="service_account",
        scope=RESOURCE,
        permissions=(action,),
        source="iam",
    )


def _snapshot(scan_id, when, bindings, *, alternate=False, revoke=False):
    bundle = AuthorizationEvidenceBundle(
        provider=AuthorizationProvider.GCP,
        scope=SCOPE,
        observed_at=when,
        sources=(EvidenceSource("iam", EvidenceSourceState.COMPLETE, provenance=(f"{scan_id}:iam",)),),
        required_sources=("iam",),
        bindings=tuple(bindings),
    )
    graph = UnifiedGraph(scan_id=scan_id, tenant_id="tenant-a", created_at=when.isoformat())
    for node_id, kind in (("agent", EntityType.AGENT), ("reader", EntityType.SERVICE_ACCOUNT), ("data", EntityType.DATA_STORE)):
        graph.add_node(UnifiedNode(id=node_id, label=node_id, entity_type=kind))
    if alternate:
        graph.add_node(UnifiedNode(id="alternate", label="alternate", entity_type=EntityType.SERVICE_ACCOUNT))
    identity_hops = []
    for node_id in ["reader", *(["alternate"] if alternate else [])]:
        edge = UnifiedEdge(
            source="agent",
            target=node_id,
            relationship=RelationshipType.AUTHENTICATES_AS,
            source_scan_id=scan_id,
            first_seen=when.isoformat(),
            last_seen=when.isoformat(),
            provenance={"source": "synthetic-session-collector"},
        )
        graph.add_edge(edge)
        identity_hops.append(IdentityHopReceipt(edge_id=edge.canonical_id, evidence_ref=f"{scan_id}:session:{node_id}", state="complete"))
    for binding in bindings:
        node_id = "reader" if binding.principal_id == PRINCIPAL else "alternate"
        if node_id not in graph.nodes:
            continue
        graph.add_edge(
            UnifiedEdge(
                source=node_id,
                target="data",
                relationship=RelationshipType.CAN_ACCESS,
                source_scan_id=scan_id,
                first_seen=when.isoformat(),
                last_seen=when.isoformat(),
                evidence={
                    "authorization_decisions": [
                        {
                            "source": "authorization-evidence",
                            "provider": "gcp",
                            "principal_id": binding.principal_id,
                            "action": binding.permissions[0],
                            "resource": RESOURCE,
                            "decision": "allow",
                            "binding_ids": [binding.binding_id],
                            "observed_at": when.isoformat(),
                        }
                    ]
                },
            )
        )
    receipt = AccessCollectionReceipt(
        basis="observed",
        tenant_id="tenant-a",
        source_id="gcp-connection-1",
        scope=SCOPE,
        configuration_digest=CONFIG,
        scan_id=scan_id,
        graph_digest=correlation_graph_digest(graph),
        authorization_digest=authorization_bundle_digest(bundle),
        started_at=when - timedelta(seconds=30),
        completed_at=when,
        collection_mode="live",
        coverage=tuple(
            CoverageReceipt(component=name, state="complete", evidence_ref=f"{scan_id}:{name}")
            for name in (
                "authorization",
                "identity_binding",
                "policy_conditions",
                "session_context",
                "alternate_paths",
            )
        ),
        principals=(
            PrincipalReceipt(node_id="reader", principal_id=PRINCIPAL, evidence_ref=f"{scan_id}:reader"),
            *((PrincipalReceipt(node_id="alternate", principal_id=OTHER, evidence_ref=f"{scan_id}:alternate"),) if alternate else ()),
        ),
        resources=(ResourceReceipt(node_id="data", resource=RESOURCE, evidence_ref=f"{scan_id}:data"),),
        identity_hops=tuple(identity_hops),
        revocations=(
            RevocationReceipt(
                binding_id="read-grant",
                principal_id=PRINCIPAL,
                action=READ,
                resource=RESOURCE,
                observed_at=when,
                evidence_ref=f"{scan_id}:revocation:event-1",
            ),
        )
        if revoke
        else (),
    )
    return AccessEvidenceSnapshot(receipt=receipt, graph=graph, authorization=bundle)


def _pair(*, alternate=False, candidate_bindings=(), revoke=True):
    baseline = _snapshot("baseline", NOW - timedelta(hours=1), [_binding()])
    candidate = _snapshot("rescan", NOW - timedelta(minutes=1), candidate_bindings, alternate=alternate, revoke=revoke)
    request = AccessComparisonRequest(
        tenant_id="tenant-a",
        baseline_scan_id="baseline",
        candidate_scan_id="rescan",
        baseline_graph_digest=baseline.receipt.graph_digest,
        candidate_graph_digest=candidate.receipt.graph_digest,
        source_id="gcp-connection-1",
        scope=SCOPE,
        configuration_digest=CONFIG,
        provider="gcp",
        origin_node_id="agent",
        identity_node_id="reader",
        principal_id=PRINCIPAL,
        target_node_id="data",
        resource=RESOURCE,
        action=READ,
        baseline_edge_ids=tuple(edge.canonical_id for edge in baseline.graph.edges),
        binding_ids=("read-grant",),
    )
    return baseline, candidate, request


def _compare(baseline, candidate, request, **kwargs):
    return compare_recorded_access(baseline, candidate, request, now=NOW, **kwargs)


def _reseal(snapshot):
    return replace(
        snapshot,
        receipt=snapshot.receipt.model_copy(
            update={
                "graph_digest": correlation_graph_digest(snapshot.graph),
                "authorization_digest": authorization_bundle_digest(snapshot.authorization),
            }
        ),
    )


def test_revoked_grant_with_complete_rescan_and_no_alternate_is_narrow_recorded_proof():
    baseline, candidate, request = _pair()
    result = _compare(baseline, candidate, request)
    assert result.outcome == "recorded_authorization_removed"
    assert result.remaining_path == ()
    assert result.remediation_verified is False
    assert result.claim_scope == "recorded_authorization_only"
    assert result.candidate_scan_id == "rescan"
    assert result.revocation_evidence_refs == ("rescan:revocation:event-1",)
    assert result.model_dump(mode="json")["successful_action_proven"] is False


def test_revoked_selected_grant_retains_alternate_directed_access_path():
    baseline, candidate, request = _pair(alternate=True, candidate_bindings=[_binding("alternate-read", OTHER)])
    result = _compare(baseline, candidate, request)
    assert result.outcome == "recorded_access_remains"
    assert result.selected_authorization_removed is True
    assert result.remaining_path == ("agent", "alternate", "data")
    assert result.remaining_edge_ids == tuple(edge.canonical_id for edge in candidate.graph.edges if edge.target != "reader")


def test_still_present_selected_authorization_is_not_removed():
    baseline, candidate, request = _pair(candidate_bindings=[_binding()], revoke=False)
    result = _compare(baseline, candidate, request)
    assert result.outcome == "recorded_access_remains"
    assert result.selected_authorization_removed is False


def test_mere_disappearance_without_explicit_revocation_is_unavailable():
    result = _compare(*_pair(revoke=False))
    assert result.outcome == "unavailable_evidence"
    assert "revocation_not_recorded" in result.reason_codes


@pytest.mark.parametrize("component", ["authorization", "identity_binding", "policy_conditions", "session_context", "alternate_paths"])
@pytest.mark.parametrize(
    "state", ["partial", "access_denied", "unavailable", "stale", "truncated", "unsupported", "disabled", "sdk_missing"]
)
def test_incomplete_context_or_collection_cannot_prove_removal(component, state):
    baseline, candidate, request = _pair()
    coverage = tuple(
        item.model_copy(update={"state": EvidenceSourceState(state)}) if item.component == component else item
        for item in candidate.receipt.coverage
    )
    candidate = replace(candidate, receipt=candidate.receipt.model_copy(update={"coverage": coverage}))
    assert _compare(baseline, candidate, request).outcome == "unavailable_evidence"


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "other-tenant"),
        ("source_id", "other-source"),
        ("scope", "projects/other"),
        ("configuration_digest", "sha256:" + "b" * 64),
        ("scan_id", "other-scan"),
        ("collection_mode", "cached"),
        ("collection_mode", "unknown"),
        ("coverage", ()),
    ],
)
def test_mismatched_or_cached_receipt_cannot_prove_removal(field, value):
    baseline, candidate, request = _pair()
    candidate = replace(candidate, receipt=candidate.receipt.model_copy(update={field: value}))
    assert _compare(baseline, candidate, request).outcome == "unavailable_evidence"


def test_stale_candidate_and_reused_baseline_are_unavailable():
    baseline, candidate, request = _pair()
    assert compare_recorded_access(baseline, candidate, request, now=NOW + timedelta(days=2)).reason_codes == ("candidate_stale",)
    assert _compare(baseline, baseline, request).outcome == "unavailable_evidence"


def test_pinned_digest_detects_graph_and_authorization_mutation():
    baseline, candidate, request = _pair()
    candidate.graph.nodes["data"].label = "mutated"
    assert "snapshot_digest_mismatch" in _compare(baseline, candidate, request).reason_codes
    baseline, candidate, request = _pair()
    candidate = replace(candidate, authorization=replace(candidate.authorization, bindings=(_binding(),)))
    assert "authorization_digest_mismatch" in _compare(baseline, candidate, request).reason_codes


def test_read_revocation_does_not_remove_write_and_write_does_not_keep_read_alive():
    baseline, candidate, request = _pair(candidate_bindings=[_binding("write-grant", action=WRITE)])
    assert _compare(baseline, candidate, request).outcome == "recorded_authorization_removed"
    changed = request.model_copy(update={"action": WRITE})
    assert _compare(baseline, candidate, changed).outcome == "unavailable_evidence"


def test_reverse_and_nontraversable_edges_cannot_become_alternate_access():
    for reverse, traversable in [(True, True), (False, False)]:
        baseline, candidate, request = _pair(alternate=True, candidate_bindings=[_binding("alternate-read", OTHER)])
        edge = next(edge for edge in candidate.graph.edges if edge.target == "alternate")
        edge.traversable = traversable
        if reverse:
            edge.source, edge.target = edge.target, edge.source
        candidate = _reseal(candidate)
        request = request.model_copy(update={"candidate_graph_digest": candidate.receipt.graph_digest})
        assert _compare(baseline, candidate, request).outcome == "recorded_authorization_removed"


@pytest.mark.parametrize(
    "limits", [AccessComparisonLimits(max_nodes=2), AccessComparisonLimits(max_edges=1), AccessComparisonLimits(max_hops=1)]
)
def test_exhausted_budget_is_unknown_even_when_removed_grant_receipt_exists(limits):
    baseline, candidate, request = _pair(alternate=True, candidate_bindings=[_binding("alternate-read", OTHER)])
    result = _compare(baseline, candidate, request, limits=limits)
    assert result.outcome == "unavailable_evidence"
    assert "comparison_budget_exhausted" in result.reason_codes


def test_unknown_condition_blocks_positive_receipt_and_does_not_leak_expression():
    baseline, candidate, request = _pair()
    condition = AuthorizationCondition(ConditionLanguage.CEL, "secret-expression-that-must-not-leak")
    candidate = replace(
        candidate, authorization=replace(candidate.authorization, bindings=(replace(_binding("conditional"), condition=condition),))
    )
    candidate = _reseal(candidate)
    result = _compare(baseline, candidate, request)
    assert result.outcome == "unavailable_evidence"
    assert "secret-expression" not in result.model_dump_json()


def test_missing_identity_hop_receipt_is_not_completed_from_graph_topology():
    baseline, candidate, request = _pair(alternate=True, candidate_bindings=[_binding("alternate-read", OTHER)])
    candidate = replace(candidate, receipt=candidate.receipt.model_copy(update={"identity_hops": ()}))
    assert _compare(baseline, candidate, request).outcome == "unavailable_evidence"


def test_unknown_action_receipt_is_not_treated_as_no_alternative():
    baseline, candidate, request = _pair(alternate=True, candidate_bindings=[_binding("alternate-read", OTHER)])
    candidate.graph.edges[-1].evidence = {}
    candidate = _reseal(candidate)
    request = request.model_copy(update={"candidate_graph_digest": candidate.receipt.graph_digest})
    assert _compare(baseline, candidate, request).outcome == "unavailable_evidence"


def test_closed_contract_rejects_ambiguous_or_untimed_receipts():
    baseline, _, request = _pair()
    with pytest.raises(ValidationError):
        AccessCollectionReceipt.model_validate({**baseline.receipt.model_dump(), "verified_fixed": True})
    with pytest.raises(ValidationError):
        AccessCollectionReceipt.model_validate({**baseline.receipt.model_dump(), "completed_at": NOW.replace(tzinfo=None)})
    with pytest.raises(ValidationError):
        AccessCollectionReceipt.model_validate(
            {**baseline.receipt.model_dump(), "coverage": (*baseline.receipt.coverage, baseline.receipt.coverage[0])}
        )
    with pytest.raises(ValidationError):
        AccessComparisonRequest.model_validate({**request.model_dump(), "baseline_edge_ids": ()})


def test_allowed_alternate_missing_from_graph_is_incomplete_not_removed():
    baseline, candidate, request = _pair(alternate=True, candidate_bindings=[_binding("alternate-read", OTHER)])
    candidate.graph.edges = [edge for edge in candidate.graph.edges if edge.target != "data"]
    candidate = _reseal(candidate)
    request = request.model_copy(update={"candidate_graph_digest": candidate.receipt.graph_digest})
    result = _compare(baseline, candidate, request)
    assert result.outcome == "unavailable_evidence"
    assert result.reason_codes == ("authorization_graph_inconsistent",)


def test_conditional_alternate_missing_from_graph_is_unknown_not_removed():
    baseline, candidate, request = _pair(alternate=True)
    condition = AuthorizationCondition(ConditionLanguage.CEL, "request.time < timestamp('2030-01-01T00:00:00Z')")
    candidate = replace(
        candidate,
        authorization=replace(candidate.authorization, bindings=(replace(_binding("conditional-alternate", OTHER), condition=condition),)),
    )
    candidate = _reseal(candidate)
    assert _compare(baseline, candidate, request).reason_codes == ("authorization_indeterminate",)


@pytest.mark.parametrize("mutation", ["missing_target", "missing_principal", "wrong_resource", "graph_partial", "observed_before_scan"])
def test_snapshot_requires_recorded_entity_binding_complete_graph_and_collection_time(mutation):
    baseline, candidate, request = _pair()
    if mutation == "missing_target":
        candidate.graph.nodes.pop("data")
    elif mutation == "missing_principal":
        candidate = replace(candidate, receipt=candidate.receipt.model_copy(update={"principals": ()}))
    elif mutation == "wrong_resource":
        candidate = replace(
            candidate,
            receipt=candidate.receipt.model_copy(
                update={
                    "resources": (candidate.receipt.resources[0].model_copy(update={"resource": "projects/demo/buckets/public"}),),
                }
            ),
        )
    elif mutation == "graph_partial":
        candidate.graph.completeness.truncated = True
    else:
        candidate = replace(candidate, authorization=replace(candidate.authorization, observed_at=NOW - timedelta(days=1)))
    candidate = _reseal(candidate)
    request = request.model_copy(update={"candidate_graph_digest": candidate.receipt.graph_digest})
    assert _compare(baseline, candidate, request).outcome == "unavailable_evidence"


@pytest.mark.parametrize("scope_state", [EvidenceSourceState.ACCESS_DENIED, EvidenceSourceState.PARTIAL])
def test_wrapper_complete_cannot_override_native_required_source_failure(scope_state):
    baseline, candidate, request = _pair()
    candidate = replace(candidate, authorization=replace(candidate.authorization, sources=(EvidenceSource("iam", scope_state),)))
    candidate = _reseal(candidate)
    result = _compare(baseline, candidate, request)
    assert result.reason_codes == ("collection_or_context_incomplete",)


def test_revocation_receipt_conflicting_with_current_binding_is_unavailable():
    assert _compare(*_pair(candidate_bindings=[_binding()])).reason_codes == ("revocation_conflicts_with_current_authorization",)


def test_baseline_must_be_exact_connected_selected_action_path():
    baseline, candidate, request = _pair()
    assert _compare(
        baseline, candidate, request.model_copy(update={"baseline_edge_ids": request.baseline_edge_ids[::-1]})
    ).reason_codes == ("baseline_access_not_established",)
    assert _compare(baseline, candidate, request.model_copy(update={"binding_ids": ("unrelated",)})).reason_codes == (
        "baseline_access_not_established",
    )


def test_proposed_or_cross_snapshot_identity_edge_is_not_authority():
    for update in [{"source_scan_id": "different"}, {"provenance": {"kind": "proposed"}}]:
        baseline, candidate, request = _pair(alternate=True, candidate_bindings=[_binding("alternate-read", OTHER)])
        for name, value in update.items():
            setattr(candidate.graph.edges[0], name, value)
        candidate = _reseal(candidate)
        request = request.model_copy(update={"candidate_graph_digest": candidate.receipt.graph_digest})
        assert _compare(baseline, candidate, request).reason_codes == ("hop_receipt_unavailable",)


def test_deadline_exhaustion_never_returns_no_alternate(monkeypatch):
    baseline, candidate, request = _pair()
    readings = iter((0, 2, 2, 2))
    monkeypatch.setattr("agent_bom.graph.remediation_receipts.time.monotonic", lambda: next(readings))
    assert _compare(baseline, candidate, request).reason_codes == ("comparison_budget_exhausted",)


def test_serialized_receipts_and_sqlite_graphs_keep_exact_comparison(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    baseline, candidate, request = _pair(alternate=True, candidate_bindings=[_binding("alternate-read", OTHER)])
    # Separate immutable snapshot stores: comparison does not trust a mutable
    # latest-snapshot alias, nor reseal historical content after a write.
    restored = []
    for snapshot in (baseline, candidate):
        db_path = tmp_path / f"{snapshot.receipt.scan_id}.db"
        SQLiteGraphStore(db_path).save_graph(snapshot.graph)
        graph = SQLiteGraphStore(db_path).load_graph(scan_id=snapshot.receipt.scan_id, tenant_id="tenant-a")
        assert graph.nodes and graph.edges
        restored.append(
            replace(snapshot, graph=graph, receipt=AccessCollectionReceipt.model_validate_json(snapshot.receipt.model_dump_json()))
        )
    result = _compare(*restored, request)
    assert result.outcome == "recorded_access_remains"
    assert result.remaining_path == ("agent", "alternate", "data")
    assert result == _compare(*restored, request)
    assert not SQLiteGraphStore(tmp_path / "rescan.db").load_graph(scan_id="rescan", tenant_id="tenant-other").nodes


def test_scope_or_action_changes_alter_the_output_request_digest():
    baseline, candidate, request = _pair()
    first = _compare(baseline, candidate, request)
    different_action = _compare(baseline, candidate, request.model_copy(update={"action": WRITE}))
    assert first.request_digest != different_action.request_digest
    assert first.baseline_receipt_digest == different_action.baseline_receipt_digest
    assert first.candidate_receipt_digest == different_action.candidate_receipt_digest


def test_selected_grant_must_be_on_the_selected_hop_not_only_elsewhere_in_bundle():
    baseline, candidate, request = _pair()
    baseline = replace(
        baseline,
        authorization=replace(
            baseline.authorization,
            bindings=(
                *baseline.authorization.bindings,
                _binding("unmaterialized-read"),
            ),
        ),
    )
    baseline = _reseal(baseline)
    request = request.model_copy(update={"binding_ids": ("unmaterialized-read",)})
    assert _compare(baseline, candidate, request).reason_codes == ("baseline_access_not_established",)


def test_comparison_keeps_inputs_unchanged_and_rechecks_cached_result_freshness():
    baseline, candidate, request = _pair()
    before = (baseline.graph.to_dict(), candidate.graph.to_dict(), baseline.receipt.model_dump_json(), candidate.receipt.model_dump_json())
    first = _compare(baseline, candidate, request)
    assert first.outcome == "recorded_authorization_removed"
    assert first.limits.max_hops == 16
    assert before == (
        baseline.graph.to_dict(),
        candidate.graph.to_dict(),
        baseline.receipt.model_dump_json(),
        candidate.receipt.model_dump_json(),
    )
    later = compare_recorded_access(baseline, candidate, request, now=NOW + timedelta(hours=2))
    assert later.outcome == "unavailable_evidence"
    assert later.reason_codes == ("candidate_stale",)


def test_model_cannot_accept_remediation_success_or_unrequested_field():
    from agent_bom.graph.remediation_receipts import AccessComparisonReceipt

    result = _compare(*_pair()).model_dump()
    with pytest.raises(ValidationError):
        AccessComparisonReceipt.model_validate({**result, "remediation_verified": True})
    with pytest.raises(ValidationError):
        AccessComparisonReceipt.model_validate({**result, "successful_action_proven": True})
    with pytest.raises(ValidationError):
        AccessComparisonReceipt.model_validate({**result, "business_loss": 100})


def test_deserialized_result_cannot_erase_required_proof_fields():
    from agent_bom.graph.remediation_receipts import AccessComparisonReceipt

    removed = _compare(*_pair()).model_dump()
    remaining = _compare(*_pair(candidate_bindings=[_binding()], revoke=False)).model_dump()
    unavailable = _compare(*_pair(revoke=False)).model_dump()
    for payload in (
        {**removed, "revocation_evidence_refs": ()},
        {**removed, "selected_authorization_removed": None},
        {**remaining, "remaining_edge_ids": ()},
        {**unavailable, "reason_codes": ()},
        {**unavailable, "selected_authorization_removed": True},
    ):
        with pytest.raises(ValidationError):
            AccessComparisonReceipt.model_validate(payload)


@pytest.mark.parametrize("with_allow", [False, True])
def test_unbound_reachable_identity_cannot_prove_no_alternate(with_allow):
    bindings = [_binding("alternate-read", OTHER)] if with_allow else []
    baseline, candidate, request = _pair(alternate=True, candidate_bindings=bindings)
    candidate.graph.edges = [edge for edge in candidate.graph.edges if edge.target != "data"]
    candidate = replace(
        candidate,
        receipt=candidate.receipt.model_copy(
            update={"principals": tuple(item for item in candidate.receipt.principals if item.node_id != "alternate")}
        ),
    )
    candidate = _reseal(candidate)
    request = request.model_copy(update={"candidate_graph_digest": candidate.receipt.graph_digest})
    result = _compare(baseline, candidate, request)
    assert result.outcome == "unavailable_evidence"
    assert result.reason_codes == ("hop_receipt_unavailable",)
    assert result.selected_authorization_removed is None


@pytest.mark.parametrize("relationship", [RelationshipType.AUTHENTICATES_AS, RelationshipType.ASSUMES, RelationshipType.MEMBER_OF])
def test_identity_relationship_to_resource_is_not_a_remaining_action_witness(relationship):
    baseline, candidate, request = _pair()
    edge = UnifiedEdge(
        source="agent",
        target="data",
        relationship=relationship,
        source_scan_id=candidate.receipt.scan_id,
        first_seen=candidate.receipt.completed_at.isoformat(),
        last_seen=candidate.receipt.completed_at.isoformat(),
    )
    candidate.graph.add_edge(edge)
    candidate = replace(
        candidate,
        receipt=candidate.receipt.model_copy(
            update={
                "identity_hops": (
                    *candidate.receipt.identity_hops,
                    IdentityHopReceipt(edge_id=edge.canonical_id, evidence_ref="rescan:identity-only", state="complete"),
                ),
            }
        ),
    )
    candidate = _reseal(candidate)
    request = request.model_copy(update={"candidate_graph_digest": candidate.receipt.graph_digest})
    result = _compare(baseline, candidate, request)
    assert result.outcome == "unavailable_evidence"
    assert result.reason_codes == ("hop_receipt_unavailable",)
    assert not result.remaining_path


def test_baseline_identity_relationship_cannot_substitute_for_action_authority():
    baseline, candidate, request = _pair()
    terminal = baseline.graph.edges[-1]
    terminal.relationship = RelationshipType.MEMBER_OF
    baseline = replace(
        baseline,
        receipt=baseline.receipt.model_copy(
            update={
                "identity_hops": (
                    *baseline.receipt.identity_hops,
                    IdentityHopReceipt(edge_id=terminal.canonical_id, evidence_ref="baseline:identity-only", state="complete"),
                ),
            }
        ),
    )
    baseline = _reseal(baseline)
    request = request.model_copy(
        update={
            "baseline_graph_digest": baseline.receipt.graph_digest,
            "baseline_edge_ids": tuple(edge.canonical_id for edge in baseline.graph.edges),
        }
    )
    result = _compare(baseline, candidate, request)
    assert result.outcome == "unavailable_evidence"
    assert result.reason_codes == ("baseline_access_not_established",)


@pytest.mark.parametrize("edge_index", [0, 1], ids=["identity", "action"])
@pytest.mark.parametrize("lifecycle", ["closed", "expired", "not_yet_valid"])
def test_inactive_baseline_hop_cannot_establish_selected_access(edge_index, lifecycle):
    baseline, candidate, request = _pair()
    edge = baseline.graph.edges[edge_index]
    if lifecycle == "closed":
        edge.activity_id = 3
    elif lifecycle == "expired":
        edge.valid_to = baseline.receipt.completed_at.isoformat()
    else:
        edge.valid_from = (baseline.receipt.completed_at + timedelta(seconds=1)).isoformat()
    baseline = _reseal(baseline)
    request = request.model_copy(update={"baseline_graph_digest": baseline.receipt.graph_digest})
    result = _compare(baseline, candidate, request)
    assert result.outcome == "unavailable_evidence"
    assert result.reason_codes == ("baseline_access_not_established",)
    assert result.selected_authorization_removed is None


@pytest.mark.parametrize("relationship", [RelationshipType.AUTHENTICATES_AS, RelationshipType.CAN_ACCESS])
@pytest.mark.parametrize("lifecycle", ["closed", "expired", "not_yet_valid"])
def test_inactive_alternate_hop_is_not_a_remaining_access_witness(relationship, lifecycle):
    baseline, candidate, request = _pair(alternate=True, candidate_bindings=[_binding("alternate-read", OTHER)])
    edge = next(
        edge
        for edge in candidate.graph.edges
        if edge.relationship == relationship and (edge.target == "alternate" or edge.source == "alternate")
    )
    if lifecycle == "closed":
        edge.activity_id = 3
    elif lifecycle == "expired":
        edge.valid_to = candidate.receipt.completed_at.isoformat()
    else:
        edge.valid_from = (candidate.receipt.completed_at + timedelta(seconds=1)).isoformat()
    candidate = _reseal(candidate)
    request = request.model_copy(update={"candidate_graph_digest": candidate.receipt.graph_digest})
    result = _compare(baseline, candidate, request)
    assert result.remaining_path == ()
    if relationship is RelationshipType.AUTHENTICATES_AS:
        # The alternate principal's native grant remains, but the recorded
        # agent session no longer reaches it. This is only recorded path proof.
        assert result.outcome == "recorded_authorization_removed"
        assert result.selected_authorization_removed is True
    else:
        # A still-reachable principal with an ALLOW but no active action edge
        # is inconsistent evidence, never proof of removal or residual access.
        assert result.outcome == "unavailable_evidence"
        assert result.reason_codes == ("authorization_graph_inconsistent",)
    assert result.remediation_verified is False
    assert result.successful_action_proven is False


@pytest.mark.parametrize("conditional", [False, True])
def test_alternate_native_deny_is_reevaluated_without_assuming_conditions(conditional):
    baseline, candidate, request = _pair(alternate=True, candidate_bindings=[_binding("alternate-read", OTHER)])
    deny = replace(
        _binding("alternate-deny", OTHER),
        effect=AuthorizationEffect.DENY,
        condition=AuthorizationCondition(ConditionLanguage.CEL, "request.time < timestamp('2030-01-01T00:00:00Z')")
        if conditional
        else None,
    )
    candidate = replace(candidate, authorization=replace(candidate.authorization, bindings=(*candidate.authorization.bindings, deny)))
    # A collector must not materialize an ALLOW edge after a deny or unknown
    # condition; the comparison rechecks the native policy for reachable roles.
    candidate.graph.edges = [edge for edge in candidate.graph.edges if edge.target != "data"]
    candidate = _reseal(candidate)
    request = request.model_copy(update={"candidate_graph_digest": candidate.receipt.graph_digest})
    result = _compare(baseline, candidate, request)
    assert result.outcome == ("unavailable_evidence" if conditional else "recorded_authorization_removed")
    assert result.reason_codes == (("authorization_indeterminate",) if conditional else ())
    assert not result.remaining_path
    assert not result.remediation_verified


def test_closed_alternate_identity_remains_inactive_after_sqlite_roundtrip(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    baseline, candidate, request = _pair(alternate=True, candidate_bindings=[_binding("alternate-read", OTHER)])
    edge = next(edge for edge in candidate.graph.edges if edge.target == "alternate")
    edge.activity_id = 3
    candidate = _reseal(candidate)
    request = request.model_copy(update={"candidate_graph_digest": candidate.receipt.graph_digest})
    store = SQLiteGraphStore(tmp_path / "closed-session.db")
    store.save_graph(candidate.graph)
    restored = store.load_graph(scan_id="rescan", tenant_id="tenant-a")
    assert correlation_graph_digest(restored) == candidate.receipt.graph_digest
    assert next(edge for edge in restored.edges if edge.target == "alternate").activity_id == 3
    result = _compare(baseline, replace(candidate, graph=restored), request)
    assert result.outcome == "recorded_authorization_removed"
    assert result.remaining_path == ()
    assert result.remediation_verified is False
