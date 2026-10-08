"""Adversarial contracts for privately reviewed investigation measurements."""

from copy import deepcopy

import pytest

from agent_bom.graph.investigation_measurement import evaluate_investigation, evidence_digest


def bundle():
    edge = {"source": "agent:a", "target": "server:a", "relationship": "uses"}
    graph = {
        "schema_version": "1.0",
        "scan_id": "before",
        "tenant_id": "tenant-a",
        "nodes": [{"id": "agent:a"}, {"id": "server:a"}],
        "edges": [edge],
        "completeness": {"status": "complete", "complete": True, "truncated": False, "sampled": False, "returned": 2, "total": 2},
    }
    before = {
        "scope_id": "pilot-a",
        "collected_at": "2026-10-01T09:00:00Z",
        "collection_complete": True,
        "source_evidence_ref": "collector:before",
        "graph": graph,
    }
    after = deepcopy(before)
    after.update(collected_at="2026-10-01T09:12:00Z", source_evidence_ref="collector:after")
    after["graph"].update(scan_id="after", edges=[])
    review = {
        "schema_version": "investigation-review.v1",
        "evidence_origin": "fixture",
        "tenant_id": "tenant-a",
        "scope_id": "pilot-a",
        "reviewer_ref": "reviewer:one",
        "reviewed_at": "2026-10-01T09:15:00Z",
        "before_digest": evidence_digest(before),
        "after_digest": evidence_digest(after),
        "timeline": {
            "investigation_started_at": "2026-10-01T09:01:00Z",
            "decision_at": "2026-10-01T09:05:00Z",
            "change_applied_at": "2026-10-01T09:10:00Z",
            "rescan_started_at": "2026-10-01T09:11:00Z",
        },
        "change_evidence_ref": "change:approved-and-applied",
        "relationships": [
            dict(edge, snapshot="before", expected=True, evidence_ref="source:positive"),
            dict(edge, snapshot="after", expected=False, evidence_ref="source:negative"),
        ],
        "outcomes": [
            {
                "check_id": "relationship-removed",
                "edge": edge,
                "before_present": True,
                "after_present": False,
                "verification_ref": "collector:verified-change",
            }
        ],
    }
    return before, after, review


def evaluate(before=None, after=None, review=None):
    b, a, r = bundle()
    return evaluate_investigation(before or b, after or a, review or r)


def rebound(b, a, r):
    r.update(before_digest=evidence_digest(b), after_digest=evidence_digest(a))
    return evaluate_investigation(b, a, r)


def test_reviewed_positive_and_negative_denominators_and_reported_time():
    result = evaluate()
    assert result["relationships"]["true_positive"] == 1
    assert result["relationships"]["true_negative"] == 1
    assert result["relationships"]["precision"] == 1
    assert result["relationships"]["false_positive_rate"] == 0
    assert result["timing"]["reported_investigation_seconds"] == 240
    assert result["outcomes"]["evidence_supported"] == 1
    assert result["evidence_origin"] == "fixture"
    assert result["independently_verified"] is False


def test_unreviewed_edges_never_count_as_false_correlations():
    b, a, r = bundle()
    b["graph"]["edges"].append({"source": "server:a", "target": "agent:a", "relationship": "uses"})
    result = rebound(b, a, r)
    assert result["relationships"]["unreviewed_observed"] == 1
    assert result["relationships"]["false_positive"] == 0
    assert result["relationships"]["observed_review_coverage"] == 0.5


def test_known_false_correlation_and_missing_expected_edge_reduce_scores():
    b, a, r = bundle()
    r["relationships"][0]["expected"] = False
    r["relationships"][1]["expected"] = True
    result = rebound(b, a, r)
    assert result["relationships"]["false_positive"] == 1
    assert result["relationships"]["false_negative"] == 1
    assert result["relationships"]["precision"] == 0
    assert result["relationships"]["recall"] == 0


@pytest.mark.parametrize("mutation", ["truncated", "missing_completeness", "collection_failed", "paging", "missing_node", "count_mismatch"])
def test_absence_in_incomplete_evidence_never_proves_removal(mutation):
    b, a, r = bundle()
    if mutation == "truncated":
        a["graph"]["completeness"]["truncated"] = True
    elif mutation == "missing_completeness":
        a["graph"].pop("completeness")
    elif mutation == "collection_failed":
        a["collection_complete"] = False
    elif mutation == "paging":
        a["graph"]["pagination"] = {"has_more": True}
    elif mutation == "missing_node":
        a["graph"]["nodes"].pop()
    else:
        a["graph"]["completeness"]["total"] = 4
    result = rebound(b, a, r)
    assert result["relationships"]["unknown"] == 1
    assert result["relationships"]["true_negative"] == 0
    assert result["outcomes"]["unknown"] == 1
    assert result["outcomes"]["evidence_supported"] == 0


def test_missing_negative_labels_and_zero_denominators_are_null():
    b, a, r = bundle()
    r["relationships"] = []
    result = rebound(b, a, r)
    assert result["relationships"]["precision"] is None
    assert result["relationships"]["false_positive_rate"] is None
    assert result["relationships"]["observed_review_coverage"] == 0


@pytest.mark.parametrize(
    "mutation", ["digest", "tenant", "scope", "replay", "time", "duplicate", "naive_time", "extra", "contradictory_label"]
)
def test_ambiguous_or_unbound_inputs_rejected(mutation):
    b, a, r = bundle()
    if mutation == "digest":
        r["before_digest"] = "sha256:" + "0" * 64
    elif mutation == "tenant":
        a["graph"]["tenant_id"] = "other"
    elif mutation == "scope":
        a["scope_id"] = "other"
    elif mutation == "replay":
        a["graph"]["scan_id"] = b["graph"]["scan_id"]
    elif mutation == "time":
        r["timeline"]["decision_at"] = "2026-10-01T09:20:00Z"
    elif mutation == "naive_time":
        r["reviewed_at"] = "2026-10-01T09:15:00"
    elif mutation == "extra":
        r["independently_verified"] = True
    elif mutation == "duplicate":
        r["relationships"].append(deepcopy(r["relationships"][0]))
    else:
        r["relationships"].append(dict(r["relationships"][0], expected=False))
    with pytest.raises(ValueError):
        if mutation == "digest":
            evaluate_investigation(b, a, r)
        else:
            rebound(b, a, r)


def test_unchanged_relationship_is_failed_outcome_not_success():
    b, a, r = bundle()
    a["graph"]["edges"] = deepcopy(b["graph"]["edges"])
    result = rebound(b, a, r)
    assert result["outcomes"]["failed"] == 1
    assert result["outcomes"]["evidence_supported"] == 0


def test_output_contains_hashes_and_counts_not_customer_identifiers():
    import json

    result = evaluate()
    encoded = json.dumps(result)
    for sensitive in ["tenant-a", "pilot-a", "agent:a", "server:a", "reviewer:one", "collector:verified-change"]:
        assert sensitive not in encoded
    assert result["review_digest"].startswith("sha256:")


def test_report_is_deterministic_and_does_not_mutate_evidence():
    b, a, r = bundle()
    original = deepcopy((b, a, r))
    assert evaluate_investigation(b, a, r) == evaluate_investigation(b, a, r)
    assert (b, a, r) == original


def test_duplicate_outcomes_cannot_inflate_verified_count():
    b, a, r = bundle()
    r["outcomes"].append(dict(r["outcomes"][0], check_id="same-check-new-name"))
    with pytest.raises(ValueError):
        rebound(b, a, r)


def test_script_preserves_existing_receipts_and_uses_generic_errors(tmp_path):
    import json
    import subprocess
    import sys
    from pathlib import Path

    script = Path(__file__).resolve().parents[2] / "scripts/evaluate_investigation.py"
    b, a, r = bundle()
    for name, obj in [("before", b), ("after", a), ("review", r)]:
        (tmp_path / f"{name}.json").write_text(json.dumps(obj))
    output = tmp_path / "measurement.json"
    cmd = [
        sys.executable,
        str(script),
        "measure",
        "--before",
        str(tmp_path / "before.json"),
        "--after",
        str(tmp_path / "after.json"),
        "--review",
        str(tmp_path / "review.json"),
        "--output",
        str(output),
    ]
    first = subprocess.run(cmd, capture_output=True, text=True)
    assert first.returncode == 0, first.stderr
    saved = output.read_bytes()
    second = subprocess.run(cmd, capture_output=True, text=True)
    assert second.returncode == 2
    assert output.read_bytes() == saved
    assert str(tmp_path) not in second.stderr


def test_script_rejects_duplicate_json_keys_without_echoing_private_input(tmp_path):
    import subprocess
    import sys
    from pathlib import Path

    script = Path(__file__).resolve().parents[2] / "scripts/evaluate_investigation.py"
    source = tmp_path / "private.json"
    source.write_text('{"graph":{},"graph":{"private":"customer-sensitive-value"}}')
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "measure",
            "--before",
            str(source),
            "--after",
            str(source),
            "--review",
            str(source),
            "--output",
            str(tmp_path / "out.json"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "customer-sensitive-value" not in result.stderr
    assert str(tmp_path) not in result.stderr
    assert not (tmp_path / "out.json").exists()


def test_outer_completeness_cannot_override_incomplete_upstream_receipt():
    b, a, r = bundle()
    a["graph"]["completeness"]["source_completeness"] = {"status": "failed", "complete": False}
    result = rebound(b, a, r)
    assert result["outcomes"]["unknown"] == 1


def test_false_discovery_rate_uses_reviewed_observed_relationships():
    b, a, r = bundle()
    r["relationships"][0]["expected"] = False
    result = rebound(b, a, r)
    assert result["relationships"]["false_discovery_rate"] == 1


def test_persisted_production_graph_exports_use_the_same_measurement_contract(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

    b, a, r = bundle()
    store = SQLiteGraphStore(tmp_path / "graphs.db")
    for label, wrapper in [("before", b), ("after", a)]:
        graph = UnifiedGraph(scan_id=label, tenant_id="tenant-a")
        graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent"))
        graph.add_node(UnifiedNode(id="server:a", entity_type=EntityType.SERVER, label="server"))
        if label == "before":
            graph.add_edge(UnifiedEdge(source="agent:a", target="server:a", relationship=RelationshipType.USES))
        store.save_graph(graph)
        wrapper["graph"] = store.load_graph(scan_id=label, tenant_id="tenant-a").to_dict()
    result = rebound(b, a, r)
    assert result["outcomes"]["evidence_supported"] == 1


@pytest.mark.parametrize("field", ["edges_truncated", "depth_limited", "missing_neighbor_endpoints"])
def test_relationship_bounds_override_node_completeness(field):
    b, a, r = bundle()
    a["graph"]["completeness"][field] = True
    assert rebound(b, a, r)["outcomes"]["unknown"] == 1


def test_unversioned_api_graph_payload_is_accepted_without_inventing_completeness():
    b, a, r = bundle()
    b["graph"].pop("schema_version")
    a["graph"].pop("schema_version")
    assert rebound(b, a, r)["outcomes"]["evidence_supported"] == 1
