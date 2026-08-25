"""Persistence and pure-operation contracts for proposed graph scenarios."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agent_bom.api.graph_scenario_store import (
    GraphScenarioConflictError,
    InMemoryGraphScenarioStore,
    SQLiteGraphScenarioStore,
)
from agent_bom.api.routes.graph_scenarios import (
    GraphScenarioCreate,
    _apply_operations,
    _path_id,
)
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode


def _record(
    scenario_id: str = "scenario-1",
    *,
    tenant_id: str = "tenant-a",
    revision: int = 1,
    updated_at: str = "2026-08-25T00:00:00+00:00",
) -> dict[str, Any]:
    return {
        "id": scenario_id,
        "tenant_id": tenant_id,
        "base_scan_id": "snapshot-1",
        "revision": revision,
        "name": "Private endpoint design",
        "description": "Proposed architecture; not observed state.",
        "operations": [{"kind": "patch_node", "node_id": "cloud:api", "patch": {"risk_score": 2.0}}],
        "assumptions": ["Traffic moves through the private endpoint"],
        "created_by": "analyst@example.test",
        "provenance": {
            "kind": "proposed",
            "modeled": True,
            "scenario_id": scenario_id,
            "base_scan_id": "snapshot-1",
            "authority": "operator_authored_scenario",
            "created_by": "analyst@example.test",
        },
        "created_at": "2026-08-25T00:00:00+00:00",
        "updated_at": updated_at,
    }


@pytest.fixture(params=["memory", "sqlite"])
def scenario_store(request: pytest.FixtureRequest, tmp_path: Path) -> Any:
    if request.param == "memory":
        return InMemoryGraphScenarioStore()
    return SQLiteGraphScenarioStore(str(tmp_path / "scenarios.db"))


def test_store_crud_is_tenant_scoped_and_ids_are_tenant_local(scenario_store: Any) -> None:
    tenant_a = _record(tenant_id="tenant-a")
    tenant_b = _record(tenant_id="tenant-b")

    scenario_store.create("tenant-a", tenant_a)
    scenario_store.create("tenant-b", tenant_b)

    assert scenario_store.get("tenant-a", "scenario-1")["tenant_id"] == "tenant-a"
    assert scenario_store.get("tenant-b", "scenario-1")["tenant_id"] == "tenant-b"
    assert scenario_store.get("tenant-c", "scenario-1") is None
    assert [row["tenant_id"] for row in scenario_store.list("tenant-a")] == ["tenant-a"]
    assert scenario_store.count("tenant-a") == 1
    assert scenario_store.count("tenant-b") == 1

    assert scenario_store.delete_tenant("tenant-a") == 1
    assert scenario_store.get("tenant-a", "scenario-1") is None
    assert scenario_store.get("tenant-b", "scenario-1") is not None


def test_store_rejects_duplicate_id_within_one_tenant(scenario_store: Any) -> None:
    scenario_store.create("tenant-a", _record())
    with pytest.raises(GraphScenarioConflictError, match="already exists"):
        scenario_store.create("tenant-a", _record())


def test_store_rejects_record_tenant_mismatch(scenario_store: Any) -> None:
    with pytest.raises(GraphScenarioConflictError, match="identity"):
        scenario_store.create("tenant-b", _record(tenant_id="tenant-a"))


def test_store_returns_defensive_copies(scenario_store: Any) -> None:
    original = _record()
    created = scenario_store.create("tenant-a", original)

    original["operations"][0]["patch"]["risk_score"] = 9.9
    created["provenance"]["kind"] = "observed"
    fetched = scenario_store.get("tenant-a", "scenario-1")
    assert fetched is not None
    assert fetched["operations"][0]["patch"]["risk_score"] == 2.0
    assert fetched["provenance"]["kind"] == "proposed"

    fetched["assumptions"].append("mutated caller copy")
    listed = scenario_store.list("tenant-a")
    listed[0]["operations"].clear()
    reread = scenario_store.get("tenant-a", "scenario-1")
    assert reread is not None
    assert reread["assumptions"] == ["Traffic moves through the private endpoint"]
    assert len(reread["operations"]) == 1


def test_update_and_delete_use_optimistic_revisions(scenario_store: Any) -> None:
    scenario_store.create("tenant-a", _record())
    revision_two = _record(revision=2, updated_at="2026-08-25T01:00:00+00:00")
    revision_two["name"] = "Revision two"

    updated = scenario_store.update(
        "tenant-a",
        "scenario-1",
        expected_revision=1,
        scenario=revision_two,
    )
    assert updated["revision"] == 2
    assert updated["name"] == "Revision two"

    with pytest.raises(GraphScenarioConflictError, match="revision conflict"):
        scenario_store.update("tenant-a", "scenario-1", expected_revision=1, scenario=revision_two)
    with pytest.raises(GraphScenarioConflictError, match="revision conflict"):
        scenario_store.delete("tenant-a", "scenario-1", expected_revision=1)
    skipped_revision = _record(revision=4, updated_at="2026-08-25T02:00:00+00:00")
    with pytest.raises(GraphScenarioConflictError, match="advance exactly once"):
        scenario_store.update(
            "tenant-a",
            "scenario-1",
            expected_revision=2,
            scenario=skipped_revision,
        )

    assert scenario_store.delete("tenant-a", "scenario-1", expected_revision=2) is True
    assert scenario_store.delete("tenant-a", "scenario-1", expected_revision=2) is False
    missing = _record("missing", revision=2)
    with pytest.raises(KeyError):
        scenario_store.update("tenant-a", "missing", expected_revision=1, scenario=missing)


def test_only_one_concurrent_revision_update_commits(scenario_store: Any) -> None:
    scenario_store.create("tenant-a", _record())

    def update(name: str) -> str:
        candidate = _record(revision=2, updated_at=f"2026-08-25T00:00:0{name[-1]}+00:00")
        candidate["name"] = name
        try:
            scenario_store.update("tenant-a", "scenario-1", expected_revision=1, scenario=candidate)
        except GraphScenarioConflictError:
            return "conflict"
        return "committed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(update, ("candidate-1", "candidate-2")))

    assert outcomes == ["committed", "conflict"]
    stored = scenario_store.get("tenant-a", "scenario-1")
    assert stored is not None and stored["revision"] == 2
    assert stored["name"] in {"candidate-1", "candidate-2"}


def _observed_graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="snapshot-1", tenant_id="tenant-a")
    graph.add_node(UnifiedNode(id="cloud:api", entity_type=EntityType.CLOUD_RESOURCE, label="public-api", risk_score=8.0))
    graph.add_node(UnifiedNode(id="role:app", entity_type=EntityType.ROLE, label="application-role"))
    graph.add_node(UnifiedNode(id="db:orders", entity_type=EntityType.DATA_STORE, label="orders"))
    graph.add_edge(UnifiedEdge(source="role:app", target="cloud:api", relationship=RelationshipType.CAN_ACCESS))
    graph.add_edge(UnifiedEdge(source="cloud:api", target="db:orders", relationship=RelationshipType.CAN_ACCESS))
    return graph


def _scenario_with(operations: list[dict[str, Any]]) -> dict[str, Any]:
    scenario = _record()
    scenario["operations"] = operations
    return scenario


def test_operations_are_deterministic_and_do_not_mutate_observed_graph() -> None:
    graph = _observed_graph()
    observed_before = copy.deepcopy(graph.to_dict())
    scenario = _scenario_with(
        [
            {"kind": "patch_node", "node_id": "cloud:api", "patch": {"risk_score": 3.0, "attributes": {"environment": "production"}}},
            {"kind": "add_node", "key": "waf", "entity_type": "policy", "label": "edge-waf"},
            {"kind": "add_edge", "source": "proposal:waf", "target": "cloud:api", "relationship": "protects"},
        ]
    )
    paths = [AttackPath(source="role:app", target="db:orders", hops=["role:app", "cloud:api", "db:orders"])]

    first = _apply_operations(scenario=scenario, graph=graph, exact_node_count=3, exact_edge_count=2, attack_paths=paths)
    second = _apply_operations(scenario=scenario, graph=graph, exact_node_count=3, exact_edge_count=2, attack_paths=paths)

    assert first == second
    assert graph.to_dict() == observed_before
    assert first["difference"]["nodes_added"] == ["proposal:scenario-1:waf"]
    assert first["difference"]["nodes_changed"] == ["cloud:api"]
    assert first["difference"]["touched_observed_path_ids"] == [_path_id(paths[0])]


@pytest.mark.parametrize(
    "operations",
    [
        [{"kind": "patch_node", "node_id": "missing", "patch": {"risk_score": 1.0}}],
        [{"kind": "remove_node", "node_id": "missing"}],
        [{"kind": "unknown_operation", "node_id": "cloud:api"}],
        [{"kind": "add_edge", "source": "missing", "target": "cloud:api", "relationship": "uses"}],
        [{"kind": "remove_edge", "source": "cloud:api", "target": "role:app", "relationship": "uses"}],
        [{"kind": "add_edge", "source": "role:app", "target": "cloud:api", "relationship": "can_access"}],
    ],
)
def test_unknown_dangling_and_conflicting_operations_fail_closed(operations: list[dict[str, Any]]) -> None:
    with pytest.raises(ValueError):
        _apply_operations(
            scenario=_scenario_with(operations),
            graph=_observed_graph(),
            exact_node_count=3,
            exact_edge_count=2,
            attack_paths=[],
        )


def test_all_proposed_changes_carry_immutable_provenance() -> None:
    graph = _observed_graph()
    scenario = _scenario_with(
        [
            {"kind": "patch_node", "node_id": "cloud:api", "patch": {"owner": "ignored"}},
            {"kind": "add_node", "key": "waf", "entity_type": "policy", "label": "edge-waf"},
            {"kind": "add_edge", "source": "proposal:waf", "target": "cloud:api", "relationship": "protects"},
        ]
    )
    # Use a supported attribute spelling; the operation schema intentionally
    # forbids callers from injecting scenario_provenance or observed authority.
    scenario["operations"][0] = {
        "kind": "patch_node",
        "node_id": "cloud:api",
        "patch": {"attributes": {"owner": "platform-security"}},
    }
    original_provenance = copy.deepcopy(scenario["provenance"])

    result = _apply_operations(scenario=scenario, graph=graph, exact_node_count=3, exact_edge_count=2, attack_paths=[])
    proposed_nodes = {node["id"]: node for node in result["proposed"]["nodes"]}
    added_edge = next(edge for edge in result["proposed"]["edges"] if edge["source"] == "proposal:scenario-1:waf")
    added_node_id = "proposal:scenario-1:waf"
    for proposed in (
        proposed_nodes["cloud:api"]["scenario_provenance"],
        proposed_nodes[added_node_id]["scenario_provenance"],
        added_edge["provenance"],
    ):
        assert {key: proposed[key] for key in original_provenance} == original_provenance
        assert proposed["revision"] == 1
        assert proposed["author"] == "analyst@example.test"
        assert proposed["assumption"] == "Traffic moves through the private endpoint"

    proposed_nodes["cloud:api"]["scenario_provenance"]["authority"] = "mutated-output"
    assert scenario["provenance"] == original_provenance


def test_create_contract_caps_operations_and_forbids_extra_fields() -> None:
    within_cap = [{"kind": "remove_node", "node_id": f"node-{index}"} for index in range(500)]
    GraphScenarioCreate(name="within-cap", base_scan_id="snapshot-1", changes=within_cap)

    with pytest.raises(ValidationError):
        GraphScenarioCreate(
            name="over-cap",
            base_scan_id="snapshot-1",
            changes=[{"kind": "remove_node", "node_id": f"node-{index}"} for index in range(501)],
        )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        GraphScenarioCreate(name="extra", base_scan_id="snapshot-1", unexpected=True)  # type: ignore[call-arg]
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        GraphScenarioCreate(
            name="operation-extra",
            base_scan_id="snapshot-1",
            changes=[{"kind": "remove_node", "node_id": "node-1", "authority": "observed"}],
        )


def test_create_contract_rejects_duplicate_semantic_additions() -> None:
    with pytest.raises(ValidationError, match="unique key"):
        GraphScenarioCreate(
            name="duplicate nodes",
            base_scan_id="snapshot-1",
            changes=[
                {"kind": "add_node", "key": "new", "entity_type": "policy", "label": "one"},
                {"kind": "add_node", "key": "new", "entity_type": "policy", "label": "two"},
            ],
        )
    with pytest.raises(ValidationError, match="semantic edge identities"):
        GraphScenarioCreate(
            name="duplicate edges",
            base_scan_id="snapshot-1",
            changes=[
                {"kind": "add_edge", "source": "a", "target": "b", "relationship": "uses"},
                {"kind": "add_edge", "source": "a", "target": "b", "relationship": "uses", "weight": 2.0},
            ],
        )


def test_path_identity_is_stable_and_uses_endpoints_and_ordered_hops() -> None:
    baseline = AttackPath(source="a", target="c", hops=["a", "b", "c"])
    assert _path_id(baseline) == _path_id(copy.deepcopy(baseline))
    assert _path_id(baseline) != _path_id(AttackPath(source="a", target="c", hops=["a", "x", "c"]))
    assert _path_id(baseline) != _path_id(AttackPath(source="c", target="a", hops=["c", "b", "a"]))
