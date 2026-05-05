"""Guard A — round-trip property test (#2259).

Builds the context graph from an inventory, projects it back to an inventory
ID-set view, and asserts ``original ⊆ projected`` (no nodes silently dropped
during the build step).

Two fixtures:

1. A tiny synthetic inventory (3 agents, 5 packages on servers, 2 CVEs,
   2 credentials, 1 cloud principal) — exercises every ``EdgeKind`` /
   ``NodeKind`` the builder produces.
2. The trimmed agent-bom self-scan at
   ``tests/fixtures/agent_bom_self_scan_inventory.json`` — exercises a
   real-world payload shape (regenerate via
   ``scripts/rebaseline_graph_edges.py --refresh-self-scan``).
"""

from __future__ import annotations

import pytest

from tests._graph_helpers import (
    build_graph_from_inventory,
    expected_inventory_sets,
    load_self_scan_fixture,
    project_graph_to_inventory_sets,
    synthetic_inventory,
)


def _assert_subset(expected: dict[str, set[str]], projected: dict[str, set[str]]) -> None:
    """Assert every original ID survived the round-trip, per node kind."""
    missing_per_kind: dict[str, set[str]] = {}
    for kind, ids in expected.items():
        missing = ids - projected.get(kind, set())
        if missing:
            missing_per_kind[kind] = missing
    assert not missing_per_kind, "Round-trip lost nodes: " + "; ".join(f"{kind}={sorted(ids)}" for kind, ids in missing_per_kind.items())


class TestRoundTripSynthetic:
    """Tiny deterministic fixture — fails the moment any kind is silently lost."""

    def test_synthetic_round_trip_subset(self) -> None:
        inv = synthetic_inventory()
        graph = build_graph_from_inventory(inv)
        expected = expected_inventory_sets(inv)
        projected = project_graph_to_inventory_sets(graph)
        _assert_subset(expected, projected)

    def test_synthetic_has_three_agents(self) -> None:
        inv = synthetic_inventory()
        graph = build_graph_from_inventory(inv)
        projected = project_graph_to_inventory_sets(graph)
        assert projected["agents"] == {"agent:agent-a", "agent:agent-b", "agent:agent-c"}

    def test_synthetic_emits_iam_role_node(self) -> None:
        """ATTACHED_TO requires an iam_role node from cloud_principal metadata."""
        inv = synthetic_inventory()
        graph = build_graph_from_inventory(inv)
        projected = project_graph_to_inventory_sets(graph)
        assert "iam_role:arn:aws:iam::111:role/agent-a" in projected["iam_roles"]

    def test_synthetic_credentials_classified(self) -> None:
        """``GITHUB_TOKEN`` and ``GH_TOKEN`` both match credential patterns."""
        inv = synthetic_inventory()
        graph = build_graph_from_inventory(inv)
        projected = project_graph_to_inventory_sets(graph)
        assert {"cred:GITHUB_TOKEN", "cred:GH_TOKEN"} <= projected["credentials"]

    def test_synthetic_vulnerabilities_present(self) -> None:
        inv = synthetic_inventory()
        graph = build_graph_from_inventory(inv)
        projected = project_graph_to_inventory_sets(graph)
        assert {"vuln:CVE-2025-0001", "vuln:CVE-2025-0002"} <= projected["vulnerabilities"]


class TestRoundTripSelfScan:
    """Larger real-world fixture — guards against parser regressions."""

    @pytest.fixture(scope="class")
    def inventory(self) -> dict:
        return load_self_scan_fixture()

    def test_self_scan_round_trip_subset(self, inventory: dict) -> None:
        graph = build_graph_from_inventory(inventory)
        expected = expected_inventory_sets(inventory)
        projected = project_graph_to_inventory_sets(graph)
        _assert_subset(expected, projected)

    def test_self_scan_yields_at_least_one_agent(self, inventory: dict) -> None:
        graph = build_graph_from_inventory(inventory)
        projected = project_graph_to_inventory_sets(graph)
        assert len(projected["agents"]) >= 1, "Self-scan must include the agent-bom CLI agent"

    def test_self_scan_servers_attached_to_an_agent(self, inventory: dict) -> None:
        """Every server ID must follow the ``server:<agent>:<name>`` shape."""
        graph = build_graph_from_inventory(inventory)
        projected = project_graph_to_inventory_sets(graph)
        for srv_id in projected["servers"]:
            assert srv_id.startswith("server:"), srv_id
            assert srv_id.count(":") >= 2, srv_id
