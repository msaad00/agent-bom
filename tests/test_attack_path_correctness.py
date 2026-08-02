"""Attack paths must be real, and honest about where the walk stopped.

Two independent failure modes, both worse than a missing feature:

*Fabrication.* A credential node keyed by env-var *name* alone merges two
unrelated servers' credential slots into one node, so agent-a's estate and
agent-b's estate share a graph node they have no relationship through. Every
downstream reader then sees a lateral-movement route that does not exist.
``graph/builder.py`` and ``context_graph.py`` were scoped to the server for
exactly this reason; the agent-manifest graph — the CLI ``manifest`` export and
``GET /v1/agent-manifest`` — was not.

*Silent depth cuts.* ``bfs_paths`` / ``traverse_subgraph`` / ``impact_of`` stop
at ``max_depth`` (4 by default, chosen by the server when a caller passes
nothing) and report the bound as the answer: ``complete: true`` with
``total`` equal to what the bound happened to reach. That is the class #4595
fixed for the node/edge budget, unfixed for the depth bound — and it reads as
"there is no attack path past here" rather than "we stopped looking".

Ground truth in every fixture is known by construction, so the assertions are
counts, not judgements. Each honesty test is paired with a guard that the walk
which really did exhaust the graph still reports ``truncated: False`` with the
true total — a blanket "truncated" would be as dishonest as the bug.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

CHAIN = 9
"""``n0 -> n1 -> ... -> n8``: 8 nodes reachable from n0, 8 ancestors of n8.

Kept under the routes' ``max_depth`` ceiling of 10 so the paired "the walk really
did exhaust the graph" guard is reachable over HTTP, not only in-process."""


def chain(total: int = CHAIN, *, scan_id: str = "chain", tenant_id: str = "default") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    for index in range(total):
        graph.add_node(UnifiedNode(id=f"n{index}", entity_type=EntityType.AGENT, label=f"n{index}"))
    for index in range(total - 1):
        graph.add_edge(
            UnifiedEdge(
                source=f"n{index}",
                target=f"n{index + 1}",
                relationship=RelationshipType.USES,
                traversable=True,
            )
        )
    return graph


def components(node_ids: set[str], edges: list[tuple[str, str]]) -> list[list[str]]:
    """Undirected connected components — the shape a fabricated edge changes."""
    adjacency: dict[str, set[str]] = {node_id: set() for node_id in node_ids}
    for source, target in edges:
        if source in adjacency and target in adjacency:
            adjacency[source].add(target)
            adjacency[target].add(source)
    seen: set[str] = set()
    found: list[list[str]] = []
    for node_id in sorted(node_ids):
        if node_id in seen:
            continue
        stack, group = [node_id], []
        seen.add(node_id)
        while stack:
            current = stack.pop()
            group.append(current)
            for neighbour in adjacency[current]:
                if neighbour not in seen:
                    seen.add(neighbour)
                    stack.append(neighbour)
        found.append(sorted(group))
    return found


SHORT_CHAIN = 5
"""``POST /v1/graph/query`` is additionally capped by the tenant query budget at
``max_depth`` 5, so the "walk really did exhaust the graph" guard for that route
needs a chain a depth-5 walk can finish."""


@pytest.fixture
def store(tmp_path):
    graph_store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    graph_store.save_graph(chain())
    graph_store.save_graph(chain(SHORT_CHAIN, scan_id="short"))
    return graph_store


@pytest.fixture
def client(store):
    original = api_stores._graph_store
    set_graph_store(store)
    try:
        yield TestClient(app)
    finally:
        set_graph_store(original)


# ── Fabrication: credential identity ────────────────────────────────────────


def manifest_graph(*creds: tuple[str, str]):
    """Build the manifest graph for one server per ``(server_name, env_var)``."""
    from agent_bom.agent_manifest import build_local_agent_manifest
    from agent_bom.models import Agent, AgentType, MCPServer

    agent_types = [AgentType.CLAUDE_DESKTOP, AgentType.CURSOR, AgentType.WINDSURF]
    agents = [
        Agent(
            name=f"agent-{index}",
            agent_type=agent_types[index % len(agent_types)],
            config_path=f"/tmp/agent-{index}.json",
            mcp_servers=[MCPServer(name=server_name, command=f"/usr/bin/{server_name}", env={env_var: "redacted"})],
        )
        for index, (server_name, env_var) in enumerate(creds)
    ]
    return build_local_agent_manifest(agents)["graph"]


class TestCredentialIdentityIsNotFabricated:
    def test_two_servers_reading_the_same_env_var_name_are_not_connected(self):
        """Ground truth: two unrelated estates. Anything less than 2 components
        is a lateral-movement route the scan has no evidence for."""
        graph = manifest_graph(("srv-a", "API_KEY"), ("srv-b", "API_KEY"))

        node_ids = {node["id"] for node in graph["nodes"]}
        found = components(node_ids, [(edge["source"], edge["target"]) for edge in graph["edges"]])

        assert len(found) == 2, f"same-named credential slots merged {len(found)} estates into one: {found}"

    def test_each_server_still_keeps_its_own_credential_slot(self):
        """Recall guard: scoping the node may not drop a credential."""
        graph = manifest_graph(("srv-a", "API_KEY"), ("srv-b", "API_KEY"))

        credentials = [node for node in graph["nodes"] if node["entity_type"] == "credential"]
        exposures = [edge for edge in graph["edges"] if edge["relationship"] == "exposes_cred"]

        assert len(credentials) == 2
        assert len(exposures) == 2
        assert {node["label"] for node in credentials} == {"API_KEY"}
        assert len({edge["target"] for edge in exposures}) == 2, "both servers still point at one credential node"

    def test_one_server_with_two_credentials_keeps_both(self):
        """Recall guard on the other axis: distinct names on one server."""
        from agent_bom.agent_manifest import build_local_agent_manifest
        from agent_bom.models import Agent, AgentType, MCPServer

        server = MCPServer(name="srv", command="/usr/bin/srv", env={"API_KEY": "x", "DB_PASSWORD": "y"})
        agent = Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/a.json", mcp_servers=[server])

        graph = build_local_agent_manifest([agent])["graph"]
        credentials = [node for node in graph["nodes"] if node["entity_type"] == "credential"]

        assert {node["label"] for node in credentials} == {"API_KEY", "DB_PASSWORD"}


# ── Honesty: the depth cut ──────────────────────────────────────────────────


class TestContainerDepthHonesty:
    def test_a_walk_stopped_by_the_depth_cap_is_not_complete(self):
        source = chain()

        sub, _depths, _truncated = source.traverse_subgraph(["n0"], max_depth=4)
        completeness = sub.completeness.to_dict()

        assert len(sub.nodes) == 5
        assert completeness["complete"] is False, "5 of 9 nodes returned while reporting a complete walk"
        assert completeness["truncated"] is True
        assert completeness["reason"] == "depth_limit"

    def test_a_walk_that_exhausts_the_graph_inside_the_cap_stays_complete(self):
        """Non-vacuity pair: the fix may not mark every bounded walk truncated.

        ``max_depth`` is the exact eccentricity of the chain, so the last node
        sits *at* the cap: the frontier check runs and must find nothing left,
        rather than never running at all."""
        source = chain()

        sub, _depths, _truncated = source.traverse_subgraph(["n0"], max_depth=CHAIN - 1)
        completeness = sub.completeness.to_dict()

        assert len(sub.nodes) == CHAIN
        assert completeness["complete"] is True
        assert completeness["truncated"] is False
        assert completeness["total"] == CHAIN

    def test_the_deeper_node_budget_loss_still_names_itself_first(self):
        """A budget overrun outranks a depth cut: widening depth cannot recover
        nodes the budget never visited."""
        source = chain()

        sub, _depths, truncated = source.traverse_subgraph(["n0"], max_depth=4, max_nodes=3)

        assert truncated is True
        assert sub.completeness.to_dict()["reason"] == "traversal_budget"


class TestSqliteTraversalHonesty:
    def test_traverse_subgraph_reports_the_nodes_it_actually_returned(self, store):
        """The #4595 self-contradiction, still live in the SQLite store:
        N nodes returned beside ``returned: 0, total: 0, complete: true``."""
        graph, _depths, _truncated = store.traverse_subgraph(tenant_id="default", scan_id="chain", roots=["n0"], max_depth=CHAIN - 1)
        completeness = graph.completeness.to_dict()

        assert len(graph.nodes) == CHAIN
        assert completeness["returned"] == len(graph.nodes)
        assert completeness["total"] == CHAIN

    def test_traverse_subgraph_depth_cut_is_not_complete(self, store):
        graph, _depths, _truncated = store.traverse_subgraph(tenant_id="default", scan_id="chain", roots=["n0"], max_depth=4)
        completeness = graph.completeness.to_dict()

        assert len(graph.nodes) == 5
        assert completeness["complete"] is False
        assert completeness["reason"] == "depth_limit"

    def test_traverse_subgraph_that_exhausts_the_graph_stays_complete(self, store):
        graph, _depths, truncated = store.traverse_subgraph(tenant_id="default", scan_id="chain", roots=["n0"], max_depth=CHAIN - 1)

        assert truncated is False
        assert graph.completeness.to_dict()["complete"] is True

    def test_bfs_paths_reports_that_the_depth_cap_cut_the_walk(self, store):
        paths, reachable, _truncated, depth_limited = store.bfs_paths(tenant_id="default", scan_id="chain", source="n0", max_depth=4)

        assert len(paths) == 4
        assert len(reachable) == 4
        assert depth_limited is True, "4 of 8 reachable nodes walked, reported as the whole answer"

    def test_bfs_paths_that_reaches_every_node_is_not_depth_limited(self, store):
        paths, reachable, truncated, depth_limited = store.bfs_paths(tenant_id="default", scan_id="chain", source="n0", max_depth=CHAIN - 1)

        assert len(reachable) == CHAIN - 1
        assert len(paths) == CHAIN - 1
        assert truncated is False
        assert depth_limited is False


# ── Honesty: the HTTP surfaces a user actually reads ────────────────────────


class TestGraphPathsRoute:
    def test_a_depth_bound_is_not_reported_as_the_path_total(self, client):
        response = client.get("/v1/graph/paths?source_id=n0&scan_id=chain&max_depth=4")
        body = response.json()

        assert response.status_code == 200
        assert len(body["paths"]) == 4
        assert body["completeness"]["complete"] is False
        assert body["completeness"]["truncated"] is True
        assert body["completeness"]["reason"] == "depth_limit"
        assert "total" not in body["completeness"], "a depth-bounded BFS cannot know the path total"

    def test_a_walk_that_exhausts_the_graph_reports_the_true_total(self, client):
        """#4595's paired invariant: a complete source still reports its total."""
        response = client.get(f"/v1/graph/paths?source_id=n0&scan_id=chain&max_depth={CHAIN - 1}")
        body = response.json()

        assert body["reachable_count"] == CHAIN - 1
        assert body["completeness"]["complete"] is True
        assert body["completeness"]["truncated"] is False
        assert body["completeness"]["total"] == CHAIN - 1


class TestGraphImpactRoute:
    def test_a_depth_bounded_blast_radius_says_so(self, client):
        """``affected_count: 4`` over 8 true ancestors, with no completeness
        field at all, reads as the whole blast radius."""
        response = client.get(f"/v1/graph/impact?node=n{CHAIN - 1}&scan_id=chain&max_depth=4")
        body = response.json()

        assert response.status_code == 200
        assert body["affected_count"] == 4
        assert body["completeness"]["complete"] is False
        assert body["completeness"]["reason"] == "depth_limit"

    def test_an_exhaustive_blast_radius_reports_complete(self, client):
        response = client.get(f"/v1/graph/impact?node=n{CHAIN - 1}&scan_id=chain&max_depth={CHAIN - 1}")
        body = response.json()

        assert body["affected_count"] == CHAIN - 1
        assert body["completeness"]["complete"] is True
        assert body["completeness"]["truncated"] is False


class TestGraphQueryRoute:
    def test_a_depth_cut_subgraph_is_not_reported_complete(self, client):
        response = client.post("/v1/graph/query", json={"roots": ["n0"], "scan_id": "chain", "max_depth": 4})
        body = response.json()

        assert response.status_code == 200
        assert len(body["nodes"]) == 5
        assert body["completeness"]["complete"] is False
        assert body["completeness"]["reason"] == "depth_limit"

    def test_an_exhaustive_query_stays_complete(self, client):
        response = client.post("/v1/graph/query", json={"roots": ["n0"], "scan_id": "short", "max_depth": SHORT_CHAIN})
        body = response.json()

        assert len(body["nodes"]) == SHORT_CHAIN
        assert body["completeness"]["complete"] is True
        assert body["completeness"]["truncated"] is False


# ── Precision / recall of the walk itself ───────────────────────────────────


class TestPathPrecisionAndRecall:
    """Every path returned must be a real edge-by-edge walk of the graph, and
    every truly reachable node must be reached when the walk is unbounded."""

    def diamond(self) -> UnifiedGraph:
        """Two disjoint estates. ``a0 -> a1 -> {a2, a3} -> a4`` and ``b0 -> b1``.
        Reachable from a0: a1, a2, a3, a4 (4). From a0 to b*: nothing."""
        graph = UnifiedGraph(scan_id="diamond", tenant_id="default")
        for node_id in ("a0", "a1", "a2", "a3", "a4", "b0", "b1"):
            graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.AGENT, label=node_id))
        for source, target in (("a0", "a1"), ("a1", "a2"), ("a1", "a3"), ("a2", "a4"), ("a3", "a4"), ("b0", "b1")):
            graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.USES, traversable=True))
        return graph

    def test_no_path_crosses_into_an_unconnected_estate(self, tmp_path):
        graph_store = SQLiteGraphStore(str(tmp_path / "d.db"))
        graph_store.save_graph(self.diamond())

        paths, reachable, _truncated, _depth_limited = graph_store.bfs_paths(
            tenant_id="default", scan_id="diamond", source="a0", max_depth=10
        )

        assert reachable == {"a1", "a2", "a3", "a4"}, "reached a node the graph does not connect"
        assert not any(hop.startswith("b") for path in paths for hop in path)

    def test_every_returned_path_walks_real_edges(self, tmp_path):
        graph = self.diamond()
        real_edges = {(edge.source, edge.target) for edge in graph.edges}
        graph_store = SQLiteGraphStore(str(tmp_path / "d.db"))
        graph_store.save_graph(graph)

        paths, _reachable, _truncated, _depth_limited = graph_store.bfs_paths(
            tenant_id="default", scan_id="diamond", source="a0", max_depth=10
        )

        assert paths
        for path in paths:
            assert path[0] == "a0"
            for step in range(len(path) - 1):
                assert (path[step], path[step + 1]) in real_edges, f"fabricated hop {path[step]}->{path[step + 1]}"


class TestFusedKillChainPrecisionAndRecall:
    """The flagship surface: end-to-end internet -> ... -> crown-jewel chains.

    The estate below is built so the answer is arithmetic, not opinion. Three
    near-misses are included on purpose, because each is a way a looser walk
    would manufacture a chain: a dead end, a sensitive store with no internet
    entry, and an internet-reachable store holding nothing sensitive.
    """

    def estate(self) -> UnifiedGraph:
        graph = UnifiedGraph(scan_id="fusion", tenant_id="default")

        def node(node_id: str, entity_type: EntityType, **attributes: object) -> None:
            graph.add_node(UnifiedNode(id=node_id, entity_type=entity_type, label=node_id, attributes=attributes))

        for entry in ("entry-a", "entry-b", "entry-c", "entry-e"):
            node(entry, EntityType.CLOUD_RESOURCE, internet_exposed=True)
        for host in ("vm-a", "vm-b", "vm-c", "vm-d"):
            node(host, EntityType.CLOUD_RESOURCE)
        node("vuln-a", EntityType.VULNERABILITY)
        for store in ("db-a", "db-b", "db-d"):
            node(store, EntityType.DATA_STORE, data_sensitivity="pii")
        node("db-e", EntityType.DATA_STORE)  # internet-reachable, but not a jewel

        for source, target, rel in (
            ("entry-a", "vm-a", RelationshipType.CONTAINS),
            ("vm-a", "vuln-a", RelationshipType.VULNERABLE_TO),
            ("vuln-a", "db-a", RelationshipType.CAN_ACCESS),
            ("entry-b", "vm-b", RelationshipType.CONTAINS),
            ("vm-b", "db-b", RelationshipType.STORES),
            ("entry-c", "vm-c", RelationshipType.CONTAINS),  # dead end
            ("vm-d", "db-d", RelationshipType.STORES),  # sensitive, no entry
            ("entry-e", "db-e", RelationshipType.STORES),  # entry, not a jewel
        ):
            graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel))
        return graph

    TRUTH = {("entry-a", "db-a"), ("entry-b", "db-b")}

    def test_fused_chains_are_exactly_the_true_kill_chains(self):
        from agent_bom.graph.attack_path_fusion import compute_fused_attack_paths

        graph = self.estate()

        found = {(path.source, path.target) for path in compute_fused_attack_paths(graph)}

        assert found - self.TRUTH == set(), "fabricated kill-chain"
        assert self.TRUTH - found == set(), "missed a real kill-chain"

    def test_every_hop_of_a_fused_chain_is_a_real_edge(self):
        from agent_bom.graph.attack_path_fusion import compute_fused_attack_paths

        graph = self.estate()
        real_edges = {(edge.source, edge.target) for edge in graph.edges}

        paths = compute_fused_attack_paths(graph)

        assert paths
        for path in paths:
            for step in range(len(path.hops) - 1):
                hop = (path.hops[step], path.hops[step + 1])
                assert hop in real_edges, f"chain {path.hops} traverses an edge the graph does not hold: {hop}"
