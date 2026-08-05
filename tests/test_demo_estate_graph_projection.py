"""The enterprise demo estate must exist in the graph, not only in the story.

``build_demo_estate`` produces 2,068 assets and ``build_estate_findings`` 439
findings on 407 of them, yet the graph a prospect clicks was seeded separately
from a 112-node hand-built showcase. These tests pin the projection: the estate
is one correlated graph — org → account → environment → asset, each finding on
the asset it was raised against, the incident chain traversable end to end — and
the hand-built headline chain survives it.
"""

from __future__ import annotations

from collections import Counter

import pytest

from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_correlation import build_estate_correlations
from agent_bom.demo_estate.enterprise_findings import build_estate_findings
from agent_bom.demo_estate.estate_graph import (
    ESTATE_GRAPH_VERSION,
    estate_account_node_id,
    estate_environment_node_id,
    estate_org_node_id,
    project_estate_into_graph,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.rollup import drill_down, rollup_view
from agent_bom.graph.types import EntityType, RelationshipType

# The correlated incident the estate exists to demonstrate: a workflow assumes a
# role, the role runs a workload, the workload calls an MCP tool, the tool reads
# a PHI table, and the table's rows leave through a hosted model.
INCIDENT_CHAIN: tuple[str, ...] = (
    "github:workflow:member-copilot/deploy-prod",
    "cloud_resource:aws:iam:role:member-copilot-prod",
    "kubernetes:workload:member-ai-prod/ai-prod/member-copilot",
    "mcp:tool:clinical-analytics/execute_sql",
    "snowflake:table:nh_prod/analytics/phi/patient_summary",
    "model:openai:gpt-4.1",
)


@pytest.fixture(scope="module")
def estate():
    return build_demo_estate(tenant_id="default")


@pytest.fixture(scope="module")
def estate_findings(estate):
    return build_estate_findings(estate)


@pytest.fixture(scope="module")
def projected(estate, estate_findings):
    graph = UnifiedGraph(scan_id="estate-test", tenant_id="default")
    summary = project_estate_into_graph(
        graph,
        estate,
        findings=estate_findings,
        correlations=build_estate_correlations(estate),
    )
    return graph, summary


def _edge_pairs(graph: UnifiedGraph) -> set[tuple[str, str, str]]:
    return {
        (
            edge.source,
            edge.target,
            edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship),
        )
        for edge in graph.edges
    }


def test_every_estate_asset_becomes_one_node_under_its_own_id(projected, estate) -> None:
    """The estate's ``asset_id`` IS the node id — no second spelling to reconcile.

    ``enterprise_findings`` guarantees a finding's asset identifier is the
    estate's ``asset_id``; a translation layer here would reintroduce exactly the
    split identity #4637 removed.
    """
    graph, summary = projected
    for asset in estate.assets:
        assert asset.asset_id in graph.nodes, f"estate asset absent from graph: {asset.asset_id}"
    assert summary["assets"] == len(estate.assets)
    assert summary["version"] == ESTATE_GRAPH_VERSION


def test_hierarchy_is_org_account_environment_asset(projected, estate) -> None:
    """Rollup can only collapse what CONTAINS connects."""
    graph, _ = projected
    pairs = _edge_pairs(graph)
    contains = RelationshipType.CONTAINS.value

    org_id = estate_org_node_id(estate)
    assert graph.nodes[org_id].entity_type is EntityType.ORG

    # The AWS account carrying the incident, its production environment, and the
    # role the workflow assumes.
    account_id = estate_account_node_id(estate, "123456789012")
    env_id = estate_environment_node_id(estate, "123456789012", "production")
    role_id = "cloud_resource:aws:iam:role:member-copilot-prod"

    assert account_id == "account:aws:123456789012", account_id
    assert graph.nodes[account_id].entity_type is EntityType.ACCOUNT
    assert graph.nodes[env_id].entity_type is EntityType.ENVIRONMENT
    assert (org_id, account_id, contains) in pairs
    assert (account_id, env_id, contains) in pairs
    assert (env_id, role_id, contains) in pairs

    # Every asset reaches the root through exactly that three-hop spine.
    parents = {edge.target: edge.source for edge in graph.edges if edge.relationship is RelationshipType.CONTAINS}
    for asset in estate.assets:
        if asset.asset_id == org_id:
            continue
        env = parents.get(asset.asset_id)
        assert env is not None, f"asset has no environment parent: {asset.asset_id}"
        account = parents.get(env)
        assert account is not None, f"environment has no account parent: {env}"
        assert parents.get(account) == org_id, f"account {account} is not under the estate root"


def test_findings_attach_to_the_inventoried_asset(projected, estate, estate_findings) -> None:
    """407 distinct inventoried assets, zero stubs — the guarantee #4658 shipped."""
    graph, summary = projected
    asset_ids = {asset.asset_id for asset in estate.assets}

    finding_nodes = [n for n in graph.nodes.values() if n.entity_type is EntityType.MISCONFIGURATION]
    assert len(finding_nodes) == len(estate_findings) == 439, len(finding_nodes)

    affected: set[str] = set()
    for edge in graph.edges:
        if edge.relationship is not RelationshipType.AFFECTS:
            continue
        if graph.nodes[edge.source].entity_type is not EntityType.MISCONFIGURATION:
            continue
        assert edge.target in asset_ids, f"finding attached to a non-inventoried node: {edge.target}"
        affected.add(edge.target)
    assert len(affected) == 407, len(affected)
    assert summary["findings"] == 439

    # Every finding node carries the Finding.id it was projected from, so the
    # findings list and the graph join without a heuristic.
    finding_ids = {f.id for f in estate_findings}
    for node in finding_nodes:
        assert node.attributes.get("finding_id") in finding_ids


def test_incident_chain_is_traversable_end_to_end(projected) -> None:
    """The six-hop correlated chain renders as consecutive edges, not prose."""
    graph, summary = projected
    pairs = {(source, target) for source, target, _ in _edge_pairs(graph)}
    for node_id in INCIDENT_CHAIN:
        assert node_id in graph.nodes, f"incident hop missing: {node_id}"
    for source, target in zip(INCIDENT_CHAIN, INCIDENT_CHAIN[1:], strict=False):
        assert (source, target) in pairs, f"incident chain broken at {source} -> {target}"
    assert summary["chain_edges"] >= len(INCIDENT_CHAIN) - 1

    # ...and is materialized as an attack path so the exposure-path queue and the
    # ranked views see it without re-deriving.
    chains = [p for p in graph.attack_paths if list(p.hops) == list(INCIDENT_CHAIN)]
    assert chains, [p.hops for p in graph.attack_paths]

    # The exposure-path queue ranks by composite risk. Inventory nodes are
    # deliberately unrated, so a chain scored only from its hops' node severity
    # is always 0.0 and the estate's own incident sorts below every hand-built
    # one — an under-claim that hides the thing the demo exists to show. Score it
    # from the findings raised on the hops instead.
    assert chains[0].composite_risk >= 8.0, chains[0].composite_risk


def test_identity_reaches_the_asset_its_finding_names(projected, estate_findings) -> None:
    """Turn "a bucket is misconfigured" into "this principal can read this bucket"."""
    graph, _ = projected
    pairs = {(s, t) for s, t, rel in _edge_pairs(graph) if rel == RelationshipType.CAN_ACCESS.value}
    checked = 0
    for finding in estate_findings:
        principal = str(finding.evidence.get("identity_asset_id") or "")
        if not principal or principal == finding.asset.identifier:
            # A control raised *on* a role names that role as its own principal.
            # A self-loop is not an access relationship and CONTAINS-shaped
            # traversals would cycle on it, so the projection drops it.
            continue
        assert (principal, finding.asset.identifier) in pairs, (
            f"finding names {principal} but the graph has no CAN_ACCESS edge to {finding.asset.identifier}"
        )
        checked += 1
    assert checked > 300, checked


def test_rollup_collapses_the_estate_to_one_readable_root(projected, estate) -> None:
    """2,000 raw nodes are unreadable; the default read is account → env → resource."""
    graph, _ = projected
    view = rollup_view(graph)
    containers = [row for row in view["top_level"] if row.get("is_container") and row.get("has_children")]
    org_id = estate_org_node_id(estate)
    roots = [row for row in containers if row["id"] == org_id]
    assert roots, [row["id"] for row in containers]
    root = roots[0]
    assert root["entity_type"] == EntityType.ORG.value
    assert root["aggregate"]["descendant_count"] >= 2000, root["aggregate"]["descendant_count"]

    # 40 account scopes, not the 46 (provider, scope) pairs the inventory holds:
    # an EKS cluster and the S3 buckets beside it share one AWS account number,
    # and the projection must not split one account into two nodes.
    accounts = drill_down(graph, org_id)["children"]
    assert len(accounts) == 40, len(accounts)
    assert len({(a.provider, a.account_scope) for a in estate.assets}) == 46
    assert {row["entity_type"] for row in accounts} == {EntityType.ACCOUNT.value}

    envs = drill_down(graph, "account:aws:123456789012")["children"]
    assert {row["entity_type"] for row in envs} == {EntityType.ENVIRONMENT.value}
    assert {row["label"] for row in envs} >= {"production"}

    resources = drill_down(graph, estate_environment_node_id(estate, "123456789012", "production"))["children"]
    assert resources, resources
    assert EntityType.ENVIRONMENT.value not in {row["entity_type"] for row in resources}


def test_projection_emits_only_entity_types_the_canvas_can_render(projected) -> None:
    """A node type the canvas has no mapping for vanishes silently (#4640).

    The UI's coverage test asserts every ``EntityType`` maps to a renderer, so
    staying inside the enum is the guarantee — an ad-hoc string would not be.
    """
    graph, _ = projected
    emitted = {node.entity_type for node in graph.nodes.values()}
    assert emitted, "projection emitted no nodes"
    for entity_type in emitted:
        assert isinstance(entity_type, EntityType), entity_type
    counts = Counter(n.entity_type.value for n in graph.nodes.values())
    # The estate is genuinely multi-shaped: identities, data surfaces, compute,
    # code and AI assets all present, not one undifferentiated bucket.
    for required in ("role", "service_account", "service_principal", "data_store", "cluster", "model", "ci_job"):
        assert counts.get(required, 0) > 0, counts


def test_a_bounded_load_of_the_estate_never_reads_as_the_whole_estate(tmp_path, projected) -> None:
    """A trimmed estate must not be byte-identical to a whole one (#4631).

    The shipped 25,000-node investigation budget does NOT bind at this size — the
    projected snapshot is ~2,800 nodes — so the honest thing to verify is that the
    budget *path* still reports correctly when it does bind, and that
    ``completeness.total`` and ``stats.total_nodes_source`` name the estate rather
    than the page.
    """
    from agent_bom.api.graph_store import SQLiteGraphStore

    graph, _ = projected
    store = SQLiteGraphStore(db_path=tmp_path / "budget.db")
    store.save_graph(graph)
    total = len(graph.nodes)

    unbounded = store.load_graph(tenant_id="default", scan_id="estate-test", node_budget=25_000)
    assert unbounded.completeness.truncated is False
    assert len(unbounded.nodes) == total
    assert unbounded.stats()["total_nodes_source"] == total

    bounded = store.load_graph(tenant_id="default", scan_id="estate-test", node_budget=1_000)
    assert len(bounded.nodes) == 1_000
    assert bounded.completeness.truncated is True
    assert bounded.completeness.reason == "node_budget"
    assert bounded.completeness.total_nodes == total
    # The two numbers a reader reconciles agree, and neither reports the page.
    assert bounded.stats()["total_nodes_source"] == total
    assert bounded.stats()["total_nodes"] == 1_000
    assert bounded.to_dict()["completeness"] != unbounded.to_dict()["completeness"]


def test_projection_is_deterministic(estate, estate_findings) -> None:
    """A demo that shifts between runs cannot be screenshotted or diffed."""
    correlations = build_estate_correlations(estate)
    shapes = []
    for _ in range(2):
        graph = UnifiedGraph(scan_id="estate-test", tenant_id="default")
        project_estate_into_graph(graph, estate, findings=estate_findings, correlations=correlations)
        shapes.append(
            (
                sorted(graph.nodes),
                sorted((e.source, e.target, e.relationship.value) for e in graph.edges),
            )
        )
    assert shapes[0] == shapes[1]


def test_projected_node_attributes_are_json_values_not_python_objects(projected) -> None:
    """Every projected attribute must survive ``json.dumps`` untouched.

    The graph store persists attributes with ``json.dumps(..., default=str)``
    (``agent_bom/db/graph_store.py``), so a non-JSON value is not rejected — it
    is silently frozen into the snapshot as its Python ``repr`` and served from
    the API as a string. The graph node drawer then renders
    ``Remediation(fix=RemediationFix(summary=...`` as the remediation text on
    the surface a prospect clicks. Assert on the value, not on the encoder's
    willingness to coerce it.
    """
    import json

    graph, _ = projected
    offenders: list[tuple[str, str, str]] = []
    for node in graph.nodes.values():
        for key, value in node.attributes.items():
            try:
                json.dumps(value)
            except TypeError:
                offenders.append((node.id, key, type(value).__name__))
    assert not offenders, f"{len(offenders)} attribute(s) are not JSON values: {offenders[:3]}"


def test_projected_finding_nodes_carry_readable_remediation_text(projected, estate_findings) -> None:
    """``recommendation`` is prose the UI prints, so it must read as prose.

    ``ui/lib/unified-graph-flow.ts`` uses ``recommendation`` as a
    misconfiguration node's description, and ``graph/builder.py`` supplies a
    plain string there for live cloud scans. The estate projection must speak
    the same vocabulary rather than handing the same key a structured object.
    """
    graph, _ = projected
    finding_nodes = [
        node for node in graph.nodes.values() if node.entity_type is EntityType.MISCONFIGURATION and node.attributes.get("estate_id")
    ]
    assert len(finding_nodes) == len(estate_findings)
    for node in finding_nodes:
        recommendation = node.attributes.get("recommendation")
        assert isinstance(recommendation, str), (node.id, type(recommendation).__name__)
        assert recommendation, f"{node.id} lost its remediation text"
        assert not recommendation.startswith("Remediation("), f"{node.id} renders a Python repr as its remediation: {recommendation[:80]!r}"
