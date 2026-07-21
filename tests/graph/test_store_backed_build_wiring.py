"""Wire the graph producer through a store-backed container (#4055/#4075 PR-4).

``build_unified_graph_from_report`` gains an opt-in ``container=`` seam: the
persist path passes a per-build :class:`StoreBackedUnifiedGraph` on a throwaway
SQLite workspace so Phase-A emission and every Phase-B overlay run against the
store instead of a resident in-RAM graph. This proves the wiring's acceptance
bar:

* **byte-identical** — building the *same* report into a store-backed container
  yields a ``to_dict()`` byte-identical to the in-RAM producer (self-scan fixture
  + constructed report), so the opt-in changes nothing but where nodes live;
* **overlays run unchanged under eviction** — the two overlays that mutate a
  *held* node subset across passes (cnapp exposure, effective-permissions admin
  equivalence) stay byte-identical when the store's LRU is far smaller than the
  node set, i.e. the held objects are evicted mid-build (the real test of the
  #4306 interface-identity audit once the overlays actually run against the
  store);
* **producer peak is bounded** — the store-backed build's peak Python heap is a
  small, non-eroding fraction of the in-RAM producer's as the graph scales,
  because the whole-node dict + adjacency/reverse-adjacency + dedup indexes no
  longer live in RAM;
* **default-off is unchanged** — with no container the in-RAM path is used and
  the output is identical.
"""

from __future__ import annotations

import json
import tracemalloc
from pathlib import Path

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.effective_permissions import apply_effective_permissions
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.store_backed import StoreBackedUnifiedGraph, open_store_backed_unified_graph
from agent_bom.graph.types import EntityType, RelationshipType

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
_FIXED_CREATED_AT = "2026-07-20T00:00:00Z"


def _dumps(graph: UnifiedGraph) -> str:
    return json.dumps(graph.to_dict(), default=str, sort_keys=False)


def _sqlite_store(**kwargs) -> StoreBackedUnifiedGraph:
    kwargs.setdefault("backend", "sqlite")
    kwargs.setdefault("created_at", _FIXED_CREATED_AT)
    return open_store_backed_unified_graph(**kwargs)


# ── Constructed report that exercises Phase-A + cloud/vuln overlays ───────────


def _constructed_report() -> dict:
    return {
        "scan_id": "constructed",
        "scan_sources": ["mcp-scan"],
        "agents": [
            {
                "name": "planner",
                "type": "claude",
                "source": "local",
                "mcp_servers": [
                    {
                        "name": "files",
                        "packages": [
                            {
                                "name": "requests",
                                "version": "2.0.0",
                                "ecosystem": "pypi",
                                "vulnerabilities": [{"id": "CVE-1", "severity": "critical"}],
                            }
                        ],
                        "tools": [{"name": "read_file"}],
                    }
                ],
            }
        ],
        "blast_radius": [],
    }


def _report_cases() -> list[tuple[str, dict]]:
    self_scan = json.loads((_FIXTURES / "agent_bom_self_scan_inventory.json").read_text())
    return [("self_scan_fixture", self_scan), ("constructed_report", _constructed_report())]


# ── Byte-identical: builder into store-backed vs in-RAM container ─────────────


@pytest.mark.parametrize("case", _report_cases(), ids=lambda c: c[0])
def test_builder_into_store_backed_is_byte_identical(case: tuple[str, dict], monkeypatch: pytest.MonkeyPatch) -> None:
    # Freeze default timestamps so overlay-minted nodes/edges are identical across
    # the two independent builds (clock drift here is a test artifact, not a divergence).
    monkeypatch.setattr("agent_bom.graph.node._now_iso", lambda: _FIXED_CREATED_AT)
    monkeypatch.setattr("agent_bom.graph.edge._now_iso", lambda: _FIXED_CREATED_AT, raising=False)
    _name, report = case
    sid = report.get("scan_id", "s")

    in_ram = UnifiedGraph(scan_id=sid, tenant_id="t1", created_at=_FIXED_CREATED_AT)
    built_ram = build_unified_graph_from_report(report, scan_id=sid, tenant_id="t1", container=in_ram)

    store = _sqlite_store(tenant_id="t1", scan_id=sid)
    try:
        built_store = build_unified_graph_from_report(report, scan_id=sid, tenant_id="t1", container=store)
        assert built_store is store
        assert len(built_ram.nodes) > 0
        assert _dumps(built_store) == _dumps(built_ram), "store-backed build diverged from the in-RAM producer"
    finally:
        store.close()


# ── Overlays run unchanged when the held node subset is evicted mid-build ─────


def _make_cnapp_estate(g: UnifiedGraph, *, resources: int, fillers: int) -> None:
    """Exposed + vulnerable cloud resources (mutated by cnapp) followed by filler
    nodes, so on a small-capacity store the resources are evicted before cnapp's
    mutation pass — the exact hold-then-mutate-later pattern the store must serve.
    """
    for i in range(resources):
        rid = f"cloud:bucket-{i}"
        g.add_node(
            UnifiedNode(
                id=rid,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=f"public prod-data S3 bucket {i}",
                attributes={"resource_type": "s3"},
                first_seen=_FIXED_CREATED_AT,
                last_seen=_FIXED_CREATED_AT,
            )
        )
        vid = f"vuln:CVE-{i}"
        g.add_node(
            UnifiedNode(
                id=vid,
                entity_type=EntityType.VULNERABILITY,
                label=vid,
                severity="critical",
                first_seen=_FIXED_CREATED_AT,
                last_seen=_FIXED_CREATED_AT,
            )
        )
        g.add_edge(UnifiedEdge(source=rid, target=vid, relationship=RelationshipType.VULNERABLE_TO))
    # Filler nodes inserted AFTER the resources push them out of a small LRU.
    for j in range(fillers):
        g.add_node(
            UnifiedNode(
                id=f"pkg:{j}",
                entity_type=EntityType.PACKAGE,
                label=f"pkg-{j}",
                first_seen=_FIXED_CREATED_AT,
                last_seen=_FIXED_CREATED_AT,
            )
        )


def test_cnapp_overlay_store_safe_under_eviction(monkeypatch: pytest.MonkeyPatch) -> None:
    # cnapp mints DATA_STORE companion nodes; freeze their default timestamps so the
    # two independent overlay runs are comparable (drift here is a test artifact).
    monkeypatch.setattr("agent_bom.graph.node._now_iso", lambda: _FIXED_CREATED_AT)
    monkeypatch.setattr("agent_bom.graph.edge._now_iso", lambda: _FIXED_CREATED_AT, raising=False)
    ram = UnifiedGraph(scan_id="s", tenant_id="t1", created_at=_FIXED_CREATED_AT)
    _make_cnapp_estate(ram, resources=30, fillers=60)
    ram_stats = apply_cnapp_overlay(ram)

    # capacity(4) << 120 nodes: the held cloud_resources are evicted from the LRU
    # during the filter scan, before cnapp mutates them.
    store = _sqlite_store(tenant_id="t1", scan_id="s", capacity=4)
    try:
        _make_cnapp_estate(store, resources=30, fillers=60)
        store_stats = apply_cnapp_overlay(store)
        assert store_stats == ram_stats
        assert ram_stats["exposed_nodes"] == 30 and ram_stats["toxic_combinations"] == 30
        assert _dumps(store) == _dumps(ram), "cnapp exposure/toxic mutations lost on eviction"
    finally:
        store.close()


def _make_iam_estate(g: UnifiedGraph, *, principals: int, fillers: int) -> None:
    """Roles with an AdministratorAccess policy (cnapp-independent) so
    effective-permissions flags admin-equivalence on a held principal subset."""
    for i in range(principals):
        pid = f"role:admin-{i}"
        g.add_node(
            UnifiedNode(
                id=pid,
                entity_type=EntityType.ROLE,
                label=f"AdministratorAccess role {i}",
                first_seen=_FIXED_CREATED_AT,
                last_seen=_FIXED_CREATED_AT,
            )
        )
    for j in range(fillers):
        g.add_node(
            UnifiedNode(
                id=f"pkg:{j}",
                entity_type=EntityType.PACKAGE,
                label=f"pkg-{j}",
                first_seen=_FIXED_CREATED_AT,
                last_seen=_FIXED_CREATED_AT,
            )
        )


def test_effective_permissions_store_safe_under_eviction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent_bom.graph.node._now_iso", lambda: _FIXED_CREATED_AT)
    monkeypatch.setattr("agent_bom.graph.edge._now_iso", lambda: _FIXED_CREATED_AT, raising=False)
    ram = UnifiedGraph(scan_id="s", tenant_id="t1", created_at=_FIXED_CREATED_AT)
    _make_iam_estate(ram, principals=25, fillers=60)
    ram_stats = apply_effective_permissions(ram)

    store = _sqlite_store(tenant_id="t1", scan_id="s", capacity=4)
    try:
        _make_iam_estate(store, principals=25, fillers=60)
        store_stats = apply_effective_permissions(store)
        assert store_stats == ram_stats
        # Every role is admin-equivalent via the name heuristic — the held-subset write.
        assert all(ram.nodes[f"role:admin-{i}"].attributes.get("admin_equivalent") is True for i in range(25))
        assert _dumps(store) == _dumps(ram), "admin-equivalence mutation lost on eviction"
    finally:
        store.close()


# ── Producer peak is a bounded fraction of the in-RAM build ───────────────────


def _scaled_report(agents: int) -> dict:
    return {
        "scan_id": "scale",
        "scan_sources": ["mcp-scan"],
        "agents": [
            {
                "name": f"agent-{i}",
                "type": "claude",
                "source": "local",
                "mcp_servers": [
                    {
                        "name": f"srv-{i}",
                        "packages": [
                            {
                                "name": f"pkg-{i}",
                                "version": "1.0.0",
                                "ecosystem": "pypi",
                                "vulnerabilities": [{"id": f"CVE-{i}-{k}", "severity": "high", "cvss_score": 7.5} for k in range(2)],
                            }
                        ],
                        "tools": [{"name": f"tool-{i}"}],
                    }
                ],
            }
            for i in range(agents)
        ],
        "blast_radius": [],
    }


def _builder_peak(report: dict, *, store_backed: bool) -> tuple[int, int]:
    tracemalloc.start()
    if store_backed:
        graph: UnifiedGraph = open_store_backed_unified_graph(
            backend="sqlite", tenant_id="t1", scan_id="scale", created_at=_FIXED_CREATED_AT, capacity=256
        )
    else:
        graph = UnifiedGraph(scan_id="scale", tenant_id="t1", created_at=_FIXED_CREATED_AT)
    try:
        build_unified_graph_from_report(report, scan_id="scale", tenant_id="t1", container=graph)
        node_count = len(graph.nodes)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        close = getattr(graph, "close", None)
        if callable(close):
            close()
    tracemalloc.stop()
    return peak, node_count


def test_store_backed_producer_peak_advantage_widens_with_scale() -> None:
    """The store-backed producer removes the dominant resident structures — the
    whole-node dict + adjacency / reverse-adjacency + dedup indexes — so its peak
    per node is well under the in-RAM producer's AND the gap *widens* as the graph
    grows (the in-RAM producer grows strictly faster).

    Honesty note: this is a large, measured reduction (~2.5-3x lower peak,
    widening), not a strict sub-linear bound. A residual O(N) term survives in the
    store-backed build — Phase-A's id-bookkeeping maps + a few overlays' bounded
    node subsets stay resident — so the ratio converges to a constant fraction
    rather than to zero. Removing that residual (streaming Phase-A / two-pass
    overlays) is the remaining #4075 work; this guard pins the realized reduction.
    """
    small, large = _scaled_report(1200), _scaled_report(4800)

    # Warm-up: resolve the builder's lazy overlay imports + first-use caches so
    # those one-time allocations are not charged to the measured runs.
    _builder_peak(_scaled_report(50), store_backed=True)
    _builder_peak(_scaled_report(50), store_backed=False)

    store_small, n_small = _builder_peak(small, store_backed=True)
    ram_small, n_small_ram = _builder_peak(small, store_backed=False)
    store_large, n_large = _builder_peak(large, store_backed=True)
    ram_large, n_large_ram = _builder_peak(large, store_backed=False)

    assert n_small == n_small_ram and n_large == n_large_ram
    assert n_large > n_small * 3  # the graph really scaled ~4x

    # The in-RAM producer's peak scales ~linearly with node count (flat per-node
    # cost) — that is the O(N) wall the store-backed build cuts into.
    ram_per_node_small = ram_small / n_small
    ram_per_node_large = ram_large / n_large
    assert abs(ram_per_node_large - ram_per_node_small) < ram_per_node_small * 0.25

    ratio_small = store_small / ram_small
    ratio_large = store_large / ram_large

    assert ratio_small < 0.65, f"store/in-RAM producer peak too high at ~{n_small} nodes: {ratio_small:.3f}"
    assert ratio_large < 0.48, f"store/in-RAM producer peak too high at ~{n_large} nodes: {ratio_large:.3f}"
    # Advantage widens with scale: the store-backed peak grows strictly slower than
    # the in-RAM producer, so the ratio drops as N grows 4x.
    assert ratio_large < ratio_small * 0.92, (
        f"store-backed producer advantage did not widen with scale: {ratio_small:.3f} -> {ratio_large:.3f}"
    )


# ── Default-off: no container -> in-RAM path, identical output ────────────────


def test_default_off_uses_in_ram_container() -> None:
    report = _constructed_report()
    default = build_unified_graph_from_report(report, scan_id="c", tenant_id="t1")
    assert type(default) is UnifiedGraph
    assert not isinstance(default, StoreBackedUnifiedGraph)

    explicit = UnifiedGraph(scan_id="c", tenant_id="t1", created_at=default.created_at)
    built = build_unified_graph_from_report(report, scan_id="c", tenant_id="t1", container=explicit)
    assert _dumps(default) == _dumps(built)
