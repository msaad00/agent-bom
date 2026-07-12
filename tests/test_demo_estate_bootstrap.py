from __future__ import annotations

import os
from collections import Counter

import pytest
from fastapi import HTTPException
from starlette.testclient import TestClient

from agent_bom.demo_estate.showcase_graph import SHOWCASE_BASELINE_SCAN_ID

ADMIN = {"X-Agent-Bom-Role": "admin"}


@pytest.fixture()
def demo_estate_client(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "demo-estate.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "demo-graph.db"))

    from agent_bom.api import server as api_server
    from agent_bom.api import stores as api_stores

    api_server._runtime_api_key_seeded = False
    api_server._shutting_down = False
    original_job_store = api_stores._store
    original_graph_store = api_stores._graph_store
    api_stores._store = None
    api_stores._graph_store = None

    try:
        with TestClient(api_server.app) as client:
            yield client
    finally:
        api_stores._store = original_job_store
        api_stores._graph_store = original_graph_store
        # The proxy alert/metric ring buffers and the firewall decision store are
        # process-global; the demo bootstrap seeds them, so clear them here to
        # keep the seeded gateway feed from leaking into later tests.
        from agent_bom.api.routes.proxy import _reset_proxy_runtime_for_tests

        _reset_proxy_runtime_for_tests()
        api_stores._get_firewall_decision_store().reset()


def _demo_report(client: TestClient) -> dict:
    jobs = (
        client.get("/v1/jobs", headers=ADMIN, params={"include_details": "true"}).json().get("jobs")
        or []
    )
    assert jobs, "expected at least one demo job after bootstrap"
    detail = client.get(f"/v1/scan/{jobs[0]['job_id']}", headers=ADMIN).json()
    return detail.get("result") or {}


def test_demo_estate_bootstrap_seeds_jobs_and_graph(demo_estate_client: TestClient) -> None:
    jobs_payload = demo_estate_client.get(
        "/v1/jobs",
        headers={"X-Agent-Bom-Role": "admin"},
        params={"include_details": "true"},
    ).json()
    jobs = jobs_payload.get("jobs") or []
    assert jobs, "expected at least one demo job after bootstrap"
    job_id = jobs[0]["job_id"]
    detail = demo_estate_client.get(f"/v1/scan/{job_id}", headers={"X-Agent-Bom-Role": "admin"}).json()
    sources = (detail.get("result") or {}).get("scan_sources", [])
    assert any("demo" in str(src).lower() for src in sources)

    graph = demo_estate_client.get("/v1/graph", headers={"X-Agent-Bom-Role": "viewer"})
    assert graph.status_code == 200, graph.text
    payload = graph.json()
    node_count = len(payload.get("nodes") or [])
    assert node_count > 0


def test_demo_estate_graph_is_a_rich_multi_agent_estate(demo_estate_client: TestClient) -> None:
    payload = demo_estate_client.get("/v1/graph", headers=ADMIN).json()
    nodes = payload.get("nodes") or []
    by_type = Counter(n.get("entity_type") for n in nodes)

    # Several AI agents, many MCP servers, real packages + CVEs, credentials.
    assert by_type["agent"] >= 5, by_type
    assert by_type["server"] >= 10, by_type
    assert by_type["package"] >= 10, by_type
    assert by_type["vulnerability"] >= 10, by_type
    assert by_type["credential"] >= 5, by_type
    assert by_type["tool"] >= 15, by_type

    labels = {n.get("label") for n in nodes}
    # Realistic, distinct agents render.
    assert {"Cursor IDE Agent", "LangChain Service Agent", "Support Copilot", "Data Pipeline Agent"} <= labels

    # Malicious/typosquat package differentiator.
    malicious = [n for n in nodes if n.get("attributes", {}).get("is_malicious")]
    assert malicious, "expected a malicious/typosquat package node"
    assert any("reqeusts" in (n.get("label") or "") for n in malicious)

    # KEV vulnerability lights up.
    kev = [n for n in nodes if n.get("attributes", {}).get("is_kev")]
    assert any("CVE-2023-4863" in (n.get("label") or "") for n in kev), "expected a KEV CVE node"


def test_demo_estate_headline_blast_radius_chain(demo_estate_client: TestClient) -> None:
    """agent -> MCP server -> vulnerable package -> critical CVE -> reachable
    credential + reachable run_shell tool -> potential RCE renders in the graph."""
    payload = demo_estate_client.get("/v1/graph", headers=ADMIN).json()
    node_ids = {n.get("id") for n in payload.get("nodes") or []}
    edges = payload.get("edges") or []
    edge_pairs = {(e.get("source"), e.get("target")) for e in edges}

    # Chain nodes exist.
    for nid in (
        "agent:cursor",
        "server:shell-runner-server",
        "pkg:pyyaml@5.3",
        "vuln:CVE-2020-14343",
        "cred:aws-secret",
        "tool:shell-runner-server:run_shell",
    ):
        assert nid in node_ids, f"missing chain node {nid}"

    assert ("agent:cursor", "server:shell-runner-server") in edge_pairs
    assert ("server:shell-runner-server", "pkg:pyyaml@5.3") in edge_pairs
    assert ("pkg:pyyaml@5.3", "vuln:CVE-2020-14343") in edge_pairs
    assert ("server:shell-runner-server", "cred:aws-secret") in edge_pairs
    # The critical CVE reaches both the credential and the run_shell tool (RCE).
    assert ("vuln:CVE-2020-14343", "cred:aws-secret") in edge_pairs
    assert ("vuln:CVE-2020-14343", "tool:shell-runner-server:run_shell") in edge_pairs


def test_demo_estate_findings_include_critical_and_kev(demo_estate_client: TestClient) -> None:
    result = _demo_report(demo_estate_client)
    summary = result.get("summary") or {}
    assert summary.get("total_agents") == 5
    assert summary.get("total_mcp_servers") == 10
    assert (summary.get("critical_findings") or 0) >= 2, summary

    findings = result.get("findings") or []
    assert len(findings) >= 12, f"expected a dense findings list, got {len(findings)}"

    # KEV differentiator surfaces in the blast radius (Pillow/libwebp).
    blast = result.get("blast_radius") or []
    kev = [b for b in blast if b.get("is_kev") or b.get("cisa_kev")]
    assert any(b.get("vulnerability_id") == "CVE-2023-4863" for b in kev), "expected KEV CVE in blast radius"


def test_demo_estate_cis_posture_spans_aws_gcp_azure(demo_estate_client: TestClient) -> None:
    result = _demo_report(demo_estate_client)
    # Curated multi-cloud CIS posture is attached to the demo scan result, which
    # is exactly what the CIS/compliance surfaces read (build_cis_benchmark_check_rows).
    seen_clouds: set[str] = set()
    for key, cloud in (
        ("cis_benchmark", "aws"),
        ("gcp_cis_benchmark", "gcp"),
        ("azure_cis_benchmark", "azure"),
    ):
        checks = (result.get(key) or {}).get("checks") or []
        assert checks, f"expected CIS checks for {key}"
        statuses = {c.get("status") for c in checks}
        # A believable spread — neither empty nor all-passing.
        assert "pass" in statuses and "fail" in statuses, f"{key} needs a pass/fail spread: {statuses}"
        seen_clouds.add(cloud)
    assert seen_clouds == {"aws", "gcp", "azure"}

    # The rows normalize through the same contract the /v1/cis/checks route uses.
    from agent_bom.analytics_contract import build_cis_benchmark_check_rows

    rows = build_cis_benchmark_check_rows(result, "showcase")
    clouds = Counter(r["cloud"] for r in rows)
    assert {"aws", "gcp", "azure"} <= set(clouds), clouds
    statuses = Counter(r["status"] for r in rows)
    assert statuses["pass"] > 0 and statuses["fail"] > 0, statuses


def test_demo_estate_gateway_feed_shows_the_ai_firewall(demo_estate_client: TestClient) -> None:
    """The gateway live feed renders authorized / blocked / shadow / redacted
    tool-call events on the demo — the AI-firewall differentiator."""
    feed = demo_estate_client.get("/v1/gateway/feed")
    assert feed.status_code == 200, feed.text
    payload = feed.json()
    events = payload.get("events") or []
    assert len(events) >= 12, f"expected a dense gateway feed, got {len(events)}"

    by_action = Counter(e.get("action_type") for e in events)
    # A believable mix mirroring a real AI-firewall feed.
    assert by_action["tool_call_authorized"] >= 5, by_action
    assert by_action["tool_call_blocked"] >= 5, by_action
    assert by_action["data_filter_applied"] >= 2, by_action

    # Shadow / undeclared-agent blocks are labeled as such.
    shadow = [e for e in events if e.get("shadow")]
    assert len(shadow) >= 2, "expected shadow/undeclared-agent blocks in the feed"
    assert any("shadow" in (e.get("agent") or "").lower() for e in shadow)

    # Attribution uses the showcase graph's real agent names.
    agents = {e.get("agent") for e in events}
    assert {"Cursor IDE Agent", "Claude Desktop Agent", "Data Pipeline Agent"} & agents

    # Feed is time-ordered newest-first and redaction-safe (metadata only).
    ts_values = [e.get("ts") for e in events]
    assert ts_values == sorted(ts_values, reverse=True)
    for e in events:
        assert "arguments" not in e and "response" not in e


def test_demo_estate_gateway_feed_kpis_populated(demo_estate_client: TestClient) -> None:
    kpis = demo_estate_client.get("/v1/gateway/feed/kpis").json()
    assert kpis.get("calls_today", 0) >= 12, kpis
    assert kpis.get("blocked_today", 0) >= 5, kpis
    assert kpis.get("shadow_ai_blocked", 0) >= 2, kpis
    assert kpis.get("data_filters_applied", 0) >= 2, kpis
    assert kpis.get("uptime_seconds", 0) > 0, kpis


def test_demo_estate_runtime_production_index_has_traffic(demo_estate_client: TestClient) -> None:
    idx = demo_estate_client.get("/v1/runtime/production-index", headers=ADMIN).json()
    assert idx.get("status") == "ok", idx
    traffic = idx.get("traffic") or {}
    assert traffic.get("total_tool_calls", 0) > 100, traffic
    assert traffic.get("blocked_tool_calls", 0) > 0, traffic
    assert traffic.get("uptime_seconds", 0) > 0, traffic
    trace = (idx.get("authorization_trace") or {}).get("recent") or []
    assert trace, "expected recent authorization-trace events"


def test_demo_estate_firewall_stats_populated(demo_estate_client: TestClient) -> None:
    stats = demo_estate_client.get("/v1/firewall/stats").json()
    assert stats.get("total_decisions", 0) >= 6, stats
    assert stats.get("deny", 0) >= 2, stats
    assert stats.get("allow", 0) >= 2, stats
    assert stats.get("recent"), "expected recent firewall decisions"


def test_demo_estate_gateway_feed_is_idempotent(demo_estate_client: TestClient) -> None:
    first = len(demo_estate_client.get("/v1/gateway/feed").json().get("events") or [])
    from agent_bom.demo_estate.showcase_gateway import seed_showcase_gateway_events

    again = seed_showcase_gateway_events()
    assert again.get("seeded") is False and again.get("reason") == "already_present"
    second = len(demo_estate_client.get("/v1/gateway/feed").json().get("events") or [])
    assert second == first


def test_demo_estate_graph_snapshots_support_drift_lens(demo_estate_client: TestClient) -> None:
    """Baseline + current snapshots let the shipped drift lens diff against a prior estate."""
    snapshots = demo_estate_client.get("/v1/graph/snapshots", headers=ADMIN).json()
    scan_ids = {row.get("scan_id") for row in snapshots}
    assert SHOWCASE_BASELINE_SCAN_ID in scan_ids
    assert "showcase" in scan_ids
    assert len(snapshots) >= 2

    diff = demo_estate_client.get(
        "/v1/graph/diff",
        headers=ADMIN,
        params={"old": SHOWCASE_BASELINE_SCAN_ID, "new": "showcase"},
    )
    assert diff.status_code == 200, diff.text
    body = diff.json()
    index = body.get("change_kind_index") or {}
    node_kinds = index.get("nodes") or {}
    assert node_kinds, "expected node drift between baseline and current showcase snapshots"
    kinds = set(node_kinds.values())
    assert kinds & {"new", "removed", "changed"}, kinds

    deltas = body.get("attribute_deltas") or {}
    pii_deltas = deltas.get("cloud:pii-bucket") or []
    summaries = {row.get("summary") for row in pii_deltas}
    assert "Public exposure opened" in summaries or "Encryption at rest disabled" in summaries, pii_deltas

    assert body.get("nodes_added"), "expected at least one new node in the showcase drift story"
    assert body.get("nodes_removed"), "expected at least one removed node in the showcase drift story"
    assert body.get("nodes_changed"), "expected at least one changed node in the showcase drift story"


def test_demo_estate_showcase_cloud_hierarchy_and_exposure(demo_estate_client: TestClient) -> None:
    """Showcase graph carries org→account containment and a bastion→PII exposure edge."""
    payload = demo_estate_client.get("/v1/graph", headers=ADMIN).json()
    node_ids = {node.get("id") for node in payload.get("nodes") or []}
    assert "org:corp" in node_ids
    assert "account:aws:123456789012" in node_ids

    edges = payload.get("edges") or []
    contains = {
        (row.get("source"), row.get("target"))
        for row in edges
        if row.get("relationship") == "contains"
    }
    assert ("org:corp", "account:aws:123456789012") in contains
    assert ("account:aws:123456789012", "cloud:pii-bucket") in contains
    assert ("account:aws:123456789012", "cloud:bastion") in contains

    exposed = [
        row
        for row in edges
        if row.get("relationship") == "exposed_to"
        and row.get("source") == "cloud:bastion"
        and row.get("target") == "cloud:pii-bucket"
    ]
    assert exposed, "expected bastion→PII EXPOSED_TO edge in showcase snapshot"


def test_demo_estate_graph_tags_runtime_evidence_tiers(demo_estate_client: TestClient) -> None:
    payload = demo_estate_client.get("/v1/graph", headers=ADMIN).json()
    attrs_by_id = {
        node.get("id"): (node.get("attributes") or {}) for node in payload.get("nodes") or []
    }
    assert attrs_by_id.get("call:0", {}).get("evidence_tier") == "runtime_observed"
    assert (
        attrs_by_id.get("tool:shell-runner-server:run_shell", {}).get("evidence_tier")
        == "runtime_blocked"
    )


def test_demo_estate_catalog_seeds_connections_sources_and_spend(demo_estate_client: TestClient) -> None:
    """Connections, Sources, and AI Spend surfaces are populated on first demo boot."""
    from agent_bom.api.connection_store import get_connection_store
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    connections = get_connection_store().list_for_tenant(SHOWCASE_TENANT)
    assert len(connections) >= 3
    assert any(record.id.startswith("demo-conn-") for record in connections)
    demo_connection = next(record for record in connections if record.id.startswith("demo-conn-"))
    assert demo_connection.external_id_encrypted == ""
    from agent_bom.api.routes.cloud_connections import _reject_showcase_connection

    with pytest.raises(HTTPException) as exc_info:
        _reject_showcase_connection(demo_connection)
    assert exc_info.value.status_code == 409
    assert "synthetic" in str(exc_info.value.detail).lower()

    sources = demo_estate_client.get("/v1/sources").json()
    source_rows = sources.get("sources") or []
    assert len(source_rows) >= 2
    assert any(row.get("source_id", "").startswith("demo-src-") for row in source_rows)

    counts = demo_estate_client.get("/v1/posture/counts").json()
    services = counts.get("services") or {}
    assert services.get("cloud_accounts", {}).get("state") == "live"
    assert services.get("cloud_accounts", {}).get("count", 0) >= 3
    assert services.get("data_sources", {}).get("state") == "live"
    assert services.get("data_sources", {}).get("count", 0) >= 2
    assert services.get("ai_spend", {}).get("state") == "live"


def test_demo_estate_catalog_is_idempotent(demo_estate_client: TestClient) -> None:
    from agent_bom.demo_estate.showcase_catalog import seed_showcase_catalog_if_empty

    again = seed_showcase_catalog_if_empty()
    assert again.get("seeded") is False and again.get("reason") == "catalog_present"


def test_showcase_catalog_needs_no_ephemeral_key_and_is_tenant_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.api.connection_crypto import CONNECTIONS_KEY_ENV
    from agent_bom.api.connection_store import InMemoryConnectionStore
    from agent_bom.api.cost_store import InMemoryCostStore
    from agent_bom.api.source_store import InMemorySourceStore
    from agent_bom.demo_estate import showcase_catalog

    connection_store = InMemoryConnectionStore()
    source_store = InMemorySourceStore()
    cost_store = InMemoryCostStore()
    monkeypatch.delenv(CONNECTIONS_KEY_ENV, raising=False)
    monkeypatch.setattr(showcase_catalog, "get_connection_store", lambda: connection_store)
    monkeypatch.setattr(showcase_catalog, "_get_source_store", lambda: source_store)
    monkeypatch.setattr(showcase_catalog, "get_cost_store", lambda: cost_store)

    first = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="tenant-a")
    second = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="tenant-a")
    other = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="tenant-b")

    assert first == {"seeded": True, "connections": 3, "sources": 2, "cost_samples": 1}
    assert second.get("seeded") is False and second.get("reason") == "catalog_present"
    assert other.get("seeded") is True
    assert CONNECTIONS_KEY_ENV not in os.environ
    tenant_a_connections = connection_store.list_for_tenant("tenant-a")
    tenant_b_connections = connection_store.list_for_tenant("tenant-b")
    assert len(tenant_a_connections) == len(tenant_b_connections) == 3
    assert {row.id for row in tenant_a_connections}.isdisjoint(
        {row.id for row in tenant_b_connections}
    )
    assert all(not row.external_id_encrypted for row in tenant_a_connections)
    assert len(source_store.list_all("tenant-a")) == 2
    assert len(source_store.list_all("tenant-b")) == 2
    assert len(cost_store.list_records("tenant-a")) == 1
    assert len(cost_store.list_records("tenant-b")) == 1


def test_showcase_catalog_retry_heals_partial_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.connection_store import InMemoryConnectionStore
    from agent_bom.api.cost_store import InMemoryCostStore
    from agent_bom.api.source_store import InMemorySourceStore
    from agent_bom.demo_estate import showcase_catalog

    connection_store = InMemoryConnectionStore()
    source_store = InMemorySourceStore()
    cost_store = InMemoryCostStore()
    original_put = source_store.put
    should_fail = True

    def flaky_put(source) -> None:
        nonlocal should_fail
        if should_fail:
            should_fail = False
            raise RuntimeError("injected source failure")
        original_put(source)

    monkeypatch.setattr(showcase_catalog, "get_connection_store", lambda: connection_store)
    monkeypatch.setattr(showcase_catalog, "_get_source_store", lambda: source_store)
    monkeypatch.setattr(showcase_catalog, "get_cost_store", lambda: cost_store)
    monkeypatch.setattr(source_store, "put", flaky_put)

    with pytest.raises(RuntimeError, match="injected source failure"):
        showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="retry-tenant")

    summary = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="retry-tenant")
    assert summary == {"seeded": True, "connections": 0, "sources": 2, "cost_samples": 1}
    assert len(connection_store.list_for_tenant("retry-tenant")) == 3
    assert len(source_store.list_all("retry-tenant")) == 2
    assert len(cost_store.list_records("retry-tenant")) == 1


def test_demo_estate_bootstrap_is_idempotent(demo_estate_client: TestClient) -> None:
    first = demo_estate_client.get("/v1/jobs", headers={"X-Agent-Bom-Role": "admin"}).json()
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

    second = maybe_bootstrap_demo_estate()
    assert second.get("reason") == "demo_jobs_present"
    again = demo_estate_client.get("/v1/jobs", headers={"X-Agent-Bom-Role": "admin"}).json()
    assert again.get("total") == first.get("total")


def test_demo_estate_exposure_paths_materialized(demo_estate_client: TestClient) -> None:
    """The materialized exposure-path queue (read by /v1/graph/exposure-paths) is
    non-empty and headlines the seeded hero chains."""
    payload = demo_estate_client.get(
        "/v1/graph/exposure-paths", headers=ADMIN, params={"limit": 10}
    ).json()
    assert payload.get("count", 0) >= 3, payload
    assert payload.get("total", 0) >= 3, payload

    findings = {f for p in payload.get("paths", []) for f in (p.get("findings") or [])}
    creds = {c for p in payload.get("paths", []) for c in (p.get("exposedCredentials") or [])}
    tools = {t for p in payload.get("paths", []) for t in (p.get("reachableTools") or [])}
    # The PyYAML RCE → run_shell → AWS-secret hero chain materializes.
    assert "CVE-2020-14343" in findings, findings
    assert "AWS_SECRET_ACCESS_KEY" in creds, creds
    assert "run_shell" in tools, tools


def test_demo_estate_nhi_governance_tells_a_story(demo_estate_client: TestClient) -> None:
    """NHI governance evaluates the seeded identities and surfaces at least one
    over-granted, one dormant/orphaned, and one clearly high/critical identity."""
    posture = demo_estate_client.get("/v1/graph/nhi/governance", headers=ADMIN).json()
    assert posture.get("evaluated", 0) >= 5, posture
    counts = posture.get("counts") or {}
    assert counts.get("over_granted", 0) >= 1, counts
    assert counts.get("dormant", 0) >= 1, counts
    assert counts.get("orphaned", 0) >= 1, counts
    bands = counts.get("by_risk_band") or {}
    assert (bands.get("critical", 0) + bands.get("high", 0)) >= 1, bands

    # A dormant + orphaned admin identity is the headline risk.
    worst = (posture.get("identities") or [])[0]
    assert worst.get("is_dormant") and worst.get("is_orphaned"), worst
    assert worst.get("risk_band") in {"high", "critical"}, worst


def test_demo_estate_overview_identity_tile_populated(demo_estate_client: TestClient) -> None:
    """The Overview NHI/Identity tile reads the live identity store, which the
    demo seed populates, so it is no longer 0/idle."""
    overview = demo_estate_client.get("/v1/overview").json()
    identity = overview["domains"]["identity"]
    assert identity["metric"] >= 5, identity
    assert identity["detail"]["managed_identities"] >= 5, identity
    assert identity["status"] != "idle", identity


def test_demo_estate_agents_fall_back_to_demo_inventory(
    demo_estate_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a hosted server local discovery is empty; the demo estate falls back to
    the curated inventory so /v1/agents + /v1/agents/mesh are non-empty and
    correlated with the graph agents."""
    import agent_bom.discovery as discovery_mod

    monkeypatch.setattr(discovery_mod, "discover_all", lambda: [])
    from agent_bom.api.routes.discovery import _clear_agents_response_cache_for_tests

    _clear_agents_response_cache_for_tests()

    agents = demo_estate_client.get("/v1/agents", headers=ADMIN).json()
    names = {a.get("name") for a in agents.get("agents", [])}
    assert agents.get("count", 0) >= 5, agents
    assert {"cursor", "langchain-service", "support-copilot"} <= names, names

    mesh = demo_estate_client.get("/v1/agents/mesh", headers=ADMIN).json()
    assert len(mesh.get("nodes") or []) >= 5, mesh


def test_demo_estate_agents_no_fallback_without_demo_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Env unset ⇒ live discovery only; the demo inventory is never injected."""
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    import agent_bom.discovery as discovery_mod
    from agent_bom.api.routes.discovery import _discover_agents_with_demo_fallback

    monkeypatch.setattr(discovery_mod, "discover_all", lambda: [])
    assert _discover_agents_with_demo_fallback() == []


def test_demo_estate_scan_findings_restored_after_restart(
    demo_estate_client: TestClient,
) -> None:
    """A restart resets the in-memory job store; demo mode must re-seed the scan
    so posture + findings are restored (the graph snapshot already persists)."""
    from agent_bom.api import stores as api_stores
    from agent_bom.demo_estate.bootstrap import (
        _tenant_has_demo_jobs,
        maybe_bootstrap_demo_estate,
    )
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    before = demo_estate_client.get("/v1/findings", headers=ADMIN, params={"limit": 3}).json()
    assert before.get("total", 0) > 0

    # Simulate a process restart: the in-memory job store is recreated empty
    # while the persisted graph snapshot survives.
    api_stores._store = None
    assert not _tenant_has_demo_jobs(api_stores._get_store(), SHOWCASE_TENANT)

    summary = maybe_bootstrap_demo_estate()
    assert summary.get("seeded") is True, summary

    after = demo_estate_client.get("/v1/findings", headers=ADMIN, params={"limit": 3}).json()
    assert after.get("total", 0) == before.get("total", 0), (before.get("total"), after.get("total"))
