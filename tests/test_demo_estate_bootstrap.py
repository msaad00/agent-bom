from __future__ import annotations

from collections import Counter

import pytest
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

    assert body.get("nodes_added"), "expected at least one new node in the showcase drift story"
    assert body.get("nodes_removed"), "expected at least one removed node in the showcase drift story"
    assert body.get("nodes_changed"), "expected at least one changed node in the showcase drift story"


def test_demo_estate_bootstrap_is_idempotent(demo_estate_client: TestClient) -> None:
    first = demo_estate_client.get("/v1/jobs", headers={"X-Agent-Bom-Role": "admin"}).json()
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

    second = maybe_bootstrap_demo_estate()
    assert second.get("reason") == "demo_jobs_present"
    again = demo_estate_client.get("/v1/jobs", headers={"X-Agent-Bom-Role": "admin"}).json()
    assert again.get("total") == first.get("total")
