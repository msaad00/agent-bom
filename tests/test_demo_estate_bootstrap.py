from __future__ import annotations

import os
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from starlette.testclient import TestClient

from agent_bom.demo_estate.showcase_graph import SHOWCASE_BASELINE_SCAN_ID

# The hosted-demo contract is anonymous viewer access.  Supplying an unattested
# role header is credential spoofing and must be rejected by the auth resolver.
VIEWER: dict[str, str] = {}


@pytest.fixture()
def demo_estate_client(monkeypatch: pytest.MonkeyPatch, tmp_path):
    from agent_bom.backpressure import _controller_for, reset_backpressure_for_tests

    # Model the stale process state that caused main CI's 429 regression. Keep
    # this proof inside the exported fixture so modules that import only
    # ``demo_estate_client`` do not lose one of its private dependencies.
    reset_backpressure_for_tests()
    controller = _controller_for("findings")
    controller.open_until_monotonic = time.monotonic() + 60
    controller.last_trigger_reason = "p99_latency_threshold"

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "demo-estate.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "demo-graph.db"))

    from agent_bom.api import compliance_hub_store as hub_store_mod
    from agent_bom.api import server as api_server
    from agent_bom.api import stores as api_stores
    from agent_bom.api.compliance_hub_store import set_compliance_hub_store
    from agent_bom.api.findings_count_cache import reset_findings_count_cache

    api_server._runtime_api_key_seeded = False
    api_server._shutting_down = False
    original_job_store = api_stores._store
    original_graph_store = api_stores._graph_store
    original_hub_store = hub_store_mod._HUB_STORE
    api_stores._store = None
    api_stores._graph_store = None
    set_compliance_hub_store(None)
    reset_findings_count_cache()
    # Each TestClient instance represents a fresh API process.  The adaptive
    # controllers are process-global, so reset them at that lifecycle boundary
    # instead of carrying latency/cooldown state across randomized test apps.
    reset_backpressure_for_tests()

    try:
        with TestClient(api_server.app) as client:
            yield client
    finally:
        api_stores._store = original_job_store
        api_stores._graph_store = original_graph_store
        set_compliance_hub_store(original_hub_store)
        reset_findings_count_cache()
        reset_backpressure_for_tests()
        # The proxy alert/metric ring buffers and the firewall decision store are
        # process-global; the demo bootstrap seeds them, so clear them here to
        # keep the seeded gateway feed from leaking into later tests.
        from agent_bom.api.routes.proxy import _reset_proxy_runtime_for_tests
        from agent_bom.demo_estate.bootstrap import reset_daily_evidence_day

        _reset_proxy_runtime_for_tests()
        api_stores._get_firewall_decision_store().reset()
        # The governance seed writes 5 blueprints and a fortnight of LLM spend
        # into two more process-global singletons. Leaving them populated made
        # test_graph_governance_overlay fail with `assert 6 == 1` — its overlay
        # call omits `blueprint_store`, so it read the demo's 5 blueprints plus
        # its own 1 identity. That is a real leak, not that test's bug, and with
        # pytest-randomly it only surfaces when the two land in this order.
        from agent_bom.api import blueprint_store as blueprint_store_mod
        from agent_bom.api import cost_store as cost_store_mod
        from agent_bom.api.campaign_store import set_campaign_store
        from agent_bom.api.skills_scan_store import set_skills_scan_store
        from agent_bom.cloud.side_scan_lifecycle import reset_side_scan_state_store

        blueprint_store_mod.set_blueprint_store(None)
        cost_store_mod._COST_STORE = None
        set_campaign_store(None)
        set_skills_scan_store(None)
        reset_side_scan_state_store()
        reset_daily_evidence_day()


def _demo_report(client: TestClient) -> dict:
    jobs = client.get("/v1/jobs", headers=VIEWER, params={"include_details": "true"}).json().get("jobs") or []
    assert jobs, "expected at least one demo job after bootstrap"
    detail = client.get(f"/v1/scan/{jobs[0]['job_id']}", headers=VIEWER).json()
    return detail.get("result") or {}


def test_demo_estate_bootstrap_seeds_jobs_and_graph(demo_estate_client: TestClient) -> None:
    jobs_payload = demo_estate_client.get(
        "/v1/jobs",
        headers=VIEWER,
        params={"include_details": "true"},
    ).json()
    jobs = jobs_payload.get("jobs") or []
    assert jobs, "expected at least one demo job after bootstrap"
    job_id = jobs[0]["job_id"]
    detail = demo_estate_client.get(f"/v1/scan/{job_id}", headers=VIEWER).json()
    sources = (detail.get("result") or {}).get("scan_sources", [])
    assert any("demo" in str(src).lower() for src in sources)

    graph = demo_estate_client.get("/v1/graph", headers=VIEWER)
    assert graph.status_code == 200, graph.text
    payload = graph.json()
    node_count = len(payload.get("nodes") or [])
    assert node_count > 0


def test_demo_estate_bootstrap_validates_versioned_enterprise_contract(
    demo_estate_client: TestClient,
) -> None:
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate
    from agent_bom.demo_estate.enterprise import ENTERPRISE_SCHEMA_VERSION

    summary = maybe_bootstrap_demo_estate()
    contract = summary.get("enterprise_contract") or {}

    assert contract["schema_version"] == ENTERPRISE_SCHEMA_VERSION
    # The demo now boots the narrative estate composed into a generated
    # population, so the id gains its suffix and the floors move from
    # "the story exists" to "the story sits inside an enterprise". The old
    # values (20 assets, 15 observations) passed against an estate too small
    # to demonstrate correlation at all.
    assert contract["estate_id"] == "northstar-health-ai-v1-composed"
    assert contract["assets"] >= 2000
    assert contract["observations"] >= 6000
    assert contract["snapshots"] == 3
    assert contract["partial_sources"] == ["gcp_audit"]
    assert len(contract["content_hash"]) == 64


def test_demo_estate_story_api_exposes_normalized_evidence_only(
    demo_estate_client: TestClient,
) -> None:
    response = demo_estate_client.get("/v1/demo-estate/story", headers=VIEWER)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["schema_version"] == "enterprise_demo_story.v1"
    assert payload["synthetic"] is True
    assert payload["fictional"] is True
    assert payload["graph_snapshot_id"] == "showcase"
    focused_graph = demo_estate_client.get(
        "/v1/graph",
        headers=VIEWER,
        params={"scan": payload["graph_snapshot_id"], "limit": 1},
    )
    assert focused_graph.status_code == 200, focused_graph.text
    focused_payload = focused_graph.json()
    assert focused_payload["scan_id"] == payload["graph_snapshot_id"]
    assert focused_payload["stats"]["total_nodes"] > 0
    assert focused_payload["stats"]["total_edges"] > 0
    assert payload["primary_correlation"]["outcome"] == "blocked"
    assert payload["summary"]["evidence_sources"] == 9
    assert "raw_payload" not in response.text


def test_demo_estate_graph_is_a_rich_multi_agent_estate(demo_estate_client: TestClient) -> None:
    # Reads the whole snapshot rather than the default page. Since the
    # enterprise estate is projected into this snapshot it holds ~2,900 nodes,
    # and the default page is 500 ordered by severity — which the estate's 439
    # posture findings now fill. The agents/servers/packages asserted here are
    # unrated inventory, so a default-page read would be testing the pager, not
    # the estate. ``test_demo_estate_default_graph_page_declares_its_truncation``
    # covers the bounded read.
    payload = _full_graph(demo_estate_client)
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
    credential + reachable run_shell tool -> potential RCE renders in the graph.

    Whole snapshot, not the default page: the hand-built chain is *extended* by
    the projected enterprise estate, never replaced, but its unrated inventory
    nodes no longer land in a 500-row severity-ranked page.
    """
    payload = _full_graph(demo_estate_client)
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


def test_demo_estate_hero_findings_carry_the_persisted_graph_path(demo_estate_client: TestClient) -> None:
    """The scan and graph surfaces must tell the same hero-path story."""
    result = _demo_report(demo_estate_client)
    blast = result.get("blast_radius") or []
    hero = [
        row
        for row in blast
        if row.get("vulnerability_id") == "CVE-2020-14343" and row.get("package_name") == "pyyaml" and row.get("package_version") == "5.3"
    ]

    assert len(hero) > 1, "the bundled inventory did not include estate-scoped pyyaml exposures"
    for row in hero:
        assert row.get("graph_reachable") is True
        assert row.get("graph_min_hop_distance") == 3
        assert "agent:cursor" in (row.get("graph_reachable_from_agents") or [])
        assert "cursor" in (row.get("affected_agents") or [])
        assert "shell-runner-server" in (row.get("affected_servers") or [])
        assert (row.get("risk_score") or 0) > 0

    listing = demo_estate_client.get(
        "/v1/findings",
        headers=VIEWER,
        params={"limit": 1000},
    ).json()
    public_hero = [row for row in listing.get("findings") or [] if (row.get("vulnerability_id") or row.get("cve_id")) == "CVE-2020-14343"]
    assert public_hero, "the persisted hero path did not reach the public findings route"
    graph_hero = [row for row in public_hero if row.get("graph_reachable") is True]
    assert graph_hero, [(row.get("id"), row.get("graph_reachable"), row.get("source"), row.get("asset")) for row in public_hero]
    assert all(
        row.get("package") == "pyyaml"
        or (row.get("asset") or {}).get("name") == "pyyaml"
        or (row.get("evidence") or {}).get("package_name") == "pyyaml"
        for row in graph_hero
    )
    assert all("cursor" in (row.get("affected_agents") or []) for row in graph_hero)
    assert all("shell-runner-server" in (row.get("affected_servers") or []) for row in graph_hero)


def test_demo_estate_graph_evidence_covers_a_meaningful_finding_share(demo_estate_client: TestClient) -> None:
    """The attack-path demo must cover more than a token handful of CVEs."""
    blast = _demo_report(demo_estate_client).get("blast_radius") or []
    evidenced = [row for row in blast if row.get("graph_reachable") is True]

    assert len(evidenced) >= 100, f"only {len(evidenced)} of {len(blast)} vulnerability rows carry persisted graph evidence"


def test_demo_estate_posture_findings_resolve_to_inventoried_assets(
    demo_estate_client: TestClient,
) -> None:
    """The estate's posture findings reach the public findings list, chain intact.

    Asserted on ``/v1/findings`` rather than the raw scan result on purpose:
    that route is the canonical list every consumer reads, and it applies
    ``safe_finding_response_payload`` — default-deny tier-A redaction. A chain
    that only holds before redaction is a chain no user ever sees, so the join
    keys the demo relies on must be ones the evidence policy already classifies
    as safe.
    """
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    inventoried = {asset.asset_id for asset in build_demo_estate(tenant_id=SHOWCASE_TENANT).assets}

    listing = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1000, "domain": "cspm"}).json()
    rows = [row for row in listing["findings"] if (row.get("evidence") or {}).get("resource_id", "") in inventoried]
    assert len(rows) >= 400, f"only {len(rows)} estate posture findings reached the findings list"

    for row in rows:
        evidence = row.get("evidence") or {}
        assert evidence["resource_id"] in inventoried, evidence["resource_id"]
        assert evidence.get("principal_id") or evidence.get("actor_id"), (
            f"{row.get('id')} lost its identity edge through redaction: {sorted(evidence)}"
        )
        # Every posture finding must say which check saw it — that is the join
        # key the rest of the product reads. A control id is required *exactly
        # when* the finding claims a framework: not every posture rule has a
        # CIS twin ("resource declared without an ownership tag" has none), and
        # a rule with no control must say so rather than borrow one. Requiring
        # a control on every row is what forced the IaC lane to assert CIS and
        # NIST coverage it could not support.
        assert evidence.get("check_id"), f"{row.get('id')} has no check identity: {sorted(evidence)}"
        claims_cis = any(str(tag).upper().startswith("CIS") for tag in (row.get("compliance_tags") or row.get("compliance") or []))
        if claims_cis:
            assert evidence.get("control_id"), f"{row.get('id')} claims CIS with no control_id behind it"
        assert evidence.get("resource_name") and evidence.get("resource_type")
        assert row.get("provider"), sorted(row)
        assert row.get("severity"), sorted(row)
    assert any((row.get("evidence") or {}).get("correlation_id") for row in rows), "no posture finding kept its correlated attack path"
    assert len({(row.get("evidence") or {}).get("resource_id") for row in rows}) > 200, (
        "the estate's findings all land on a handful of assets"
    )


def test_demo_estate_finding_counts_reconcile_across_tile_list_and_facet(
    demo_estate_client: TestClient,
) -> None:
    """One estate, one total — whatever surface is asked.

    The tile, the list header, and the severity facet histogram are three
    different code paths over the same evidence. Adding hundreds of posture
    findings is exactly the change that makes them drift apart, so pin them
    together on the seeded estate rather than trusting that they agree.
    """
    listing = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1, "include_facets": "true"}).json()
    total = listing["total"]
    assert total > 400, total

    severity_facet = (listing.get("facets") or {}).get("severity") or {}
    assert severity_facet, f"the findings list returned no severity facet: {list(listing.get('facets') or {})}"
    assert sum(int(v) for v in severity_facet.values()) == total, (
        f"severity facet sums to {sum(int(v) for v in severity_facet.values())} but the list reports {total}"
    )

    counts = demo_estate_client.get("/v1/posture/counts", headers=VIEWER).json()
    assert "unrated" in counts, counts
    assert sum(counts[band] for band in ("critical", "high", "medium", "low", "unrated")) == counts["total"], counts
    assert counts["unrated"] > 0, (
        "no unrated finding survives to the tiles, so an unevaluable control is indistinguishable from one that passed"
    )

    # The bounded page reports the unbounded total, never its own size.
    page = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 25}).json()
    assert len(page["findings"]) <= 25
    assert page["total"] == total > len(page["findings"]), (page["total"], len(page["findings"]))


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
    idx = demo_estate_client.get("/v1/runtime/production-index", headers=VIEWER).json()
    assert idx.get("status") == "ok", idx
    traffic = idx.get("traffic") or {}
    assert traffic.get("total_tool_calls", 0) > 100, traffic
    assert traffic.get("blocked_tool_calls", 0) > 0, traffic
    assert traffic.get("uptime_seconds", 0) > 0, traffic
    trace = (idx.get("authorization_trace") or {}).get("recent") or []
    assert trace, "expected recent authorization-trace events"


def test_demo_estate_firewall_stats_require_audit_permission(demo_estate_client: TestClient) -> None:
    response = demo_estate_client.get("/v1/firewall/stats")
    assert response.status_code == 403
    assert "audit_read" in response.json()["detail"]


def test_demo_estate_gateway_feed_is_idempotent(demo_estate_client: TestClient) -> None:
    first = len(demo_estate_client.get("/v1/gateway/feed").json().get("events") or [])
    from agent_bom.demo_estate.showcase_gateway import seed_showcase_gateway_events

    again = seed_showcase_gateway_events()
    assert again.get("seeded") is False and again.get("reason") == "already_present"
    second = len(demo_estate_client.get("/v1/gateway/feed").json().get("events") or [])
    assert second == first


def test_demo_estate_graph_snapshots_support_drift_lens(demo_estate_client: TestClient) -> None:
    """Baseline + current snapshots let the shipped drift lens diff against a prior estate."""
    snapshots = demo_estate_client.get("/v1/graph/snapshots", headers=VIEWER).json()
    scan_ids = {row.get("scan_id") for row in snapshots}
    assert SHOWCASE_BASELINE_SCAN_ID in scan_ids
    assert "showcase" in scan_ids
    assert len(snapshots) >= 2

    diff = demo_estate_client.get(
        "/v1/graph/diff",
        headers=VIEWER,
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


def test_demo_estate_exec_severity_counts_reconcile_across_surfaces(
    demo_estate_client: TestClient,
) -> None:
    """Exec-facing severity counts agree across surfaces on one estate (#3961).

    Regression for the exec-read honesty bug: ``/v1/posture/counts`` read the
    CVE-only ``blast_radius`` while ``/v1/overview`` read the unified findings
    spine, so a leader saw different critical/high on the same estate (2/10 vs
    3/12 on the demo estate). Both exec surfaces must now derive from the one
    reconciled source of truth. The graph snapshot ``risk_summary`` is a
    *different* metric (graph nodes at risk, per scan) and is explicitly tagged
    as such so it is never mistaken for the exec headline.
    """
    counts = demo_estate_client.get("/v1/posture/counts").json()
    overview = demo_estate_client.get("/v1/overview").json()
    headline = overview["headline"]

    # 1. The exec headline and the nav-badge counts are the same number.
    assert counts["critical"] == headline["critical"], (counts, headline)
    assert counts["high"] == headline["high"], (counts, headline)
    assert counts["kev"] == headline["kev"], (counts, headline)
    # The demo estate carries the non-CVE critical/high that blast_radius missed.
    assert counts["critical"] >= 3 and counts["high"] >= 12, counts

    # 2. Honest histogram: unrated is an explicit bucket and the buckets sum to
    #    total — no severity is silently dropped.
    assert "unrated" in counts, counts
    bucketed = sum(counts[band] for band in ("critical", "high", "medium", "low", "unrated"))
    assert bucketed == counts["total"], counts

    # 3. The graph snapshot risk_summary is a distinctly-labeled metric
    #    (graph-node severity), NOT the reconciled exec headline.
    snapshots = demo_estate_client.get("/v1/graph/snapshots").json()
    assert snapshots, "expected persisted demo snapshots"
    for snapshot in snapshots:
        assert snapshot.get("severity_basis") == "graph_nodes", snapshot


def test_demo_estate_showcase_cloud_hierarchy_and_exposure(demo_estate_client: TestClient) -> None:
    """Showcase graph carries org→account containment and a bastion→PII exposure edge.

    Read through the cursor rather than from a single default page. This asserts
    a property of the *graph* — two named low-severity leaves and the edge
    between them — and node pages are ordered by severity, so at estate scale no
    page-size choice can promise a particular leaf is on page one. Asserting it
    against the default page passed only while the estate was small enough to
    fit, which made the test a size check wearing a topology check's clothes.

    The default page's own contract — that it still describes a shaped estate
    rather than a heap of findings — is asserted separately in
    ``test_default_graph_page_carries_the_containment_spine``.
    """
    payload = _full_graph(demo_estate_client)
    node_ids = {node.get("id") for node in payload.get("nodes") or []}
    assert "org:corp" in node_ids
    assert "account:aws:123456789012" in node_ids

    edges = payload.get("edges") or []
    contains = {(row.get("source"), row.get("target")) for row in edges if row.get("relationship") == "contains"}
    assert ("org:corp", "account:aws:123456789012") in contains
    assert ("account:aws:123456789012", "cloud:pii-bucket") in contains
    assert ("account:aws:123456789012", "cloud:bastion") in contains

    exposed = [
        row
        for row in edges
        if row.get("relationship") == "exposed_to" and row.get("source") == "cloud:bastion" and row.get("target") == "cloud:pii-bucket"
    ]
    assert exposed, "expected bastion→PII EXPOSED_TO edge in showcase snapshot"


def test_demo_estate_graph_tags_runtime_evidence_tiers(demo_estate_client: TestClient) -> None:
    # Whole snapshot: runtime-evidence tiers sit on unrated tool/tool-call nodes,
    # which the estate's rated findings now outrank on the default page.
    payload = _full_graph(demo_estate_client)
    attrs_by_id = {node.get("id"): (node.get("attributes") or {}) for node in payload.get("nodes") or []}
    assert attrs_by_id.get("call:0", {}).get("evidence_tier") == "runtime_observed"
    assert attrs_by_id.get("tool:shell-runner-server:run_shell", {}).get("evidence_tier") == "runtime_blocked"


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
    assert {row.id for row in tenant_a_connections}.isdisjoint({row.id for row in tenant_b_connections})
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
    first = demo_estate_client.get("/v1/jobs", headers=VIEWER).json()
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

    second = maybe_bootstrap_demo_estate()
    assert second.get("reason") == "demo_jobs_present"
    again = demo_estate_client.get("/v1/jobs", headers=VIEWER).json()
    assert again.get("total") == first.get("total")


def test_demo_estate_reseeds_when_marker_job_has_no_findings(
    demo_estate_client: TestClient,
) -> None:
    """A demo-tagged job with empty findings must not block reseed (empty demo)."""
    import uuid

    from agent_bom.api import stores as api_stores
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.pipeline import _now
    from agent_bom.api.store import DEMO_ESTATE_TRIGGERED_BY
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    store = api_stores._get_store()
    for job in list(store.list_all(tenant_id=SHOWCASE_TENANT)):
        store.delete(job.job_id, tenant_id=SHOWCASE_TENANT)

    empty = ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id=SHOWCASE_TENANT,
        triggered_by=DEMO_ESTATE_TRIGGERED_BY,
        created_at=_now(),
        request=ScanRequest(offline=True),
    )
    empty.status = JobStatus.DONE
    empty.completed_at = _now()
    empty.result = {"scan_sources": ["demo", "demo-estate"], "findings": [], "agents": []}
    store.put(empty)

    before_total = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1}).json()
    assert before_total.get("total", 0) == 0

    summary = maybe_bootstrap_demo_estate()
    assert summary.get("seeded") is True, summary
    assert (summary.get("findings") or 0) >= 1

    after = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1}).json()
    assert after.get("total", 0) > 0


def test_demo_estate_survives_job_ttl_cleanup(demo_estate_client: TestClient) -> None:
    """API job TTL must not delete curated demo-estate scan jobs."""
    from agent_bom.api import stores as api_stores
    from agent_bom.api.pipeline import _now
    from agent_bom.api.store import DEMO_ESTATE_TRIGGERED_BY
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    store = api_stores._get_store()
    demo_jobs = [job for job in store.list_all(tenant_id=SHOWCASE_TENANT) if getattr(job, "triggered_by", None) == DEMO_ESTATE_TRIGGERED_BY]
    assert demo_jobs, "precondition: bootstrap seeded a demo-estate job"
    for job in demo_jobs:
        job.completed_at = "2020-01-01T00:00:00+00:00"
        store.put(job)

    removed = store.cleanup_expired(ttl_seconds=1)
    remaining = [job for job in store.list_all(tenant_id=SHOWCASE_TENANT) if getattr(job, "triggered_by", None) == DEMO_ESTATE_TRIGGERED_BY]
    assert remaining, f"demo estate jobs were purged by TTL (removed={removed})"

    # Restore a current completed_at so the default findings window still sees them.
    now = _now()
    for job in remaining:
        job.completed_at = now
        store.put(job)
    findings = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1}).json()
    assert findings.get("total", 0) > 0


def test_demo_estate_exposure_paths_materialized(demo_estate_client: TestClient) -> None:
    """The materialized exposure-path queue (read by /v1/graph/exposure-paths) is
    non-empty and headlines the seeded hero chains."""
    payload = demo_estate_client.get("/v1/graph/exposure-paths", headers=VIEWER, params={"limit": 10}).json()
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
    posture = demo_estate_client.get("/v1/graph/nhi/governance", headers=VIEWER).json()
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


def test_demo_estate_agents_fall_back_to_demo_inventory(demo_estate_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """On a hosted server local discovery is empty; the demo estate falls back to
    the curated inventory so /v1/agents + /v1/agents/mesh are non-empty and
    correlated with the graph agents."""
    import agent_bom.discovery as discovery_mod

    monkeypatch.setattr(discovery_mod, "discover_all", lambda: [])
    from agent_bom.api.routes.discovery import _clear_agents_response_cache_for_tests

    _clear_agents_response_cache_for_tests()

    agents = demo_estate_client.get("/v1/agents", headers=VIEWER).json()
    names = {a.get("name") for a in agents.get("agents", [])}
    assert agents.get("count", 0) >= 5, agents
    assert {"cursor", "langchain-service", "support-copilot"} <= names, names

    mesh = demo_estate_client.get("/v1/agents/mesh", headers=VIEWER).json()
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

    before = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 3}).json()
    assert before.get("total", 0) > 0

    # Simulate a process restart: the in-memory job store is recreated empty
    # while the persisted graph snapshot survives.
    api_stores._store = None
    assert not _tenant_has_demo_jobs(api_stores._get_store(), SHOWCASE_TENANT)

    summary = maybe_bootstrap_demo_estate()
    assert summary.get("seeded") is True, summary

    after = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 3}).json()
    assert after.get("total", 0) == before.get("total", 0), (before.get("total"), after.get("total"))


# ── Enterprise estate projected into the graph ────────────────────────────
#
# Once the estate is in the graph the snapshot no longer fits one severity-ranked
# API page, so these read the whole snapshot explicitly and separately assert
# that the *default* page says so rather than reading as the estate.


def _full_graph(client: TestClient) -> dict:
    """Assemble the COMPLETE snapshot by walking the keyset cursor.

    A single ``limit=5000`` request used to cover it. It no longer can: the
    estate projects more nodes than ``/v1/graph``'s own ``limit <= 5000``
    ceiling, so one request is a truncated page by definition and asserting
    ``complete is True`` on it could only ever be satisfied by shrinking the
    estate. ``cursor=`` is the route's documented deep-paging path; walking it
    is how a client reads everything, and it is what these tests need.
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()
    payload: dict = {}
    cursor: str | None = None
    for _page in range(20):  # bounded so a paging bug fails rather than hangs
        params: dict[str, object] = {"limit": 5000}
        if cursor:
            params["cursor"] = cursor
        payload = client.get("/v1/graph", headers=VIEWER, params=params).json()
        for node in payload.get("nodes") or []:
            node_id = node.get("id")
            if node_id not in seen:
                seen.add(str(node_id))
                nodes.append(node)
        edges.extend(payload.get("edges") or [])
        cursor = payload.get("next_cursor") or (payload.get("pagination") or {}).get("next_cursor")
        if not cursor:
            break
    else:  # pragma: no cover - only reached when paging never terminates
        raise AssertionError("graph paging did not terminate")

    total = (payload.get("completeness") or {}).get("total")
    assert total is None or len(nodes) >= int(total), (len(nodes), total)
    merged = dict(payload)
    merged["nodes"] = nodes
    merged["edges"] = edges
    return merged


def test_demo_estate_graph_carries_the_projected_estate(demo_estate_client: TestClient) -> None:
    """The graph a prospect clicks IS the estate, not a 112-node stand-in."""
    payload = _full_graph(demo_estate_client)
    nodes = payload.get("nodes") or []
    node_ids = {n.get("id") for n in nodes}
    by_type = Counter(n.get("entity_type") for n in nodes)

    assert len(nodes) >= 2500, len(nodes)
    # org → account → environment → asset, all four levels present.
    assert "organization:northstar-health-ai" in node_ids
    assert "account:aws:123456789012" in node_ids
    assert "env:aws:123456789012:production" in node_ids
    assert "cloud_resource:aws:iam:role:member-copilot-prod" in node_ids
    assert by_type["account"] >= 40, by_type
    assert by_type["environment"] >= 100, by_type
    assert by_type["misconfiguration"] >= 439, by_type

    contains = {(row.get("source"), row.get("target")) for row in payload.get("edges") or [] if row.get("relationship") == "contains"}
    assert ("organization:northstar-health-ai", "account:aws:123456789012") in contains
    assert ("account:aws:123456789012", "env:aws:123456789012:production") in contains
    assert (
        "env:aws:123456789012:production",
        "cloud_resource:aws:iam:role:member-copilot-prod",
    ) in contains
    # One estate, one root: the hand-built showcase org hangs off the estate org.
    assert ("organization:northstar-health-ai", "org:corp") in contains


def test_demo_estate_graph_incident_chain_is_traversable(demo_estate_client: TestClient) -> None:
    """workflow → role → workload → MCP tool → PHI table → hosted model.

    Asserts each landmark is *reachable* from the one before it, not that the
    two are directly adjacent. The chain names the six assets the incident story
    is told through; how many hops sit between them is a property of the estate,
    not of the story. Pinning adjacency made this a test of chain length — it
    broke the moment the estate started modelling the real intermediate assets
    (the ECR image the role deploys, the cluster hosting the workload, the MCP
    server publishing the tool, the database holding the table), all of which
    make the traversal *more* faithful, not less.
    """
    payload = _full_graph(demo_estate_client)
    adjacency: dict[str, set[str]] = {}
    for row in payload.get("edges") or []:
        adjacency.setdefault(str(row.get("source")), set()).add(str(row.get("target")))
    chain = (
        "github:workflow:member-copilot/deploy-prod",
        "cloud_resource:aws:iam:role:member-copilot-prod",
        "kubernetes:workload:member-ai-prod/ai-prod/member-copilot",
        "mcp:tool:clinical-analytics/execute_sql",
        "snowflake:table:nh_prod/analytics/phi/patient_summary",
        "model:openai:gpt-4.1",
    )
    node_ids = {n.get("id") for n in payload.get("nodes") or []}
    for hop in chain:
        assert hop in node_ids, f"missing incident hop {hop}"

    def _reaches(source: str, target: str, *, max_hops: int = 6) -> bool:
        frontier = {source}
        seen = {source}
        for _ in range(max_hops):
            frontier = {nxt for node in frontier for nxt in adjacency.get(node, ())} - seen
            if target in frontier:
                return True
            if not frontier:
                return False
            seen |= frontier
        return False

    for source, target in zip(chain, chain[1:], strict=False):
        assert _reaches(source, target), f"incident chain broken at {source} -> {target}"


def test_demo_estate_findings_land_on_inventoried_graph_nodes(
    demo_estate_client: TestClient,
) -> None:
    """No finding materialises its own stub target (the #4637 defect class)."""
    payload = _full_graph(demo_estate_client)
    nodes_by_id = {n.get("id"): n for n in payload.get("nodes") or []}
    affected: set[str] = set()
    for row in payload.get("edges") or []:
        if row.get("relationship") != "affects":
            continue
        source = nodes_by_id.get(row.get("source")) or {}
        if source.get("entity_type") != "misconfiguration":
            continue
        target = nodes_by_id.get(row.get("target"))
        assert target is not None, row
        if (target.get("attributes") or {}).get("estate_id"):
            affected.add(row.get("target"))
    assert len(affected) >= 407, len(affected)


def test_demo_estate_default_graph_page_declares_its_truncation(
    demo_estate_client: TestClient,
) -> None:
    """A bounded page must never read as the whole estate (#4631)."""
    payload = demo_estate_client.get("/v1/graph", headers=VIEWER).json()
    completeness = payload.get("completeness") or {}
    stats = payload.get("stats") or {}

    assert completeness.get("truncated") is True, completeness
    assert completeness.get("complete") is False, completeness
    assert completeness.get("returned") == len(payload.get("nodes") or [])
    assert completeness.get("reason"), completeness
    # The two numbers a reader reconciles must agree.
    assert completeness.get("total") == stats.get("total_nodes_source"), (completeness, stats)
    assert completeness["total"] > completeness["returned"]


def test_demo_estate_graph_rolls_up_to_a_readable_estate(demo_estate_client: TestClient) -> None:
    """2,000 raw nodes are unreadable — the default read is account → env → resource."""
    rollup = demo_estate_client.get("/v1/graph/rollup", headers=VIEWER).json()
    top_level = rollup.get("top_level") or []
    containers = [row for row in top_level if row.get("is_container") and row.get("has_children")]
    root_ids = {row.get("id") for row in containers}
    assert "organization:northstar-health-ai" in root_ids, root_ids

    root = next(row for row in containers if row["id"] == "organization:northstar-health-ai")
    assert root["aggregate"]["descendant_count"] >= 2500, root["aggregate"]
    assert rollup["summary"]["total_nodes_source"] >= 2500, rollup["summary"]

    accounts = demo_estate_client.get(
        "/v1/graph/rollup",
        headers=VIEWER,
        params={"node": "organization:northstar-health-ai"},
    ).json()
    account_ids = {row.get("id") for row in accounts.get("children") or []}
    assert "account:aws:123456789012" in account_ids
    assert len(account_ids) >= 40, len(account_ids)

    envs = demo_estate_client.get("/v1/graph/rollup", headers=VIEWER, params={"node": "account:aws:123456789012"}).json()
    env_children = {row.get("id"): row for row in envs.get("children") or []}
    assert "env:aws:123456789012:production" in env_children, list(env_children)

    resources = demo_estate_client.get("/v1/graph/rollup", headers=VIEWER, params={"node": "env:aws:123456789012:production"}).json()
    assert resources.get("children"), resources


def test_default_graph_page_carries_the_containment_spine(demo_estate_client: TestClient) -> None:
    """The first page a client gets must describe a shaped estate, not a heap.

    ``/v1/graph`` orders nodes by severity. Once the estate carries more
    high-severity findings than a page holds — 2,582 findings against a default
    limit of 500 — every org, account and environment ranks below the cut, and
    the default response contains findings floating with no structure. It looked
    correct only while the estate was small enough that the spine happened to
    fit inside the page.

    Containment ancestors are few at any estate size, so they are resolved
    explicitly and added on top of the page rather than left to compete on rank.
    """
    payload = demo_estate_client.get("/v1/graph", headers=VIEWER).json()
    nodes = payload.get("nodes") or []
    kinds = {str(node.get("type") or node.get("entity_type") or "") for node in nodes}
    assert {"org", "account"} <= kinds, f"default page has no containment spine: {sorted(kinds)}"

    node_ids = {node.get("id") for node in nodes}
    contains = {
        (row.get("source"), row.get("target"))
        for row in payload.get("edges") or []
        if row.get("relationship") in {"contains", "hosts", "owns"}
    }
    linked = [pair for pair in contains if pair[0] in node_ids and pair[1] in node_ids]
    assert linked, "containment nodes arrived with no edge joining them to the page"


# ── UTC day rollover ────────────────────────────────────────────────────────
#
# CI caught this the hard way: a run whose demo bootstrap landed at 23:59 and
# whose request landed at 00:00:04 read ``calls_today: 0`` and failed
# ``assert 0 >= 12``. The same clock makes the hosted demo claim no traffic on
# an estate the tile beside it describes as busy, and left the seeded LLM spend
# permanently invisible — its guard treated "any records exist" as "already
# seeded", so it never re-seeded at all.
#
# Running these once proves nothing, so nothing below reads the wall clock for
# the behaviour under test: evidence is seeded against an explicit yesterday and
# is read back through the real ``[UTC midnight, now]`` window.


def _seed_only_yesterdays_evidence() -> datetime:
    """Reset the day-scoped stores and leave them holding yesterday's demo data.

    Covers both halves of the rollover: the gateway feed (which the maintenance
    loop reseeds, so it was merely late) and the seeded LLM spend (which was
    guarded on "any records exist" and so never came back at all).
    """
    from agent_bom.api import cost_store
    from agent_bom.api import stores as api_stores
    from agent_bom.api.gateway_activity_store import get_gateway_activity_store
    from agent_bom.api.routes.proxy import _reset_proxy_runtime_for_tests
    from agent_bom.demo_estate.bootstrap import reset_daily_evidence_day
    from agent_bom.demo_estate.showcase_gateway import seed_showcase_gateway_events
    from agent_bom.demo_estate.showcase_governance import _seed_cost_records

    _reset_proxy_runtime_for_tests()
    api_stores._get_firewall_decision_store().reset()
    reset_gateway_activity = getattr(get_gateway_activity_store(), "reset", None)
    if callable(reset_gateway_activity):
        reset_gateway_activity()
    cost_store._COST_STORE = None
    reset_daily_evidence_day()

    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    seeded = seed_showcase_gateway_events(now=yesterday)
    assert seeded.get("seeded") is True, seeded
    assert _seed_cost_records(tenant_id="default", now=yesterday) > 0
    return yesterday


def test_yesterdays_gateway_evidence_is_outside_todays_kpi_window() -> None:
    """The mechanism itself: day-scoped evidence goes dark when the day turns.

    Pinned separately from the fix so a future change that stops scoping the
    seed to a single UTC day fails here loudly rather than quietly making the
    rollover test below tautological.
    """
    from agent_bom.demo_estate.showcase_gateway import _event_time

    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    todays_window_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    for minutes_ago in (0, 1, 20):
        assert _event_time(yesterday, minutes_ago) < todays_window_start


def test_gateway_kpis_recover_after_a_utc_day_rollover(demo_estate_client: TestClient) -> None:
    """A request landing on the far side of midnight still reports the estate."""
    _seed_only_yesterdays_evidence()

    # Pre-state: the stores hold demo evidence, but none of it is inside the
    # window the KPI header reports on. This is precisely what CI saw.
    from agent_bom.api.routes.proxy import _load_proxy_alerts

    today = datetime.now(timezone.utc).date().isoformat()
    assert not [alert for alert in _load_proxy_alerts("default") if str(alert.get("ts") or "").startswith(today)]

    kpis = demo_estate_client.get("/v1/gateway/feed/kpis").json()

    assert kpis.get("calls_today", 0) >= 12, kpis
    assert kpis.get("blocked_today", 0) >= 5, kpis
    assert kpis.get("shadow_ai_blocked", 0) >= 2, kpis
    assert kpis.get("data_filters_applied", 0) >= 2, kpis
    # The spend half of the same rollover: this one never self-healed.
    assert kpis.get("llm_calls", 0) > 0, kpis


def test_daily_refresh_does_not_reseed_twice_in_one_day(demo_estate_client: TestClient) -> None:
    """The per-request hook must cost one comparison, not a reseed each time."""
    from agent_bom.demo_estate.bootstrap import refresh_demo_daily_evidence

    _seed_only_yesterdays_evidence()
    demo_estate_client.get("/v1/gateway/feed/kpis")

    assert refresh_demo_daily_evidence() == {
        "refreshed": False,
        "reason": "current",
        "day": datetime.now(timezone.utc).date().isoformat(),
    }


def test_daily_refresh_is_a_no_op_outside_demo_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every deployment pays for this hook; only the demo may act on it."""
    from agent_bom.demo_estate.bootstrap import refresh_demo_daily_evidence, reset_daily_evidence_day

    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    reset_daily_evidence_day()

    assert refresh_demo_daily_evidence() == {"refreshed": False, "reason": "disabled"}
