"""The demo estate must demonstrate scale and correlation, not assert them.

Every assertion here is about a *chain* or a *reconciliation*. A test that only
counts rows proves nothing: 6,148 "correlations" of which 6,145 were one event
grouped with itself passed a count assertion for months while the surface headed
"cross-vendor correlations" showed 3.

The four properties under test:

1. **Traces span vendors.** A correlation is a real multi-source trace with an
   ordered asset path, not a single event wearing a trace id.
2. **Findings come from more than one scanner.** Posture, vulnerability, secret,
   IaC and runtime lanes, every one of them landing on an *inventoried* asset via
   the canonical id path.
3. **The AI estate lives inside the cloud accounts.** A first-party AI service
   shares its account, region, environment, identity and data store with the
   cloud resources beside it — that shared context is what the correlation is.
4. **Counts reconcile and generation is deterministic**, including across
   ``PYTHONHASHSEED``.
"""

from __future__ import annotations

import collections
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_bom.demo_estate.enterprise import EnterpriseEstate, EvidenceSource
from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_correlation import (
    EnterpriseCorrelationResult,
    correlate_enterprise_estate,
)
from agent_bom.demo_estate.enterprise_findings import (
    build_estate_findings,
    summarize_estate_findings,
)
from agent_bom.demo_estate.enterprise_scale import (
    AI_LANE_TAG,
    MIN_CROSS_SOURCE_CORRELATIONS,
    MIN_ESTATE_FINDINGS,
)
from agent_bom.demo_estate.estate_graph import project_estate_into_graph
from agent_bom.graph.container import UnifiedGraph

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def estate() -> EnterpriseEstate:
    return build_demo_estate(tenant_id="estate-v2")


@pytest.fixture(scope="module")
def correlated(estate: EnterpriseEstate) -> EnterpriseCorrelationResult:
    return correlate_enterprise_estate(estate)


@pytest.fixture(scope="module")
def findings(estate: EnterpriseEstate, correlated: EnterpriseCorrelationResult):
    return build_estate_findings(estate, correlation_result=correlated)


# ── 1. Cross-vendor traces ────────────────────────────────────────────────────


def test_cross_source_correlations_are_in_the_hundreds(correlated):
    """The headline claim: evidence from different vendors joins on one trace."""
    cross_source = [row for row in correlated.correlations if len(set(row.sources)) >= 2]
    assert len(cross_source) >= MIN_CROSS_SOURCE_CORRELATIONS, f"only {len(cross_source)} correlations span more than one evidence source"


def test_a_cross_vendor_trace_is_a_real_chain_not_a_relabelled_event(estate, correlated):
    """Assert the CHAIN: distinct sources, ordered time, multi-provider asset path.

    The defect this replaces was invisible to a count — every observation carried
    its own trace id, so a "correlation" was one event grouped with itself. A
    chain is only a chain if it has more than one event, from more than one
    source, walking more than one provider's assets, in time order.
    """
    assets_by_id = {asset.asset_id: asset for asset in estate.assets}
    events_by_id = {event.event_id: event for event in correlated.events}

    deep = [row for row in correlated.correlations if len(set(row.sources)) >= 4 and len(row.asset_path) >= 3]
    assert deep, "no correlation spans four evidence sources over three or more assets"

    for row in deep[:25]:
        assert len(row.event_ids) == len(row.sources)
        assert len(set(row.event_ids)) == len(row.event_ids), "an event was counted twice"

        timestamps = [events_by_id[event_id].observed_at for event_id in row.event_ids]
        assert timestamps == sorted(timestamps), "trace events are not in time order"
        assert row.started_at == timestamps[0]
        assert row.ended_at == timestamps[-1]

        # Every hop is an asset the estate actually inventoried — no stubs.
        assert all(asset_id in assets_by_id for asset_id in row.asset_path)
        providers = {assets_by_id[asset_id].provider for asset_id in row.asset_path}
        assert len(providers) >= 2, f"asset path stays inside one provider: {providers}"

        # One actor drives the whole trace; that is what makes it one story.
        actors = {events_by_id[event_id].actor_id for event_id in row.event_ids}
        assert len(actors) == 1, f"a single trace has {len(actors)} actors"


def test_the_full_six_vendor_pipeline_is_represented(correlated):
    """CI -> cloud audit -> Kubernetes -> MCP -> warehouse -> model, on one trace."""
    pipeline = {
        EvidenceSource.GITHUB_ACTIONS,
        EvidenceSource.KUBERNETES_AUDIT,
        EvidenceSource.MCP_GATEWAY,
        EvidenceSource.SNOWFLAKE_ACCESS_HISTORY,
        EvidenceSource.OTEL_LLM,
    }
    spanning = [row for row in correlated.correlations if pipeline <= set(row.sources)]
    assert len(spanning) >= 50, f"only {len(spanning)} traces cover the whole pipeline"


def test_trace_outcomes_are_read_from_evidence_not_assumed(correlated):
    """A blocked egress and an allowed one must not both report 'blocked'.

    ``_correlation_kind`` used to label *any* trace touching an LLM span as
    ``blocked``, which is a verdict the evidence does not support. Outcomes now
    come from the policy decision the span actually recorded, so both verdicts
    have to be present.
    """
    egress = [row for row in correlated.correlations if row.kind == "data_egress_attempt"]
    assert len(egress) >= 2
    outcomes = collections.Counter(row.outcome for row in egress)
    assert outcomes["blocked"] > 0, "no blocked egress attempt"
    assert outcomes["allowed"] > 0, "every egress reads as blocked — the verdict is assumed"


def test_the_narrative_incident_is_still_the_primary_correlation():
    """The generated population must not shoulder the hand-authored incident aside."""
    from agent_bom.demo_estate.presentation import build_enterprise_demo_story

    story = build_enterprise_demo_story(tenant_id="estate-v2")
    assert story.primary_correlation.outcome == "blocked"
    assert tuple(source.value for source in story.primary_correlation.sources) == (
        "github_actions",
        "aws_cloudtrail",
        "kubernetes_audit",
        "mcp_gateway",
        "snowflake_access_history",
        "otel_llm",
    )
    assert story.correlations[0] == story.primary_correlation


# ── 2. Findings from more than CIS ────────────────────────────────────────────


def test_findings_reach_the_thousands_across_several_lanes(findings):
    assert len(findings) >= MIN_ESTATE_FINDINGS

    by_type = collections.Counter(finding.finding_type.value for finding in findings)
    for required in ("CIS_FAIL", "CVE", "CREDENTIAL_EXPOSURE"):
        assert by_type[required] > 0, f"no {required} findings — the estate is single-lane"

    by_source = collections.Counter(finding.source.value for finding in findings)
    assert len(by_source) >= 4, f"findings come from too few scanners: {dict(by_source)}"

    # Realistic distribution: no lane may dominate the estate.
    dominant = max(by_type.values())
    assert dominant < len(findings) * 0.6, f"one finding type is {dominant}/{len(findings)}"


def test_severity_is_a_distribution_not_a_wall_of_critical(estate, findings):
    summary = summarize_estate_findings(estate, findings)
    assert sum(summary.by_severity.values()) == summary.total == len(findings)
    assert summary.by_severity["critical"] > 0
    assert summary.by_severity["medium"] > 0
    # Unrated is an explicit bucket, never a silent drop.
    assert summary.by_severity["unrated"] > 0
    assert summary.by_severity["critical"] < summary.total * 0.2, "most of the estate is critical"


def test_vulnerability_findings_carry_exploitability_evidence(findings):
    """A CVE without EPSS/KEV is a row of text, not a prioritisable risk."""
    cves = [finding for finding in findings if finding.finding_type.value == "CVE"]
    assert len(cves) >= 200
    assert all(finding.cve_id for finding in cves)
    assert any(finding.is_kev for finding in cves), "no KEV-flagged vulnerability"
    scored = [finding for finding in cves if finding.epss_score is not None]
    assert len(scored) == len(cves), "some CVEs carry no EPSS score"
    assert len({round(finding.epss_score, 3) for finding in scored}) > 10, "EPSS is a constant"


def test_every_finding_resolves_to_an_inventoried_asset(estate, findings):
    """#4637: one id scheme. A finding's asset id IS an estate asset id."""
    known = {asset.asset_id for asset in estate.assets}
    orphans = [finding.asset.identifier for finding in findings if (finding.asset.identifier or "") not in known]
    assert not orphans, f"{len(orphans)} findings point at assets the estate never inventoried"

    # ... and the canonical id is a pure function of that row, so the findings
    # list and the graph join on an identifier rather than on a label.
    for finding in findings[:200]:
        assert finding.asset.canonical_id
        assert finding.evidence.get("resource_id") == finding.asset.identifier


def test_secret_and_iac_findings_name_both_the_code_and_the_resource(findings):
    """The code-layer location is evidence; the affected thing is the asset."""
    secrets = [f for f in findings if f.finding_type.value == "CREDENTIAL_EXPOSURE"]
    assert secrets
    for finding in secrets[:50]:
        assert finding.evidence.get("file"), "a secret finding names no file"
        assert "REDACT" in str(finding.evidence.get("redacted_preview", "")).upper()

    iac = [f for f in findings if f.evidence.get("iac") is True]
    assert iac, "no IaC misconfiguration findings"
    for finding in iac[:50]:
        assert finding.evidence.get("file_path")
        assert finding.evidence.get("rule_id")


# ── 3. The AI estate lives inside the cloud accounts ──────────────────────────


def test_first_party_ai_services_share_account_region_and_environment(estate):
    """A Bedrock agent is an AWS account resource, not a separate vendor lane."""
    native = [a for a in estate.assets if a.tags.get(AI_LANE_TAG) == "first_party"]
    assert len(native) >= 300, f"only {len(native)} first-party AI services"

    by_provider = collections.Counter(asset.provider for asset in native)
    for cloud in ("aws", "azure", "gcp", "snowflake"):
        assert by_provider[cloud] > 0, f"{cloud} has no first-party AI service"

    # Every AI service sits in an account/region/environment that already holds
    # non-AI resources from the same provider.
    cloud_scopes: dict[str, set[tuple[str, str, str]]] = {}
    for asset in estate.assets:
        if asset.tags.get(AI_LANE_TAG):
            continue
        cloud_scopes.setdefault(asset.provider, set()).add((asset.account_scope, asset.region, asset.environment))
    for asset in native:
        assert (asset.account_scope, asset.region, asset.environment) in cloud_scopes[asset.provider], (
            f"{asset.asset_id} lives in a scope no other resource occupies"
        )


def test_ai_services_attach_to_identities_and_data_that_already_exist(estate):
    """The correlation is the shared identity and the shared data store."""
    by_id = {asset.asset_id: asset for asset in estate.assets}
    native = [a for a in estate.assets if a.tags.get(AI_LANE_TAG) == "first_party"]

    linked = 0
    for asset in native:
        identity = asset.tags.get("uses_identity", "")
        data_store = asset.tags.get("reads_data", "")
        if not identity and not data_store:
            continue
        linked += 1
        if identity:
            principal = by_id[identity]
            assert principal.provider == asset.provider
            assert principal.account_scope == asset.account_scope
        if data_store:
            store = by_id[data_store]
            assert store.account_scope == asset.account_scope
    assert linked >= len(native) * 0.8, "most AI services borrow no existing identity or data"


def test_third_party_ai_is_the_smaller_share(estate):
    native = [a for a in estate.assets if a.tags.get(AI_LANE_TAG) == "first_party"]
    third_party = [a for a in estate.assets if a.tags.get(AI_LANE_TAG) == "third_party"]
    assert third_party, "the third-party AI lane disappeared"
    assert len(third_party) < len(native), f"third-party ({len(third_party)}) is not the smaller share of native ({len(native)})"


def test_mcp_servers_own_their_tools_and_agents_delegate(estate):
    by_id = {asset.asset_id: asset for asset in estate.assets}
    tools = [a for a in estate.assets if a.resource_type == "tool"]
    servers = [a for a in estate.assets if a.resource_type == "server"]
    agents = [a for a in estate.assets if a.resource_type == "agent"]
    assert len(servers) >= 20 and len(tools) >= 80 and len(agents) >= 30

    for tool in tools:
        parent = tool.tags.get("mcp_server", "")
        assert parent in by_id, f"tool {tool.asset_id} hangs off no inventoried server"
        assert by_id[parent].resource_type == "server"

    delegating = [a for a in agents if a.tags.get("delegates_to")]
    assert delegating, "no agent-to-agent topology"
    for agent in delegating:
        assert by_id[agent.tags["delegates_to"]].resource_type == "agent"


# ── 4. Exposure surfaces and attack paths ─────────────────────────────────────


def test_exposure_surfaces_exist_and_are_labelled(estate):
    public = [a for a in estate.assets if a.tags.get("internet_facing") == "true"]
    permissive = [a for a in estate.assets if a.tags.get("over_permissive") == "true"]
    public_data = [a for a in estate.assets if a.tags.get("public_access") == "true" and a.data_classifications]
    assert len(public) >= 40
    assert len(permissive) >= 20
    assert public_data, "no publicly reachable data store"


def test_attack_paths_are_a_rich_set_and_every_hop_is_inventoried(estate, correlated, findings):
    graph = UnifiedGraph()
    shape = project_estate_into_graph(graph, estate, findings=findings, correlations=correlated.correlations)
    known = {asset.asset_id for asset in estate.assets}

    assert shape["attack_paths"] >= 200, f"only {shape['attack_paths']} attack paths"
    assert len(graph.attack_paths) == shape["attack_paths"]
    for path in graph.attack_paths:
        assert len(path.hops) >= 2
        assert all(hop in known for hop in path.hops)
        assert path.source == path.hops[0] and path.target == path.hops[-1]

    # A path is only worth showing if it ends somewhere that matters.
    by_id = {asset.asset_id: asset for asset in estate.assets}
    to_data = [path for path in graph.attack_paths if by_id[path.target].data_classifications or by_id[path.target].tags.get(AI_LANE_TAG)]
    assert len(to_data) >= 100, "attack paths rarely reach data or an AI service"


def test_graph_projection_reports_its_size_against_the_canvas_budget(estate, correlated, findings):
    """The projection is total, and says how it sits against the render budget.

    The estate is not trimmed to fit one view — that would be tuning the data to
    flatter the picture. What must never happen is a canvas showing part of the
    estate while nothing says so, so the projection reports both halves of that
    relationship and the API's ``completeness`` carries it to the client.
    """
    graph = UnifiedGraph()
    shape = project_estate_into_graph(graph, estate, findings=findings, correlations=correlated.correlations)
    # Every finding lands: none was dropped for want of an inventoried asset.
    assert shape["findings"] == shape["findings_total"] == len(findings)
    assert shape["findings_truncated"] is False
    assert shape["findings_bound_reason"] == ""

    assert shape["nodes"] == len(graph.nodes)
    assert shape["edges"] == len(graph.edges)
    assert shape["node_budget"] > 0
    assert shape["exceeds_canvas_budget"] is (shape["nodes"] > shape["node_budget"])


def test_topology_edges_make_the_ai_chain_traversable(estate, correlated, findings):
    """AI service -> identity -> data store must be edges, not tags."""
    from agent_bom.graph.types import RelationshipType

    graph = UnifiedGraph()
    shape = project_estate_into_graph(graph, estate, findings=findings, correlations=correlated.correlations)
    assert shape["topology_edges"] >= 500
    assert shape["exposure_edges"] > 0

    by_relationship = collections.Counter(edge.relationship for edge in graph.edges)
    for relationship in (
        RelationshipType.ASSUMES,
        RelationshipType.CAN_ACCESS,
        RelationshipType.DELEGATED_TO,
        RelationshipType.EXPOSED_TO,
    ):
        assert by_relationship[relationship] > 0, f"no {relationship.value} edges"

    # Walk one: a first-party AI service, the role it assumes, the store it reads.
    by_id = {asset.asset_id: asset for asset in estate.assets}
    service = next(
        a for a in estate.assets if a.tags.get(AI_LANE_TAG) == "first_party" and a.tags.get("uses_identity") and a.tags.get("reads_data")
    )
    assumed = by_id[service.tags["uses_identity"]]
    store = by_id[service.tags["reads_data"]]
    assert assumed.account_scope == service.account_scope == store.account_scope
    assert {service.asset_id, assumed.asset_id, store.asset_id} <= set(graph.nodes)


# ── 5. Reconciliation and determinism ─────────────────────────────────────────


def test_story_counts_reconcile_with_the_estate_they_describe():
    from agent_bom.demo_estate.presentation import build_enterprise_demo_story

    story = build_enterprise_demo_story(tenant_id="estate-v2")
    assert story.summary.findings == story.finding_summary.total
    assert sum(story.finding_summary.by_severity.values()) == story.finding_summary.total
    assert story.summary.cross_source_correlations >= MIN_CROSS_SOURCE_CORRELATIONS
    assert story.summary.cross_source_correlations <= story.summary.correlations

    for name, returned, total in (
        ("events", len(story.events), story.summary.observations),
        ("correlations", len(story.correlations), story.summary.correlations),
        ("findings", len(story.findings), story.summary.findings),
    ):
        bound = getattr(story.bounds, name)
        assert bound.returned == returned
        assert bound.total == total
        assert bound.truncated is (returned < total)


def test_generation_is_deterministic_across_process_and_hash_seed():
    """Same profile, same content hash — proved in fresh interpreters.

    ``PYTHONHASHSEED`` randomises ``str.__hash__``, so any generator that let set
    or dict iteration order leak into its output produces a different estate per
    run. That cannot be caught in-process: this has to fork.
    """
    script = (
        "import json;"
        "from agent_bom.demo_estate.enterprise_composition import build_demo_estate;"
        "from agent_bom.demo_estate.enterprise_correlation import correlate_enterprise_estate;"
        "from agent_bom.demo_estate.enterprise_findings import build_estate_findings;"
        "e=build_demo_estate(tenant_id='determinism');"
        "c=correlate_enterprise_estate(e);"
        "f=build_estate_findings(e, correlation_result=c);"
        "print(json.dumps({"
        "'estate':e.content_hash,'story':c.content_hash,"
        "'assets':len(e.assets),'observations':len(e.observations),"
        "'correlations':len(c.correlations),'findings':len(f),"
        "'finding_ids':[x.id for x in f[:500]],"
        "'asset_ids':[a.asset_id for a in e.assets[:500]]}))"
    )
    results = []
    for seed in ("0", "1", "12345"):
        proc = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO_ROOT / "src")},
        )
        results.append(json.loads(proc.stdout))

    assert results[0] == results[1] == results[2], "estate generation is not deterministic"
    assert len(results[0]["estate"]) == 64
