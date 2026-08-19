"""Regression lock for the scan -> findings -> attack-paths wiring.

Mirrors what ``agent-bom quickstart --run`` produces end to end: a scan that
carries a known vulnerability must surface that vulnerability in
``GET /v1/findings`` *and* the corresponding CVE-anchored chain in
``GET /v1/graph/attack-paths``.  The pipeline wiring was validated by hand;
this test locks it so a future refactor of the finding aggregation or graph
persistence path can't silently drop either surface.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.finding_reachability import (
    MAX_FINDING_REACHABILITY_PATHS,
    project_persisted_graph_reachability,
)
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import JobStatus
from agent_bom.api.pipeline import _now, _persist_graph_snapshot
from agent_bom.api.server import _jobs, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import AttackPath
from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.output import to_json

KNOWN_CVE = "CVE-2026-9999"
NON_OVERLAP_CVE = "CVE-2026-0000"


def _report_with_known_vuln() -> dict:
    """Build the canonical scan-result JSON a real scan of a vulnerable agent emits."""
    vuln = Vulnerability(
        id=KNOWN_CVE,
        summary="Remote code execution in demo-lib",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="2.0.0",
        is_kev=True,
    )
    pkg = Package(
        name="demo-lib",
        version="1.0.0",
        ecosystem="pypi",
        vulnerabilities=[vuln],
        # --verify-integrity verdict must survive scan -> store -> API, not stop
        # at the console.
        integrity_verified=True,
        provenance_attested=False,
        provenance_source="pypi_pep740",
    )
    tool = MCPTool(name="run_shell", description="Executes shell commands")
    server = MCPServer(
        name="demo-server",
        command="python",
        args=["-m", "demo"],
        transport=TransportType.STDIO,
        packages=[pkg],
        tools=[tool],
        env={"SECRET_TOKEN": "env:SECRET_TOKEN"},
    )
    agent = Agent(
        name="demo-agent",
        agent_type=AgentType.CUSTOM,
        config_path="/tmp/demo-agent.json",
        mcp_servers=[server],
    )
    blast = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["SECRET_TOKEN"],
        exposed_tools=[tool],
        risk_score=9.0,
        owasp_tags=["LLM05"],
    )
    report = to_json(AIBOMReport(agents=[agent], blast_radii=[blast]))
    report["findings"].append(
        {
            "schema_version": "1",
            "id": "finding-without-a-persisted-path",
            "canonical_id": "finding-without-a-persisted-path",
            "finding_type": "CVE",
            "finding_category": "vulnerability",
            "source": "MCP_SCAN",
            "severity": "medium",
            "effective_severity": "medium",
            "title": f"{NON_OVERLAP_CVE}: standalone-lib@1.0.0",
            "description": "Static finding without graph path evidence",
            "cve_id": NON_OVERLAP_CVE,
            "vulnerability_id": NON_OVERLAP_CVE,
            "node_id": "pkg:pypi:standalone-lib@1.0.0",
            "finding_node_id": f"vuln:{NON_OVERLAP_CVE}",
            "asset": {
                "name": "standalone-lib",
                "asset_type": "package",
                "stable_id": "standalone-lib",
            },
            "affected_agents": [],
            "affected_servers": [],
            "exposed_credentials": [],
            "exposed_tools": [],
            "evidence": {},
        }
    )
    return report


@pytest.fixture
def wired_client(tmp_path, monkeypatch):
    """TestClient whose scan submission completes synchronously with a known vuln.

    The real worker runs discovery + enrichment in a background thread; here we
    replace submission with a deterministic completion that stores the canonical
    result and persists the unified graph through the *same* production helper
    (``_persist_graph_snapshot``) the pipeline uses.  That keeps the read-side
    wiring under test while making the fixture hermetic.
    """
    store = InMemoryJobStore()
    set_job_store(store)
    _jobs.clear()

    original_graph_store = api_stores._graph_store
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    set_graph_store(graph_store)

    report_json = _report_with_known_vuln()

    def _complete_synchronously(job) -> None:
        job.status = JobStatus.DONE
        job.result = report_json
        job.completed_at = _now()
        store.put(job)
        _persist_graph_snapshot(job, report_json)
        # The production demo estate persists its ranked ExposurePaths. This
        # fixture materializes the same evidence so /v1/findings can prove its
        # read-side projection from the graph store rather than re-deriving it.
        from agent_bom.api.routes.graph import _derived_attack_paths

        graph = graph_store.load_graph(tenant_id="default")
        graph.attack_paths = _derived_attack_paths(graph)
        graph_store.save_graph(graph)

    monkeypatch.setattr("agent_bom.api.routes.scan.submit_scan_job", _complete_synchronously)

    try:
        yield TestClient(app, raise_server_exceptions=False)
    finally:
        set_graph_store(original_graph_store)


def test_scan_vuln_flows_to_findings_and_attack_paths(wired_client):
    create = wired_client.post("/v1/scan", json={})
    assert create.status_code == 202, create.text
    job_id = create.json()["job_id"]

    scan = wired_client.get(f"/v1/scan/{job_id}")
    assert scan.status_code == 200
    assert scan.json()["status"] == JobStatus.DONE.value

    findings = wired_client.get("/v1/findings")
    assert findings.status_code == 200
    finding_rows = findings.json()["findings"]
    finding_vulns = {row.get("vulnerability_id") for row in finding_rows}
    assert KNOWN_CVE in finding_vulns, f"known vuln missing from findings: {finding_vulns}"

    attack_paths = wired_client.get("/v1/graph/attack-paths")
    assert attack_paths.status_code == 200
    paths = attack_paths.json()["attack_paths"]
    assert paths, "expected at least one derived attack path for the known vuln"
    path_vuln_ids = {vid for path in paths for vid in (path.get("vuln_ids") or [])}
    assert KNOWN_CVE in path_vuln_ids, f"known vuln missing from attack paths: {path_vuln_ids}"

    reachable = next(row for row in finding_rows if row.get("vulnerability_id") == KNOWN_CVE)
    # A derived agent -> server -> package -> CVE dependency chain is useful
    # topology, but it is not evidence that the vulnerability is reachable at
    # runtime. Keep the finding unknown until the path carries an explicit
    # execution, network, or exploit edge.
    assert reachable["graph_reachable"] is None
    assert reachable["graph_min_hop_distance"] is None
    assert reachable["graph_reachable_from_agents"] == []

    unassessed = next(row for row in finding_rows if row.get("vulnerability_id") == NON_OVERLAP_CVE)
    assert unassessed["graph_reachable"] is None
    assert unassessed["graph_min_hop_distance"] is None
    assert unassessed["graph_reachable_from_agents"] == []

    # The supply-chain verification verdict is the point of --verify-integrity;
    # a machine consumer has to be able to read it off the findings API.
    assert reachable["package_integrity_verified"] is True
    assert reachable["package_provenance_attested"] is False
    assert reachable["package_provenance_source"] == "pypi_pep740"
    # Never checked stays an explicit null, never a silent "no".
    assert unassessed["package_integrity_verified"] is None
    assert unassessed["package_provenance_attested"] is None
    assert unassessed["package_provenance_source"] is None


def test_findings_reachability_projection_is_tenant_scoped_and_bounded():
    class RecordingGraphStore:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def attack_paths(self, **kwargs):
            self.calls.append(kwargs)
            path = AttackPath(
                source="agent:reachable",
                target=f"vuln:{KNOWN_CVE}",
                hops=["agent:reachable", "server:demo", f"vuln:{KNOWN_CVE}"],
                edges=["invoked", "vulnerable_to"],
                vuln_ids=[KNOWN_CVE],
            )
            return "scan-alpha", "2026-07-27T00:00:00Z", [path], MAX_FINDING_REACHABILITY_PATHS + 1

    store = RecordingGraphStore()
    result = project_persisted_graph_reachability(
        [
            {"id": "reachable", "cve_id": KNOWN_CVE, "finding_node_id": f"vuln:{KNOWN_CVE}"},
            {"id": "unassessed", "cve_id": NON_OVERLAP_CVE},
        ],
        graph_store=store,  # type: ignore[arg-type]
        tenant_id="tenant-alpha",
        scan_id="scan-alpha",
        path_limit=50_000,
    )

    assert store.calls == [
        {
            "tenant_id": "tenant-alpha",
            "scan_id": "scan-alpha",
            "offset": 0,
            "limit": MAX_FINDING_REACHABILITY_PATHS,
        }
    ]
    assert result.truncated is True
    assert result.rows[0]["graph_reachable"] is True
    assert result.rows[0]["graph_min_hop_distance"] == 2
    assert result.rows[0]["graph_reachable_from_agents"] == ["agent:reachable"]
    assert result.rows[1]["graph_reachable"] is None


def test_structural_dependency_path_does_not_assert_graph_reachability():
    class StructuralGraphStore:
        def attack_paths(self, **_kwargs):
            path = AttackPath(
                source="agent:structural",
                target=f"vuln:{KNOWN_CVE}",
                hops=[
                    "agent:structural",
                    "server:demo",
                    "pkg:pypi:demo-lib@1.0.0",
                    f"vuln:{KNOWN_CVE}",
                ],
                edges=["uses", "depends_on", "vulnerable_to"],
                vuln_ids=[KNOWN_CVE],
            )
            return "scan-alpha", "2026-07-27T00:00:00Z", [path], 1

    result = project_persisted_graph_reachability(
        [{"id": "structural", "cve_id": KNOWN_CVE, "finding_node_id": f"vuln:{KNOWN_CVE}"}],
        graph_store=StructuralGraphStore(),  # type: ignore[arg-type]
        tenant_id="tenant-alpha",
        scan_id="scan-alpha",
    )

    assert result.rows[0]["graph_reachable"] is None
    assert result.rows[0]["graph_min_hop_distance"] is None
    assert result.rows[0]["graph_reachable_from_agents"] == []


def test_findings_read_survives_unavailable_graph_backend(wired_client, monkeypatch):
    class UnavailableGraphStore:
        def attack_paths(self, **_kwargs):
            raise NotImplementedError("graph backend unavailable at secret://internal-host")

    monkeypatch.setattr("agent_bom.api.routes.scan._get_graph_store", lambda: UnavailableGraphStore())

    create = wired_client.post("/v1/scan", json={})
    assert create.status_code == 202
    response = wired_client.get("/v1/findings")

    assert response.status_code == 200
    payload = response.json()
    assert payload["findings"]
    assert any("Graph reachability evidence is unavailable" in warning for warning in payload["warnings"])
    assert "secret://internal-host" not in response.text
    assert all(row["graph_reachable"] is None for row in payload["findings"])


def test_findings_read_sheds_with_429_when_backpressure_opens(wired_client, monkeypatch):
    """A saturated in-memory findings read path sheds with 429 + Retry-After.

    The default hub copies and re-sorts the whole current-state table per
    request, so a burst of deep reads can starve ``/health``. Under genuine
    overload the shared adaptive-backpressure guard sheds excess reads instead
    of degrading every route. Mirrors the graph route's shed contract.
    """
    import time

    from agent_bom.api.routes import scan as scan_routes
    from agent_bom.backpressure import reset_backpressure_for_tests

    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_FINDINGS_P99_MS", "1")
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_FINDINGS_MIN_SAMPLES", "1")
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_FINDINGS_COOLDOWN_SECONDS", "30")
    reset_backpressure_for_tests()

    original_impl = scan_routes._list_findings_impl

    def _slow_impl(*args, **kwargs):
        time.sleep(0.01)
        return original_impl(*args, **kwargs)

    monkeypatch.setattr(scan_routes, "_list_findings_impl", _slow_impl)

    try:
        # First read completes and records a latency above the 1ms ceiling,
        # tripping the p99 cooldown; the next read must shed.
        warm = wired_client.get("/v1/findings")
        assert warm.status_code == 200

        shed = wired_client.get("/v1/findings")
        assert shed.status_code == 429
        body = shed.json()["detail"]
        assert body["path"] == "findings"
        assert body["reason"] == "p99_latency_threshold"
        assert int(shed.headers["Retry-After"]) >= 1
    finally:
        reset_backpressure_for_tests()


def test_findings_read_not_shed_under_normal_load(wired_client):
    """Default budgets never trip on ordinary single-reader traffic."""
    from agent_bom.backpressure import describe_backpressure_posture, reset_backpressure_for_tests

    reset_backpressure_for_tests()
    try:
        for _ in range(5):
            resp = wired_client.get("/v1/findings")
            assert resp.status_code == 200
        posture = describe_backpressure_posture()
        findings = next((p for p in posture["paths"] if p["path"] == "findings"), None)
        assert findings is not None
        assert findings["state"] == "closed"
        assert findings["rejected"] == 0
    finally:
        reset_backpressure_for_tests()
