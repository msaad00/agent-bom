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
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import JobStatus
from agent_bom.api.pipeline import _now, _persist_graph_snapshot
from agent_bom.api.server import _jobs, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_graph_store
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
    pkg = Package(name="demo-lib", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
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
    return to_json(AIBOMReport(agents=[agent], blast_radii=[blast]))


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
    set_graph_store(SQLiteGraphStore(tmp_path / "graph.db"))

    report_json = _report_with_known_vuln()

    def _complete_synchronously(job) -> None:
        job.status = JobStatus.DONE
        job.result = report_json
        job.completed_at = _now()
        store.put(job)
        _persist_graph_snapshot(job, report_json)

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
    finding_vulns = {row.get("vulnerability_id") for row in findings.json()["findings"]}
    assert KNOWN_CVE in finding_vulns, f"known vuln missing from findings: {finding_vulns}"

    attack_paths = wired_client.get("/v1/graph/attack-paths")
    assert attack_paths.status_code == 200
    paths = attack_paths.json()["attack_paths"]
    assert paths, "expected at least one derived attack path for the known vuln"
    path_vuln_ids = {vid for path in paths for vid in (path.get("vuln_ids") or [])}
    assert KNOWN_CVE in path_vuln_ids, f"known vuln missing from attack paths: {path_vuln_ids}"


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
