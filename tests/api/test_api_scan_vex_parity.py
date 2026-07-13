"""API scan alignment: VEX + reachability projection and CLI parity flags (#2918, #3499)."""

from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _now, _run_scan_sync
from agent_bom.api.routes.scan import _finding_from_blast_radius, _iter_scan_findings
from agent_bom.api.server import _jobs, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output.sarif import to_sarif
from tests.test_external_scanners import TRIVY_BASIC


def _scan_job(**request_kwargs) -> ScanJob:
    return ScanJob(
        job_id="alignment-scan",
        created_at="2026-07-06T00:00:00Z",
        request=ScanRequest(**request_kwargs),
    )


def test_finding_from_blast_radius_projects_reachability_and_vex_fields():
    job = _scan_job()
    item = {
        "vulnerability_id": "CVE-2024-7000",
        "package": "demo-lib@1.0.0",
        "severity": "high",
        "risk_score": 0.0,
        "graph_reachable": True,
        "symbol_reachability": "reachable",
        "reachable_affected_symbols": ["main.handler"],
        "match_confidence_tier": "high",
        "vex_status": "fixed",
        "vex_justification": None,
    }
    row = _finding_from_blast_radius(item, job)
    assert row["graph_reachable"] is True
    assert row["symbol_reachability"] == "reachable"
    assert row["reachable_affected_symbols"] == ["main.handler"]
    assert row["match_confidence_tier"] == "high"
    assert row["vex_status"] == "fixed"
    assert row["vex_suppressed"] is True


def test_iter_scan_findings_prefers_unified_stream_over_blast_radius():
    job = _scan_job()
    job.result = {
        "findings": [
            {
                "id": "CVE-2024-7001:requests",
                "vulnerability_id": "CVE-2024-7001",
                "cve_id": "CVE-2024-7001",
                "package": "requests",
                "severity": "medium",
                "match_confidence_tier": "medium",
                "evidence": {"symbol_reachability": "unreachable"},
            }
        ],
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-7001",
                "package": "requests",
                "severity": "high",
                "symbol_reachability": "reachable",
            }
        ],
    }
    rows = _iter_scan_findings(job)
    assert len(rows) == 1
    assert rows[0]["match_confidence_tier"] == "medium"
    assert rows[0]["evidence"]["symbol_reachability"] == "unreachable"
    assert rows[0].get("symbol_reachability") != "reachable"


def test_iter_scan_findings_collapses_three_representations_to_canonical():
    """Regression for #3883: the unified/blast/package trio for one CVE folds
    to a single list row that carries non-null cve_id/title/finding_type, with
    package metadata backfilled but reachability left to the unified stream."""
    job = _scan_job()
    job.result = {
        "agents": [
            {
                "name": "agent-x",
                "mcp_servers": [
                    {
                        "name": "srv",
                        "packages": [
                            {
                                "name": "requests",
                                "version": "2.28.0",
                                "ecosystem": "pypi",
                                "vulnerabilities": [
                                    {
                                        "id": "CVE-2024-9999",
                                        "severity": "high",
                                        "summary": "boom",
                                        "cvss_score": 7.5,
                                        "fixed_version": "2.31.0",
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ],
        # Unified stream: the richest representation, already normalized.
        "findings": [
            {
                "id": "b1e2c3d4-0000-0000-0000-000000000001",
                "cve_id": "CVE-2024-9999",
                "title": "CVE-2024-9999: requests@2.28.0",
                "finding_type": "CVE",
                "severity": "high",
                "match_confidence_tier": "high",
                "evidence": {"symbol_reachability": "unreachable"},
                "asset": {"name": "srv", "asset_type": "mcp_server"},
            }
        ],
        # Blast-radius projection: identifier only under vulnerability_id, no
        # title/finding_type, plus a coarser (over-claiming) reachability signal.
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-9999",
                "package": "requests@2.28.0",
                "severity": "high",
                "symbol_reachability": "reachable",
                "graph_reachable": True,
            }
        ],
    }

    rows = _iter_scan_findings(job)

    # One row per canonical id — not three representations.
    cve_rows = [r for r in rows if (r.get("cve_id") or r.get("vulnerability_id")) == "CVE-2024-9999"]
    assert len(cve_rows) == 1
    row = cve_rows[0]

    # Every identifier is populated (no null cve_id / title / finding_type).
    assert row["cve_id"] == "CVE-2024-9999"
    assert row["title"] == "CVE-2024-9999: requests@2.28.0"
    assert row["finding_type"] == "CVE"

    # Package + descriptive metadata backfilled from the supplementary reps.
    assert row.get("package")
    assert row.get("ecosystem") == "pypi"
    assert row.get("fixed_version") == "2.31.0"

    # Unified stream stays authoritative for reachability/confidence — the
    # blast-radius "reachable" claim must not override the unified verdict.
    assert row["match_confidence_tier"] == "high"
    assert row["evidence"]["symbol_reachability"] == "unreachable"
    assert row.get("symbol_reachability") != "reachable"

    # Invariant across the whole page: no null identifiers, no duplicate groups.
    assert all(r.get("title") for r in rows)
    assert all(r.get("finding_type") for r in rows)
    assert all(r.get("cve_id") for r in rows if r.get("finding_type") == "CVE")
    from agent_bom.api.routes.scan import _canonical_group_key

    keys = [_canonical_group_key(r) for r in rows]
    assert len(keys) == len(set(keys))


def test_iter_scan_findings_normalizes_blast_only_finding_identifiers():
    """A vuln present only as a blast-radius row still surfaces cve_id/title/
    finding_type after normalization (no null identifiers)."""
    job = _scan_job()
    job.result = {
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-8888",
                "package": "urllib3@1.26.0",
                "severity": "high",
            }
        ]
    }
    rows = _iter_scan_findings(job)
    assert len(rows) == 1
    row = rows[0]
    assert row["cve_id"] == "CVE-2024-8888"
    assert row["vulnerability_id"] == "CVE-2024-8888"
    assert row["title"] == "CVE-2024-8888: urllib3@1.26.0"
    assert row["finding_type"] == "CVE"


def test_api_pipeline_ingests_external_scan(monkeypatch, tmp_path):
    class _DummyStore:
        def __init__(self) -> None:
            self.jobs: list[ScanJob] = []

        def put(self, job: ScanJob) -> None:
            self.jobs.append(job)

    external_path = tmp_path / "trivy.json"
    external_path.write_text(json.dumps(TRIVY_BASIC), encoding="utf-8")

    store = _DummyStore()
    job = ScanJob(
        job_id="external-scan-parity",
        created_at="2026-07-06T00:00:00Z",
        request=ScanRequest(external_scan=str(external_path), enrich=False, no_scan=True),
    )

    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: store)
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda _agents, tenant_id="default": None)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *args, **kwargs: [])

    _run_scan_sync(job)

    assert job.status == JobStatus.DONE
    assert job.result is not None
    agent_names = [agent["name"] for agent in job.result["agents"]]
    assert any(name.startswith("external-scan:") for name in agent_names)
    ext_agent = next(agent for agent in job.result["agents"] if agent["name"].startswith("external-scan:"))
    pkg_names = {pkg["name"] for server in ext_agent["mcp_servers"] for pkg in server.get("packages", [])}
    assert "requests" in pkg_names


def test_api_pipeline_applies_vex_and_rebuilds_findings(monkeypatch, tmp_path):
    class _DummyStore:
        def __init__(self) -> None:
            self.jobs: list[ScanJob] = []

        def put(self, job: ScanJob) -> None:
            self.jobs.append(job)

    vuln = Vulnerability(id="CVE-2024-7100", summary="Test vuln", severity=Severity.HIGH, cvss_score=8.0)
    pkg = Package(name="requests", version="2.27.0", ecosystem="pypi", vulnerabilities=[vuln])
    server = MCPServer(name="demo-server", command="python", packages=[pkg])
    agent = Agent(
        name="demo-agent",
        agent_type=AgentType.CUSTOM,
        config_path="/tmp/demo.json",
        mcp_servers=[server],
    )
    blast = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    blast.calculate_risk_score()

    vex_path = tmp_path / "vex.json"
    vex_path.write_text(
        json.dumps(
            {
                "statements": [
                    {
                        "vulnerability_id": "CVE-2024-7100",
                        "status": "not_affected",
                        "justification": "component_not_present",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    store = _DummyStore()
    job = ScanJob(
        job_id="vex-parity",
        created_at="2026-07-06T00:00:00Z",
        request=ScanRequest(vex=str(vex_path), enrich=False),
    )

    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: store)
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda _agents, tenant_id="default": None)
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *args, **kwargs: [agent])
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda agents, enable_enrichment=False, **kwargs: [blast])

    _run_scan_sync(job)

    assert job.status == JobStatus.DONE
    assert job.result is not None
    assert job.result.get("vex") is not None
    finding = job.result["findings"][0]
    assert finding["suppressed"] is True
    assert finding["evidence"]["vex_status"] == "not_affected"
    assert finding["evidence"]["vex_justification"] == "component_not_present"
    br_item = job.result["blast_radius"][0]
    assert br_item["vex_status"] == "not_affected"
    assert br_item["vex_suppressed"] is True


def test_sarif_emits_vex_properties_from_finding_evidence():
    from agent_bom.finding import blast_radius_to_finding
    from agent_bom.models import AIBOMReport

    vuln = Vulnerability(id="CVE-2024-7200", summary="VEX SARIF", severity=Severity.MEDIUM)
    vuln.vex_status = "not_affected"
    vuln.vex_justification = "component_not_present"
    pkg = Package(name="lib", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    finding = blast_radius_to_finding(br)
    report = AIBOMReport(agents=[], blast_radii=[br], findings=[finding])
    doc = to_sarif(report)
    result = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "CVE-2024-7200")
    props = result["properties"]
    assert props["vex_status"] == "not_affected"
    assert props["vex_justification"] == "component_not_present"


@pytest.fixture
def findings_client(monkeypatch):
    store = InMemoryJobStore()
    set_job_store(store)
    _jobs.clear()

    job = ScanJob(job_id="list-findings-vex", created_at=_now(), request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = _now()
    job.result = {
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-7300",
                "package": "pkg@1.0.0",
                "severity": "high",
                "risk_score": 0.0,
                "graph_reachable": False,
                "symbol_reachability": "unreachable",
                "reachable_affected_symbols": [],
                "match_confidence_tier": "low",
                "vex_status": "not_affected",
                "vex_justification": "component_not_present",
            }
        ]
    }
    store.put(job)
    _jobs[job.job_id] = job

    try:
        yield TestClient(app, raise_server_exceptions=False)
    finally:
        _jobs.clear()


def test_list_findings_api_surfaces_blast_radius_vex_and_reachability(findings_client):
    response = findings_client.get("/v1/findings")
    assert response.status_code == 200
    row = next(item for item in response.json()["findings"] if item["vulnerability_id"] == "CVE-2024-7300")
    assert row["graph_reachable"] is False
    assert row["symbol_reachability"] == "unreachable"
    assert row["match_confidence_tier"] == "low"
    assert row["vex_status"] == "not_affected"
    assert row["vex_justification"] == "component_not_present"
    assert row["vex_suppressed"] is True
