"""Every user-visible total reconciles with the breakdown printed beside it.

Two numbers on one screen that describe the same population must derive from
the same basis. A total counted over every row next to a histogram that only
recognises four severity bands reads as "all of these are benign" when the
truth is "we never rated them". An unrated finding needs an explicit bucket,
never a silent drop.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.models import Agent, AgentType, MCPServer

# ── /v1/agents/{name}: total_vulnerabilities vs severity_breakdown ──────────


def _agent_with_unrated_blast() -> list[Agent]:
    return [
        Agent(
            name="unrated-agent",
            agent_type=AgentType.CLAUDE_DESKTOP,
            config_path="/tmp/unrated-config.json",
            mcp_servers=[MCPServer(name="srv", command="npx", args=["-y", "srv"])],
        )
    ]


def _job_store_with_unrated_blast() -> InMemoryJobStore:
    """A scan whose blast radii are mostly advisories with no CVSS score."""
    store = InMemoryJobStore()
    job = ScanJob(
        job_id="job-unrated",
        tenant_id="default",
        status=JobStatus.DONE,
        created_at="2026-08-01T00:00:00Z",
        completed_at="2026-08-01T00:01:00Z",
        request=ScanRequest(),
    )
    blast = [{"severity": "critical", "affected_agents": ["unrated-agent"]}]
    # GHSA advisories routinely carry no CVSS vector at all.
    blast += [{"severity": "unknown", "affected_agents": ["unrated-agent"]} for _ in range(3)]
    blast += [{"severity": "none", "affected_agents": ["unrated-agent"]}]
    blast += [{"severity": "", "affected_agents": ["unrated-agent"]}]
    job.result = {"scan_id": "scan-unrated", "blast_radius": blast}
    store.put(job)
    return store


def test_agent_detail_severity_breakdown_sums_to_total(monkeypatch):
    """``total_vulnerabilities`` must equal the sum of ``severity_breakdown``."""
    monkeypatch.setattr("agent_bom.discovery.discover_all", _agent_with_unrated_blast)
    monkeypatch.setattr("agent_bom.api.routes.discovery._get_store", _job_store_with_unrated_blast)

    resp = TestClient(app).get("/v1/agents/unrated-agent")
    assert resp.status_code == 200
    summary = resp.json()["summary"]

    total = summary["total_vulnerabilities"]
    breakdown = summary["severity_breakdown"]
    assert total == 6
    assert sum(breakdown.values()) == total, (
        f"{total} vulnerabilities reported but the severity breakdown accounts for only {sum(breakdown.values())}: {breakdown}"
    )
    # The five unscored rows land in one explicit bucket, not nowhere.
    assert breakdown["unrated"] == 5


# ── /v1/proxy/alerts: page-scoped summary presented as the estate total ─────


def _write_alert_log(path: Path, count: int, *, tenant_id: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for index in range(count):
            handle.write(
                json.dumps(
                    {
                        "type": "runtime_alert",
                        "tenant_id": tenant_id,
                        "detector": "credential_leak",
                        "severity": "critical" if index % 2 else "low",
                        "event_id": f"log-{index:05d}",
                        "ts": f"2026-07-{(index % 28) + 1:02d}T00:00:00+00:00",
                    }
                )
                + "\n"
            )


@pytest.fixture
def proxy_alert_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from agent_bom.api.routes import proxy as proxy_routes

    proxy_routes._reset_proxy_runtime_for_tests()
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AGENT_BOM_LOG", str(log_path))
    try:
        yield log_path
    finally:
        proxy_routes._reset_proxy_runtime_for_tests()


def test_proxy_alerts_summary_reports_estate_total_not_page_total(proxy_alert_log):
    """The alert summary must describe the estate, like /v1/proxy/metrics does."""
    from agent_bom.api.routes import proxy as proxy_routes

    tenant = "default"
    _write_alert_log(proxy_alert_log, 250, tenant_id=tenant)

    full = proxy_routes._summarize_proxy_alerts(proxy_routes._load_proxy_alerts(tenant))
    assert full["total_alerts"] == 250

    client = TestClient(app)
    resp = client.get("/v1/proxy/alerts", params={"limit": 100})
    assert resp.status_code == 200
    body = resp.json()

    assert len(body["alerts"]) == 100
    assert body["count"] == 100
    assert body["summary"]["total_alerts"] == full["total_alerts"], (
        "the summary beside a 100-row page claims the whole estate holds only "
        f"{body['summary']['total_alerts']} alerts, while /v1/proxy/metrics "
        f"reports {full['total_alerts']}"
    )
    assert body["summary"]["alerts_by_severity"] == full["alerts_by_severity"]


def test_proxy_alerts_severity_filter_does_not_claim_a_uniform_estate(proxy_alert_log):
    """Filtering to one severity must not make the histogram 100% that severity."""
    tenant = "default"
    _write_alert_log(proxy_alert_log, 40, tenant_id=tenant)

    resp = TestClient(app).get("/v1/proxy/alerts", params={"severity": "critical"})
    assert resp.status_code == 200
    by_sev = resp.json()["summary"]["alerts_by_severity"]

    assert by_sev.get("low"), f"a severity-filtered view reports a whole-estate histogram of {by_sev} — the estate is not 100% critical"


# ── CIS posture verdict: PASS with zero controls evaluated ─────────────────


_ALL_NOT_APPLICABLE = [
    {"check_id": "1.1", "title": "Bucket encryption", "status": "not_applicable", "severity": "high"},
    {"check_id": "1.2", "title": "DB backups", "status": "not_applicable", "severity": "medium"},
]
_PASS_PLUS_ERROR = [
    {"check_id": "1.1", "title": "Bucket encryption", "status": "pass", "severity": "high"},
    {"check_id": "1.2", "title": "DB backups", "status": "error", "severity": "high"},
]


def _report_with_cis(checks: list[dict]):
    """A report carrying one non-cloud CIS bundle (no fail-closed rewrite)."""
    from agent_bom.models import AIBOMReport

    report = AIBOMReport()
    report.databricks_security_data = {
        "checks": checks,
        "passed": sum(1 for c in checks if c["status"] == "pass"),
        "failed": sum(1 for c in checks if c["status"] == "fail"),
        "pass_rate": 0.0,
    }
    return report


def _rendered_html_verdict(checks: list[dict]) -> str:
    import re

    from agent_bom.output.html.sections import _cis_benchmark_section

    html = _cis_benchmark_section(_report_with_cis(checks))
    match = re.search(r">(NOT EVALUATED|INCOMPLETE|ERROR|PASS|\w+ GAPS)<", html)
    return match.group(1) if match else ""


def test_html_cis_verdict_is_not_pass_when_nothing_was_evaluated():
    """An account with no in-scope resources evaluated zero controls."""
    verdict = _rendered_html_verdict(_ALL_NOT_APPLICABLE)
    assert verdict != "PASS", "the HTML report prints a green PASS beside '0% pass (0/0 checks)' — zero controls were actually evaluated"
    assert verdict == "NOT EVALUATED"


@pytest.mark.parametrize(
    "checks",
    [
        _ALL_NOT_APPLICABLE,
        _PASS_PLUS_ERROR,
        [{"check_id": "2.1", "title": "t", "status": "error", "severity": "low"}],
        [{"check_id": "3.1", "title": "t", "status": "pass", "severity": "low"}],
        [{"check_id": "4.1", "title": "t", "status": "fail", "severity": "critical"}],
    ],
)
def test_console_cis_verdict_matches_the_html_verdict(checks, monkeypatch):
    """One scan cannot render two different verdicts on two surfaces."""
    import re

    from rich.console import Console

    from agent_bom import output as output_mod
    from agent_bom.output import console_render

    # ``print_cis_findings`` writes to the shared ``agent_bom.output.console``.
    # Swap in a recording console so capture does not depend on which other
    # test last touched that global.
    recorder = Console(record=True, width=200, no_color=True, force_terminal=False)
    monkeypatch.setattr(output_mod, "console", recorder)

    console_render.print_cis_findings(_report_with_cis(checks))
    out = recorder.export_text()
    match = re.search(r"(NOT EVALUATED|INCOMPLETE|ERROR|PASS|\w+ GAPS)", out)
    console_verdict = match.group(1) if match else ""

    assert console_verdict, f"console rendered no verdict at all for {checks}"
    assert console_verdict == _rendered_html_verdict(checks), (
        f"console rendered {console_verdict!r} where HTML rendered {_rendered_html_verdict(checks)!r} for the same checks"
    )


# ── Markdown report: severity rows never sum to the totals above them ──────


def test_severity_counts_never_drops_a_finding():
    """The shared histogram must account for every finding it is handed."""
    from agent_bom.output.finding_views import severity_counts

    findings = _findings_across_bands()
    counts = severity_counts(findings)
    assert sum(counts.values()) == len(findings), (
        f"severity_counts dropped {len(findings) - sum(counts.values())} of {len(findings)} findings: {counts}"
    )


def test_markdown_summary_rows_account_for_every_finding():
    """The severity rows must account for the totals printed directly above."""
    import re

    from agent_bom.models import AIBOMReport
    from agent_bom.output.markdown import to_markdown

    report = AIBOMReport()
    report.findings = _findings_across_bands()

    md = to_markdown(report)
    rows = dict(re.findall(r"^\| (Critical|High|Medium|Low|Info|Unrated) \| (\d+) \|$", md, re.M))
    policy_total = int(re.search(r"^\| Policy/security findings \| (\d+) \|$", md, re.M).group(1))

    assert policy_total == 4
    assert sum(int(v) for v in rows.values()) == policy_total, (
        f"the summary table reports {policy_total} findings above severity rows that sum to {sum(int(v) for v in rows.values())}: {rows}"
    )
    # ``info`` is rated-and-benign; ``none``/``unknown`` were never rated at all.
    assert rows.get("Info") == "1"
    assert rows.get("Unrated") == "2"


def _findings_across_bands() -> list:
    """One rated finding plus three the scanners could not rate."""
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType

    return [
        Finding(
            finding_type=FindingType.MCP_BLOCKLIST,
            source=FindingSource.MCP_SCAN,
            asset=Asset(name=f"srv-{idx}", asset_type="mcp_server"),
            severity=sev,
            title=f"finding {idx}",
        )
        for idx, sev in enumerate(["critical", "unknown", "none", "info"])
    ]
