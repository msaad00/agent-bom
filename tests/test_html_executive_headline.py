"""The HTML report opens with an honest one-paragraph executive headline."""

from __future__ import annotations

import html as html_lib
import re

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.output.html.sections import _executive_headline_section


def _finding(title: str, severity: str, *, agents: list[str] | None = None, owner: str | None = None, risk: float = 0.0) -> Finding:
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.SBOM,
        asset=Asset(name="svc", asset_type="package", identifier=title),
        severity=severity,
        title=title,
        description="test",
        cve_id=title.split(":")[0],
        risk_score=risk,
    )
    finding.affected_agents = list(agents or [])
    finding.owner = owner
    return finding


def _text(section: str) -> str:
    return html_lib.unescape(re.sub(r"<[^>]+>", " ", section))


def test_headline_names_top_risks_reach_owner_and_boundary() -> None:
    findings = [
        _finding("CVE-2026-0001: langchain@0.0.150", "critical", agents=["research-agent"], risk=9.1),
        _finding("CVE-2026-0002: requests@2.28.0", "medium", owner="appsec-team", risk=4.0),
    ]
    section = _executive_headline_section(findings, [])
    text = " ".join(_text(section).split())
    assert 'id="executive-headline"' in section
    assert "1 of 2 findings reach at least one AI agent" in text
    # Ranked worst-first; each risk states agents reached, owner and SLA.
    assert text.index("CVE-2026-0001") < text.index("CVE-2026-0002")
    assert "reaches research-agent" in text
    assert "owner unassigned" in text
    assert "owner appsec-team" in text
    assert "SLA due" in text
    assert "not a compliance certification" in text


def test_headline_escapes_untrusted_titles() -> None:
    section = _executive_headline_section([_finding("CVE-2026-0003: <script>alert(1)</script>", "high")], [])
    assert "<script>alert(1)</script>" not in section


def test_headline_for_an_empty_scan_claims_nothing() -> None:
    text = _text(_executive_headline_section([], []))
    assert "No findings were recorded" in text
    assert "not a claim that unscanned" in text


def test_full_report_renders_the_headline_before_the_summary_cards() -> None:
    from datetime import datetime, timezone

    from agent_bom.models import AIBOMReport
    from agent_bom.output.html import to_html

    report = AIBOMReport(agents=[], blast_radii=[], generated_at=datetime(2026, 9, 20, tzinfo=timezone.utc))
    page = to_html(report, [])
    assert 'id="executive-headline"' in page
    assert page.index('id="executive-headline"') < page.index('id="summary"')
