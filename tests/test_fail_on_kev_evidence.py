"""`--fail-on-kev` must either find KEV evidence itself or say how to get it.

Without `--enrich` nothing fetched the KEV catalog, so the gate always failed
closed with "KEV evidence unavailable" — and under `-q` it printed nothing at
all, leaving a bare exit 1.
"""

from __future__ import annotations

import asyncio
from io import StringIO

import pytest
from rich.console import Console

from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._post import compute_exit_code
from agent_bom.enrichment_posture import describe_enrichment_posture, reset_enrichment_posture_for_tests
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability


@pytest.fixture(autouse=True)
def _clean_posture():
    reset_enrichment_posture_for_tests()
    yield
    reset_enrichment_posture_for_tests()


def _blast_radius(cve: str = "CVE-2024-0001") -> BlastRadius:
    return BlastRadius(
        vulnerability=Vulnerability(id=cve, summary="x", severity=Severity.HIGH),
        package=Package(name="pkg", version="1.0.0", ecosystem="pypi"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
        risk_score=5.0,
    )


def _compute(ctx: ScanContext, *, quiet: bool) -> int:
    return compute_exit_code(
        ctx,
        fail_on_severity=None,
        warn_on_severity=None,
        fail_on_kev=True,
        fail_if_ai_risk=False,
        push_url=None,
        push_api_key=None,
        quiet=quiet,
    )


@pytest.mark.parametrize("quiet", [False, True])
def test_unavailable_kev_evidence_prints_an_actionable_hint_in_every_mode(quiet: bool, capsys) -> None:
    buffer = StringIO()
    ctx = ScanContext(
        con=Console(file=buffer, force_terminal=False, width=300),
        blast_radii=[_blast_radius()],
        enrichment_posture={"sources": [{"source": "cisa_kev", "status": "unknown"}]},
    )

    assert _compute(ctx, quiet=quiet) == 1

    text = buffer.getvalue() + capsys.readouterr().err
    assert "KEV evidence is unavailable" in text
    assert "agent-bom db update" in text
    assert "--enrich" in text


def test_fresh_local_db_kev_counts_as_evidence() -> None:
    """The help promises offline from the local DB; a fresh DB that carries KEV proves the gate."""
    from agent_bom.models import AIBOMReport

    report = AIBOMReport()
    report.vuln_data_freshness = {"sources": ["OSV", "KEV"], "stale": False}
    ctx = ScanContext(
        con=Console(file=StringIO(), force_terminal=False),
        blast_radii=[_blast_radius()],
        report=report,
        enrichment_posture={"sources": [{"source": "cisa_kev", "status": "unknown"}]},
    )

    assert _compute(ctx, quiet=True) == 0


def test_stale_local_db_kev_is_not_evidence() -> None:
    from agent_bom.models import AIBOMReport

    report = AIBOMReport()
    report.vuln_data_freshness = {"sources": ["OSV", "KEV"], "stale": True}
    ctx = ScanContext(
        con=Console(file=StringIO(), force_terminal=False),
        blast_radii=[_blast_radius()],
        report=report,
        enrichment_posture={"sources": [{"source": "cisa_kev", "status": "unknown"}]},
    )

    assert _compute(ctx, quiet=True) == 1


def test_join_kev_catalog_marks_kev_and_records_evidence(monkeypatch) -> None:
    from agent_bom import enrichment

    async def fake_fetch(_client):
        enrichment.record_enrichment_source("cisa_kev", "success")
        return {"CVE-2021-44228": {"date_added": "2021-12-10", "due_date": "2021-12-24"}}

    monkeypatch.setattr(enrichment, "fetch_cisa_kev_catalog", fake_fetch)
    hit = Vulnerability(id="GHSA-jfh8-c2jp-5v3q", summary="x", severity=Severity.CRITICAL, aliases=["CVE-2021-44228"])
    miss = Vulnerability(id="CVE-2024-0001", summary="x", severity=Severity.HIGH)

    joined = asyncio.run(enrichment.join_kev_catalog([hit, miss], offline=False))

    assert joined == 1
    assert hit.is_kev is True and hit.kev_due_date == "2021-12-24"
    assert miss.is_kev is False
    status = {row["source"]: row["status"] for row in describe_enrichment_posture()["sources"]}
    assert status["cisa_kev"] == "ok"


def test_join_kev_catalog_offline_makes_no_network_call(monkeypatch) -> None:
    from agent_bom import enrichment

    async def boom(_client):
        raise AssertionError("offline KEV join must not fetch")

    monkeypatch.setattr(enrichment, "fetch_cisa_kev_catalog", boom)
    monkeypatch.setattr(enrichment, "_cached_kev_catalog", lambda **_k: {})

    assert asyncio.run(enrichment.join_kev_catalog([Vulnerability(id="CVE-1", summary="", severity=Severity.LOW)], offline=True)) == 0
