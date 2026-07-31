"""The HTML report is the artifact handed to an auditor — it must not overclaim.

It carried its own copy of "a control with no mapped finding passes", so a scan
over a zero-finding estate rendered "Compliance Posture Score: 100.0% PASS" with
hundreds of green PASS badges, including MITRE ATT&CK scored 413/413 pass —
a framework the REST API reports as an applicability OVERLAY that can never
pass.
"""

from __future__ import annotations

from agent_bom.output.html.sections import _compliance_section


def _finding(*, severity: str = "high", attack_tags: list[str] | None = None, owasp_tags: list[str] | None = None):
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType
    from agent_bom.models import Severity

    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.SBOM,
        asset=Asset(name="demo", asset_type="package", identifier="demo@1.0.0"),
        severity=Severity(severity),
        title="CVE-2026-0001",
        description="test",
        cve_id="CVE-2026-0001",
    )
    finding.owasp_tags = list(owasp_tags or [])
    finding.attack_tags = list(attack_tags or [])
    return finding


def _headline(html: str) -> str:
    """The `Score: … BADGE` sup, which is what a reader sees first."""
    return html.split('<div class="panel">')[0]


def test_zero_finding_estate_never_renders_a_passing_posture() -> None:
    html = _compliance_section([])

    assert "Score: 0.0%" in html, "an unevaluated estate was scored"
    assert "PASS</span>" not in html, "green PASS badges over an estate with nothing evaluated"
    # The headline badge reads the no-data state, not a pass.
    assert "NOT EVALUATED" in _headline(html)
    assert "no control was evaluated" in html


def test_attack_is_an_overlay_and_never_scored_as_pass_fail() -> None:
    """ATT&CK applicability must not inflate the posture score.

    413 techniques with no mapped finding used to count as 413 passes, which is
    both a false green and a denominator that drowns every real framework.
    """
    html = _compliance_section([_finding(owasp_tags=["LLM01"], attack_tags=["T1059"])])

    assert "MITRE ATT&amp;CK Enterprise" in html or "MITRE ATT&CK Enterprise" in html
    # The overlay reports applicability, never a pass rate.
    assert "413/413 pass" not in html
    assert "applicable" in html.lower()


def test_an_evaluated_failure_still_scores_and_fails() -> None:
    """The honesty fix must not pin the score at zero for a real evaluation."""
    html = _compliance_section([_finding(severity="high", owasp_tags=["LLM01"])])

    assert "FAIL</span>" in html
    assert "Score: 0.0%" in html  # 0 passes out of 1 evaluated control
    # The headline is a real FAIL verdict, not the no-data state — and it says
    # how little of the catalogue that verdict rests on.
    assert "FAIL</span>" in _headline(html)
    assert "NOT EVALUATED" not in _headline(html)
    assert "1 of " in _headline(html) and "controls evaluated" in _headline(html)
