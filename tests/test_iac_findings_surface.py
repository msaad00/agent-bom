"""IaC misconfiguration findings reach the unified stream (parity).

IaC findings were emitted into the JSON side block and SARIF's dedicated IaC
loop but never joined ``AIBOMReport.to_findings()`` — so they under-counted in
exec ``total_findings``, the ``--fail-on-severity`` gate, and CycloneDX. This
pins the fix, and critically asserts each IaC finding still appears exactly ONCE
in SARIF (the dedicated loop remains authoritative; the unified loop skips IaC).
"""

from __future__ import annotations

from agent_bom.finding import FindingType
from agent_bom.models import AIBOMReport
from agent_bom.output.cyclonedx_fmt import to_cyclonedx
from agent_bom.output.sarif import to_sarif


def _report_with_iac() -> AIBOMReport:
    report = AIBOMReport(agents=[], blast_radii=[], findings=[], scan_id="scan-1")
    report.iac_findings_data = {
        "findings": [
            {
                "rule_id": "AVD-AWS-0088",
                "severity": "high",
                "title": "S3 bucket without encryption",
                "message": "S3 bucket 'data' has no server-side encryption configured.",
                "file_path": "infra/s3.tf",
                "line_number": 12,
                "category": "terraform",
                "compliance": ["CIS-2.1.1"],
                "remediation": "Set server_side_encryption_configuration.",
                "attack_techniques": ["T1530"],
            }
        ]
    }
    return report


def test_iac_finding_reaches_unified_stream():
    report = _report_with_iac()
    # Baseline: an empty report has no IaC finding.
    assert not [f for f in AIBOMReport(agents=[], blast_radii=[], findings=[]).to_findings() if f.evidence.get("iac")]

    iac = [f for f in report.to_findings() if f.evidence.get("iac")]
    assert iac, "IaC findings must reach the unified stream"
    finding = iac[0]
    assert finding.finding_type == FindingType.CIS_FAIL
    assert finding.severity == "high"
    assert finding.evidence.get("rule_id") == "AVD-AWS-0088"
    assert finding.security_domain == "cspm"


def test_iac_counts_in_exec_total_and_severity():
    from agent_bom.output.json_fmt import to_json

    report = _report_with_iac()
    payload = to_json(report)
    # total_findings derives from to_findings(); the IaC finding is now counted.
    assert payload["summary"]["total_findings"] >= 1
    assert payload["summary"]["high_unified_findings"] >= 1
    # And it is a real high finding in the serialized unified stream.
    serialized = [f for f in payload["findings"] if isinstance(f.get("evidence"), dict) and f["evidence"].get("iac")]
    assert serialized and serialized[0]["severity"] == "high"


def test_iac_appears_exactly_once_in_sarif():
    report = _report_with_iac()
    sarif = to_sarif(report)
    results = sarif["runs"][0]["results"]
    rule_ids = [r["ruleId"] for r in results]

    # Dedicated IaC loop emits exactly one rich result for the rule.
    assert rule_ids.count("iac/AVD-AWS-0088") == 1
    # The unified non-CVE loop must NOT also emit it as a generic CIS_FAIL result
    # (no other CIS findings in this fixture, so the type must be absent).
    assert "finding/CIS_FAIL" not in rule_ids


def test_iac_idempotent_and_no_double_count():
    report = _report_with_iac()
    first = [f.id for f in report.to_findings()]
    assert len(first) == len(set(first)), "no duplicate ids within one stream"
    second = [f.id for f in report.to_findings()]
    assert first == second, "to_findings() is stable across calls"


def test_iac_not_in_cyclonedx():
    """IaC is not a CVE; it stays out of CycloneDX (package/vuln SBOM) as before."""
    report = _report_with_iac()
    cdx = to_cyclonedx(report)
    vulns = cdx.get("vulnerabilities", []) or []
    assert not any("AVD-AWS-0088" in str(v) for v in vulns)
