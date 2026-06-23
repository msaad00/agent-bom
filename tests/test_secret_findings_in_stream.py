"""Hardcoded-secret findings must reach the unified Finding stream (JSON/SARIF), redacted."""

from agent_bom.finding import FindingSource, FindingType, secret_dict_to_finding
from agent_bom.models import AIBOMReport

_SECRET = {
    "file": "config/app.py",
    "line": 12,
    "type": "AWS Access Key",
    "severity": "critical",
    "preview": "AKIA****REDACTED",
    "category": "credential",
}


def test_secret_dict_to_finding_redacted_no_value():
    f = secret_dict_to_finding(_SECRET)
    assert f.finding_type == FindingType.CREDENTIAL_EXPOSURE
    assert f.source == FindingSource.SECRET_SCAN
    assert f.severity == "CRITICAL"
    assert f.asset.location == "config/app.py"
    # The redacted preview is carried; no raw secret bytes anywhere.
    blob = str(f.to_dict())
    assert "AKIA****REDACTED" in blob
    assert "Hardcoded credential" in f.title


def test_secret_dict_to_finding_never_trusts_raw_preview():
    raw_secret = {
        **_SECRET,
        "preview": "not-a-real-but-still-raw-secret-value",
    }
    f = secret_dict_to_finding(raw_secret)
    blob = str(f.to_dict())
    assert "not-a-real-but-still-raw-secret-value" not in blob
    assert f.evidence["redacted_preview"] == "***REDACTED***"


def test_to_findings_includes_secrets_alongside_cves():
    report = AIBOMReport(agents=[], blast_radii=[])
    report.ai_inventory_data = {"secrets": {"findings": [_SECRET], "total": 1}}
    findings = report.to_findings()
    secret_findings = [f for f in findings if f.finding_type == FindingType.CREDENTIAL_EXPOSURE]
    assert len(secret_findings) == 1
    assert secret_findings[0].asset.location == "config/app.py"


def test_to_findings_no_secrets_block_is_noop():
    report = AIBOMReport(agents=[], blast_radii=[])
    assert report.to_findings() == []  # empty report, no secrets, no crash


def test_to_findings_dedupes_secret_findings_by_id():
    secret_finding = secret_dict_to_finding(_SECRET)
    report = AIBOMReport(agents=[], blast_radii=[], findings=[secret_finding])
    report.ai_inventory_data = {"secrets": {"findings": [_SECRET], "total": 1}}
    findings = report.to_findings()
    secret_findings = [f for f in findings if f.finding_type == FindingType.CREDENTIAL_EXPOSURE]
    assert len(secret_findings) == 1
    assert secret_findings[0].id == secret_finding.id


def test_secret_findings_in_json_output():
    import json

    from agent_bom.output.json_fmt import to_json

    report = AIBOMReport(agents=[], blast_radii=[])
    report.ai_inventory_data = {"secrets": {"findings": [_SECRET], "total": 1}}
    raw = to_json(report)
    data = raw if isinstance(raw, dict) else json.loads(raw)
    fts = [f.get("finding_type") for f in data.get("findings", [])]
    assert "CREDENTIAL_EXPOSURE" in fts
    # The raw value never appears; redacted preview is fine.
    assert "AKIA" not in json.dumps(data).replace("AKIA****REDACTED", "")
