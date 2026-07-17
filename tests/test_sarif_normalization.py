"""Canonical SARIF normalization contracts shared by all ingest lanes."""

from __future__ import annotations

import pytest

from agent_bom.compliance_hub_ingest import parse_sarif_document
from agent_bom.models import Severity
from agent_bom.parsers.sarif import SarifValidationError, normalize_sarif_document
from agent_bom.sast import SASTScanError, _parse_sarif_findings, scan_code


def _run(tool: str, rule_id: str, *, located: bool) -> dict:
    result = {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": f"{tool} finding"},
        "properties": {"security-severity": "8.2"},
        "fingerprints": {"primaryLocationLineHash": f"{tool}-full"},
        "partialFingerprints": {"primaryLocationStartColumnFingerprint": f"{tool}-partial"},
    }
    if located:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"src/{tool}.py"},
                    "region": {"startLine": 7, "snippet": {"text": "danger()"}},
                }
            }
        ]
    return {
        "tool": {
            "driver": {
                "name": tool,
                "rules": [
                    {
                        "id": rule_id,
                        "helpUri": f"https://example.invalid/{rule_id}",
                        "properties": {"tags": ["CWE-79", "security"]},
                    }
                ],
            }
        },
        "results": [result],
    }


def test_normalize_preserves_multiple_runs_provenance_and_evidence() -> None:
    document = normalize_sarif_document(
        {
            "version": "2.1.0",
            "runs": [
                _run("CodeQL", "js/xss", located=True),
                _run("Bandit", "B105", located=False),
            ],
        }
    )

    assert document.rules_loaded == 2
    assert document.files_scanned == 1
    assert document.tool_names == ("CodeQL", "Bandit")
    assert len(document.results) == 2

    codeql, bandit = document.results
    assert codeql.tool_name == "CodeQL"
    assert codeql.security_severity == 8.2
    assert codeql.location is not None
    assert codeql.location.uri == "src/CodeQL.py"
    assert codeql.location.snippet == "danger()"
    assert codeql.fingerprints == {"primaryLocationLineHash": "CodeQL-full"}
    assert codeql.partial_fingerprints == {"primaryLocationStartColumnFingerprint": "CodeQL-partial"}

    assert bandit.tool_name == "Bandit"
    assert bandit.location is None
    assert bandit.rule_tags == ("CWE-79", "security")


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"version": "2.1.0", "runs": {}},
        {"version": "2.1.0", "runs": ["not-a-run"]},
        {"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": []}]},
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "tool"}}, "results": {}}],
        },
    ],
)
def test_normalize_rejects_structurally_invalid_documents(payload: object) -> None:
    with pytest.raises(SarifValidationError):
        normalize_sarif_document(payload)


def test_rule_level_security_severity_is_used_as_fallback() -> None:
    run = _run("CodeQL", "js/xss", located=True)
    result = run["results"][0]
    del result["properties"]
    run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = "9.1"

    document = normalize_sarif_document({"version": "2.1.0", "runs": [run]})

    assert document.results[0].security_severity == 9.1


def test_external_finding_projection_keeps_tool_score_fingerprints_and_locationless() -> None:
    findings = parse_sarif_document(
        {
            "version": "2.1.0",
            "runs": [
                _run("CodeQL", "js/xss", located=True),
                _run("Bandit", "B105", located=False),
            ],
        }
    )

    assert [finding.evidence["external_tool"] for finding in findings] == ["CodeQL", "Bandit"]
    assert findings[0].severity == "high"
    assert findings[0].cvss_score == 8.2
    assert findings[0].evidence["sarif_fingerprints"] == {"primaryLocationLineHash": "CodeQL-full"}
    assert findings[0].evidence["sarif_partial_fingerprints"] == {"primaryLocationStartColumnFingerprint": "CodeQL-partial"}
    assert findings[1].asset.asset_type == "external"
    assert findings[1].asset.location is None


def test_sast_projection_uses_same_evidence_boundary() -> None:
    findings, rules_loaded, files_scanned = _parse_sarif_findings(
        {
            "version": "2.1.0",
            "runs": [
                _run("CodeQL", "js/xss", located=True),
                _run("Bandit", "B105", located=False),
            ],
        }
    )

    assert rules_loaded == 2
    assert files_scanned == 1
    assert findings[0].tool_name == "CodeQL"
    assert findings[0].security_severity == 8.2
    assert findings[0].severity == Severity.HIGH
    assert findings[0].fingerprints == {"primaryLocationLineHash": "CodeQL-full"}
    assert findings[1].file_path == "unknown"


def test_sast_file_import_fails_closed_on_json_array(tmp_path) -> None:
    path = tmp_path / "invalid.sarif"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(SASTScanError, match="invalid SARIF file"):
        scan_code(str(path))
