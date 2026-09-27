from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.finding_scope import domain_for_row
from agent_bom.findings_push import load_push_findings, load_push_findings_file, packages_to_bulk_findings
from agent_bom.parsers.external_scanners import parse_trivy_json
from tests.test_external_scanners import TRIVY_BASIC


def test_packages_to_bulk_findings_projects_scanner_rows() -> None:
    packages = parse_trivy_json(TRIVY_BASIC)
    findings = packages_to_bulk_findings(packages, source="trivy-ci")

    assert findings
    assert findings[0]["source"] == "trivy-ci"
    assert findings[0]["origin"] == "bulk_ingest"
    assert findings[0]["finding_type"] == "CVE"
    assert domain_for_row(findings[0]) == "vuln"
    assert findings[0]["package_name"] == packages[0].name
    assert findings[0]["vulnerability_id"]


def test_load_push_findings_accepts_embedded_findings_array() -> None:
    payload = {"findings": [{"id": "finding-1", "severity": "high", "package": "requests"}]}
    rows = load_push_findings(payload)
    assert rows == payload["findings"]


def test_load_push_findings_accepts_scanner_json() -> None:
    rows = load_push_findings(TRIVY_BASIC, source="trivy")
    assert rows
    assert rows[0]["source"] == "trivy"


def test_load_push_findings_accepts_sarif_json() -> None:
    from tests.test_external_scanners import SARIF_BASIC

    rows = load_push_findings(SARIF_BASIC, source="bandit")
    assert len(rows) == 1
    assert "package" not in rows[0]
    assert rows[0]["finding_type"] == "SAST"
    assert rows[0]["asset"]["asset_type"] == "source_file"
    assert rows[0]["evidence"]["rule_id"] == "B105"
    assert rows[0]["evidence"]["file"] == "src/app.py"
    assert rows[0]["source"] == "bandit"


def test_load_push_findings_file(tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([{"id": "finding-2", "severity": "medium"}]), encoding="utf-8")
    rows = load_push_findings_file(path)
    assert rows[0]["id"] == "finding-2"


def test_load_push_findings_rejects_empty_scanner_payload() -> None:
    with pytest.raises(ValueError, match="zero vulnerability findings"):
        load_push_findings({"Results": []})


def test_push_unresolved_advisory_retains_file_without_package():
    from copy import deepcopy

    from tests.test_external_scanners import SARIF_BASIC

    payload = deepcopy(SARIF_BASIC)
    payload["runs"][0]["results"][0]["ruleId"] = "CVE-2026-1234"
    row = load_push_findings(payload)[0]
    assert "package" not in row
    assert row["cve_id"] == "CVE-2026-1234"
    assert row["evidence"]["package_resolution"] == "unresolved"
    assert row["asset"]["identifier"] == "src/app.py"


def test_push_named_dependency_without_version_stays_unresolved():
    from copy import deepcopy

    payload = deepcopy(TRIVY_BASIC)
    payload["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = ""
    row = load_push_findings(payload)[0]
    assert "package" not in row
    assert row["evidence"]["package_name"] == "requests"
    assert row["evidence"]["package_resolution"] == "unresolved"
