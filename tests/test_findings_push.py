from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.findings_push import load_push_findings, load_push_findings_file, packages_to_bulk_findings
from agent_bom.parsers.external_scanners import parse_trivy_json
from tests.test_external_scanners import TRIVY_BASIC


def test_packages_to_bulk_findings_projects_scanner_rows() -> None:
    packages = parse_trivy_json(TRIVY_BASIC)
    findings = packages_to_bulk_findings(packages, source="trivy-ci")

    assert findings
    assert findings[0]["source"] == "trivy-ci"
    assert findings[0]["origin"] == "bulk_ingest"
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


def test_load_push_findings_file(tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([{"id": "finding-2", "severity": "medium"}]), encoding="utf-8")
    rows = load_push_findings_file(path)
    assert rows[0]["id"] == "finding-2"


def test_load_push_findings_rejects_empty_scanner_payload() -> None:
    with pytest.raises(ValueError, match="zero vulnerability findings"):
        load_push_findings({"Results": []})
