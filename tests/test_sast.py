"""Tests for SAST scanning module (Semgrep wrapper)."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock

import pytest

from agent_bom.models import Severity
from agent_bom.sast import (
    SASTFinding,
    SASTResult,
    SASTScanError,
    _findings_to_packages,
    _parse_sarif_findings,
    scan_code,
)

# ── Fixtures ────────────────────────────────────────────────────────────────

SAMPLE_SARIF = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "rules": [
                        {
                            "id": "python.lang.security.audit.eval-detected",
                            "shortDescription": {"text": "Detected use of eval()"},
                            "helpUri": "https://semgrep.dev/r/python.lang.security.audit.eval-detected",
                            "defaultConfiguration": {"level": "error"},
                            "properties": {
                                "tags": ["CWE-94", "A03:2021"],
                            },
                        },
                        {
                            "id": "python.lang.security.audit.hardcoded-password",
                            "shortDescription": {"text": "Hardcoded password"},
                            "helpUri": "https://semgrep.dev/r/python.lang.security.audit.hardcoded-password",
                            "defaultConfiguration": {"level": "warning"},
                            "properties": {
                                "tags": ["CWE-798"],
                            },
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python.lang.security.audit.eval-detected",
                    "level": "error",
                    "message": {"text": "Detected use of eval(). This can be dangerous."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/utils.py"},
                                "region": {
                                    "startLine": 42,
                                    "endLine": 42,
                                    "startColumn": 5,
                                    "endColumn": 30,
                                    "snippet": {"text": "result = eval(user_input)"},
                                },
                            }
                        }
                    ],
                },
                {
                    "ruleId": "python.lang.security.audit.hardcoded-password",
                    "level": "warning",
                    "message": {"text": "Hardcoded password detected."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/config.py"},
                                "region": {
                                    "startLine": 10,
                                    "endLine": 10,
                                    "startColumn": 1,
                                    "endColumn": 40,
                                },
                            }
                        }
                    ],
                },
            ],
        }
    ],
}

EMPTY_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "semgrep", "rules": []}},
            "results": [],
        }
    ],
}


# ── SARIF parsing tests ────────────────────────────────────────────────────


def test_parse_sarif_happy_path():
    """Semgrep SARIF output is parsed into SASTFinding objects."""
    findings, rules_loaded, files_scanned = _parse_sarif_findings(SAMPLE_SARIF)

    assert len(findings) == 2
    assert rules_loaded == 2
    assert files_scanned == 2

    eval_finding = findings[0]
    assert eval_finding.rule_id == "python.lang.security.audit.eval-detected"
    assert eval_finding.severity == Severity.HIGH  # "error" → HIGH
    assert eval_finding.file_path == "src/utils.py"
    assert eval_finding.start_line == 42
    assert "CWE-94" in eval_finding.cwe_ids
    assert eval_finding.snippet == "result = eval(user_input)"
    assert eval_finding.rule_url == "https://semgrep.dev/r/python.lang.security.audit.eval-detected"

    pw_finding = findings[1]
    assert pw_finding.severity == Severity.MEDIUM  # "warning" → MEDIUM
    assert pw_finding.file_path == "src/config.py"
    assert "CWE-798" in pw_finding.cwe_ids


def test_parse_sarif_empty():
    """Empty SARIF with no results returns empty findings."""
    findings, rules_loaded, files_scanned = _parse_sarif_findings(EMPTY_SARIF)
    assert findings == []
    assert files_scanned == 0


def test_parse_sarif_no_location():
    """Results without locations are skipped."""
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    {
                        "ruleId": "test-rule",
                        "level": "warning",
                        "message": {"text": "No location"},
                        "locations": [],
                    }
                ],
            }
        ]
    }
    findings, _, _ = _parse_sarif_findings(sarif)
    assert findings == []


# ── Severity mapping ───────────────────────────────────────────────────────


def test_severity_mapping():
    """SARIF levels map to correct Severity enums."""
    from agent_bom.sast import _SARIF_LEVEL_MAP

    assert _SARIF_LEVEL_MAP["error"] == Severity.HIGH
    assert _SARIF_LEVEL_MAP["warning"] == Severity.MEDIUM
    assert _SARIF_LEVEL_MAP["note"] == Severity.LOW
    assert _SARIF_LEVEL_MAP["none"] == Severity.NONE


# ── Findings → Packages ───────────────────────────────────────────────────


def test_findings_to_packages():
    """SAST findings are grouped by file into Package objects."""
    findings = [
        SASTFinding(
            rule_id="rule-a",
            message="Issue A",
            severity=Severity.HIGH,
            file_path="src/app.py",
            start_line=10,
            end_line=10,
            cwe_ids=["CWE-89"],
        ),
        SASTFinding(
            rule_id="rule-b",
            message="Issue B",
            severity=Severity.MEDIUM,
            file_path="src/app.py",
            start_line=20,
            end_line=20,
            cwe_ids=["CWE-79"],
        ),
        SASTFinding(
            rule_id="rule-c",
            message="Issue C",
            severity=Severity.LOW,
            file_path="src/utils.py",
            start_line=5,
            end_line=5,
        ),
    ]

    packages = _findings_to_packages(findings)
    assert len(packages) == 2  # two files

    app_pkg = next(p for p in packages if p.name == "src/app.py")
    assert app_pkg.ecosystem == "sast"
    assert app_pkg.version == "0.0.0"
    assert len(app_pkg.vulnerabilities) == 2
    assert app_pkg.vulnerabilities[0].id == "rule-a"
    assert app_pkg.vulnerabilities[0].cwe_ids == ["CWE-89"]

    utils_pkg = next(p for p in packages if p.name == "src/utils.py")
    assert len(utils_pkg.vulnerabilities) == 1


def test_findings_to_packages_dedup():
    """Duplicate findings (same rule + line) in a file are deduplicated."""
    findings = [
        SASTFinding(
            rule_id="rule-a",
            message="Issue A",
            severity=Severity.HIGH,
            file_path="src/app.py",
            start_line=10,
            end_line=10,
        ),
        SASTFinding(
            rule_id="rule-a",
            message="Issue A duplicate",
            severity=Severity.HIGH,
            file_path="src/app.py",
            start_line=10,
            end_line=10,
        ),
    ]

    packages = _findings_to_packages(findings)
    assert len(packages) == 1
    assert len(packages[0].vulnerabilities) == 1


def test_findings_to_packages_empty():
    """Empty findings list returns empty packages list."""
    assert _findings_to_packages([]) == []


# ── SASTResult ─────────────────────────────────────────────────────────────


def test_sast_result_counts():
    """SASTResult severity counts are computed correctly."""
    result = SASTResult(
        findings=[
            SASTFinding(rule_id="a", message="", severity=Severity.CRITICAL, file_path="f", start_line=1, end_line=1),
            SASTFinding(rule_id="b", message="", severity=Severity.HIGH, file_path="f", start_line=2, end_line=2),
            SASTFinding(rule_id="c", message="", severity=Severity.HIGH, file_path="f", start_line=3, end_line=3),
            SASTFinding(rule_id="d", message="", severity=Severity.MEDIUM, file_path="f", start_line=4, end_line=4),
        ],
        files_scanned=1,
        rules_loaded=4,
    )
    assert result.total_findings == 4
    assert result.critical_count == 1
    assert result.high_count == 2

    d = result.to_dict()
    assert d["severity_counts"]["critical"] == 1
    assert d["severity_counts"]["high"] == 2
    assert d["severity_counts"]["medium"] == 1
    assert d["severity_counts"]["low"] == 0
    assert len(d["findings"]) == 4


def test_sast_result_to_dict_fields():
    """SASTResult.to_dict() includes all expected fields."""
    result = SASTResult(
        findings=[],
        files_scanned=10,
        rules_loaded=50,
        scan_time_seconds=1.5,
        semgrep_version="1.50.0",
        config_used="p/security-audit",
    )
    d = result.to_dict()
    assert d["files_scanned"] == 10
    assert d["rules_loaded"] == 50
    assert d["scan_time_seconds"] == 1.5
    assert d["semgrep_version"] == "1.50.0"
    assert d["config_used"] == "p/security-audit"


# ── scan_code() ────────────────────────────────────────────────────────────


def test_semgrep_not_installed(monkeypatch):
    """scan_code raises SASTScanError when semgrep is not on PATH."""
    monkeypatch.setattr("agent_bom.sast.shutil.which", lambda _: None)
    with pytest.raises(SASTScanError, match="semgrep not found"):
        scan_code("/tmp/fake-project")


def test_scan_code_invalid_path(monkeypatch):
    """Non-existent path raises SASTScanError."""
    monkeypatch.setattr("agent_bom.sast.shutil.which", lambda _: "/usr/bin/semgrep")
    with pytest.raises(SASTScanError, match="does not exist"):
        scan_code("/nonexistent/path/abc123")


def test_scan_code_timeout(monkeypatch, tmp_path):
    """Subprocess timeout raises SASTScanError."""
    monkeypatch.setattr("agent_bom.sast.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(
        "agent_bom.sast.subprocess.run",
        MagicMock(side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=600)),
    )
    with pytest.raises(SASTScanError, match="timed out"):
        scan_code(str(tmp_path))


def test_scan_code_semgrep_error(monkeypatch, tmp_path):
    """Semgrep exit code >= 2 raises SASTScanError."""
    monkeypatch.setattr("agent_bom.sast.shutil.which", lambda _: "/usr/bin/semgrep")
    mock_result = MagicMock()
    mock_result.returncode = 2
    mock_result.stderr = "Fatal error: bad config"
    monkeypatch.setattr("agent_bom.sast.subprocess.run", MagicMock(return_value=mock_result))
    with pytest.raises(SASTScanError, match="semgrep exited 2"):
        scan_code(str(tmp_path))


def test_scan_code_invalid_json(monkeypatch, tmp_path):
    """Invalid JSON from semgrep raises SASTScanError."""
    monkeypatch.setattr("agent_bom.sast.shutil.which", lambda _: "/usr/bin/semgrep")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "not valid json"
    monkeypatch.setattr("agent_bom.sast.subprocess.run", MagicMock(return_value=mock_result))
    with pytest.raises(SASTScanError, match="invalid SARIF"):
        scan_code(str(tmp_path))


def test_scan_code_happy_path(monkeypatch, tmp_path):
    """scan_code returns packages and SASTResult when Semgrep finds issues."""
    monkeypatch.setattr("agent_bom.sast.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr("agent_bom.sast._get_semgrep_version", lambda: "1.50.0")

    mock_result = MagicMock()
    mock_result.returncode = 1  # findings found
    mock_result.stdout = json.dumps(SAMPLE_SARIF)
    monkeypatch.setattr("agent_bom.sast.subprocess.run", MagicMock(return_value=mock_result))

    packages, sast_result = scan_code(str(tmp_path))

    assert len(packages) == 2
    assert sast_result.total_findings == 2
    assert sast_result.files_scanned == 2
    assert sast_result.semgrep_version == "1.50.0"
    assert sast_result.config_used == "auto"

    # Verify packages have correct ecosystem
    for pkg in packages:
        assert pkg.ecosystem == "sast"
        assert pkg.version == "0.0.0"
        assert len(pkg.vulnerabilities) > 0


def test_scan_code_clean(monkeypatch, tmp_path):
    """scan_code with no findings returns empty packages."""
    monkeypatch.setattr("agent_bom.sast.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr("agent_bom.sast._get_semgrep_version", lambda: "1.50.0")

    mock_result = MagicMock()
    mock_result.returncode = 0  # clean, no findings
    mock_result.stdout = json.dumps(EMPTY_SARIF)
    monkeypatch.setattr("agent_bom.sast.subprocess.run", MagicMock(return_value=mock_result))

    packages, sast_result = scan_code(str(tmp_path))

    assert packages == []
    assert sast_result.total_findings == 0


def test_scan_code_imports_sarif_without_semgrep(monkeypatch, tmp_path):
    """Existing SARIF files import through the same result model without Semgrep."""
    monkeypatch.setattr("agent_bom.sast.shutil.which", lambda _: None)
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(json.dumps(SAMPLE_SARIF), encoding="utf-8")

    packages, sast_result = scan_code(str(sarif_path))

    assert len(packages) == 2
    assert sast_result.total_findings == 2
    assert sast_result.config_used == "sarif-import"
    assert sast_result.semgrep_version is None


# ── CWE mapping ────────────────────────────────────────────────────────────


def test_sast_cwe_map_has_common_weaknesses():
    """CWE_COMPLIANCE_MAP covers common OWASP Top 10 weakness types."""
    from agent_bom.constants import CWE_COMPLIANCE_MAP

    assert "CWE-89" in CWE_COMPLIANCE_MAP  # SQL injection
    assert "CWE-79" in CWE_COMPLIANCE_MAP  # XSS
    assert "CWE-798" in CWE_COMPLIANCE_MAP  # hardcoded creds
    assert "CWE-78" in CWE_COMPLIANCE_MAP  # OS command injection
    assert "CWE-22" in CWE_COMPLIANCE_MAP  # path traversal


def test_sast_cwe_map_frameworks():
    """CWE mappings include expected framework keys."""
    from agent_bom.constants import CWE_COMPLIANCE_MAP

    sql_inj = CWE_COMPLIANCE_MAP["CWE-89"]
    assert "iso_27001" in sql_inj
    assert "nist_csf" in sql_inj
    assert "owasp_llm" in sql_inj

    hardcoded = CWE_COMPLIANCE_MAP["CWE-798"]
    assert "soc2" in hardcoded
    assert "owasp_llm" in hardcoded


# ── OSV skip guard ─────────────────────────────────────────────────────────


def test_sast_packages_skip_osv():
    """Packages with ecosystem='sast' should be excluded from scannable list."""
    from agent_bom.models import Package

    packages = [
        Package(name="express", version="4.18.2", ecosystem="npm"),
        Package(name="src/utils.py", version="0.0.0", ecosystem="sast"),
        Package(name="flask", version="3.0.0", ecosystem="pypi"),
    ]

    # Replicate the guard from scanners/__init__.py
    scannable = [p for p in packages if p.version not in ("unknown", "latest") and p.ecosystem != "sast"]
    assert len(scannable) == 2
    assert all(p.ecosystem != "sast" for p in scannable)


# ── Compliance tagging with CWE ────────────────────────────────────────────


def test_iso_27001_sast_cwe_tagging():
    """ISO 27001 tagger adds A.8.28 for SAST findings with CWE-89."""
    from agent_bom.iso_27001 import tag_blast_radius
    from agent_bom.models import BlastRadius, Package, Vulnerability

    br = BlastRadius(
        vulnerability=Vulnerability(
            id="python.lang.security.audit.sql-injection",
            summary="SQL injection detected",
            severity=Severity.HIGH,
            cwe_ids=["CWE-89"],
        ),
        package=Package(name="src/db.py", version="0.0.0", ecosystem="sast"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )

    tags = tag_blast_radius(br)
    assert "A.8.28" in tags  # CWE-89 → A.8.28 (secure coding)


def test_owasp_llm_sast_cwe_tagging():
    """OWASP LLM tagger adds LLM02 for SAST findings with CWE-78."""
    from agent_bom.models import BlastRadius, Package, Vulnerability
    from agent_bom.owasp import tag_blast_radius

    br = BlastRadius(
        vulnerability=Vulnerability(
            id="python.lang.security.audit.os-command-injection",
            summary="OS command injection",
            severity=Severity.HIGH,
            cwe_ids=["CWE-78"],
        ),
        package=Package(name="src/shell.py", version="0.0.0", ecosystem="sast"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )

    tags = tag_blast_radius(br)
    assert "LLM02" in tags  # CWE-78 → LLM02 (insecure output handling)


# ── CLI integration ────────────────────────────────────────────────────────


def test_cli_code_flag():
    """--code flag appears in CLI help."""
    from click.testing import CliRunner

    from agent_bom.cli import scan as scan_cmd

    runner = CliRunner()
    result = runner.invoke(scan_cmd, ["--help"])
    assert "--code" in result.output
    assert "--sast-config" in result.output
    assert "SAST" in result.output or "Semgrep" in result.output
