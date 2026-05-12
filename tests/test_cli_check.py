from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Severity, Vulnerability
from agent_bom.scanners import IncompleteScanError


def _patch_check_scan(monkeypatch, vulns):
    async def _scan_packages(pkgs, **_kwargs):
        for pkg in pkgs:
            pkg.vulnerabilities = list(vulns)

    monkeypatch.setattr("agent_bom.scanners.scan_packages", _scan_packages)
    monkeypatch.setattr("agent_bom.parsers.os_parsers.enrich_os_package_context", lambda pkg: True)


def test_check_clean_exits_zero(monkeypatch):
    _patch_check_scan(monkeypatch, [])

    result = CliRunner().invoke(main, ["check", "django@4.1.0", "--ecosystem", "pypi"])

    assert result.exit_code == 0
    assert "No known vulnerabilities" in result.output


def test_check_vulns_exit_one_by_default(monkeypatch):
    _patch_check_scan(
        monkeypatch,
        [
            Vulnerability(
                id="CVE-2023-30861",
                summary="Session cookie disclosure",
                severity=Severity.HIGH,
                fixed_version="2.3.2",
            )
        ],
    )

    result = CliRunner().invoke(main, ["check", "flask@2.2.0", "--ecosystem", "pypi"])

    assert result.exit_code == 1
    assert "do not install without review" in result.output


def test_check_enriches_matched_vulnerabilities(monkeypatch):
    vuln = Vulnerability(
        id="CVE-2023-30861",
        summary="Session cookie disclosure",
        severity=Severity.HIGH,
        fixed_version="2.3.2",
    )
    _patch_check_scan(monkeypatch, [vuln])
    calls = []

    async def _enrich_vulnerabilities(vulns, **kwargs):
        calls.append((vulns, kwargs))
        vulns[0].epss_score = 0.91
        vulns[0].epss_percentile = 99.0
        vulns[0].is_kev = True
        vulns[0].cwe_ids.append("CWE-200")
        vulns[0].advisory_sources.append("epss")
        return 1

    monkeypatch.setattr("agent_bom.enrichment.enrich_vulnerabilities", _enrich_vulnerabilities)

    result = CliRunner().invoke(
        main,
        [
            "check",
            "flask@2.2.0",
            "--ecosystem",
            "pypi",
            "--enrich",
            "--nvd-api-key",
            "test-key",
            "--format",
            "json",
            "--quiet",
        ],
    )

    assert result.exit_code == 1
    assert calls
    assert calls[0][1]["nvd_api_key"] == "test-key"
    payload = json.loads(result.output)
    finding = payload["vulnerabilities"][0]
    assert finding["epss_score"] == 0.91
    assert finding["epss_percentile"] == 99.0
    assert finding["is_kev"] is True
    assert finding["cwe_ids"] == ["CWE-200"]
    assert finding["advisory_sources"] == ["epss"]


def test_check_does_not_enrich_without_flag(monkeypatch):
    _patch_check_scan(
        monkeypatch,
        [
            Vulnerability(
                id="CVE-2023-30861",
                summary="Session cookie disclosure",
                severity=Severity.HIGH,
                fixed_version="2.3.2",
            )
        ],
    )

    async def _enrich_vulnerabilities(_vulns, **_kwargs):
        raise AssertionError("check should not enrich unless --enrich is set")

    monkeypatch.setattr("agent_bom.enrichment.enrich_vulnerabilities", _enrich_vulnerabilities)

    result = CliRunner().invoke(main, ["check", "flask@2.2.0", "--ecosystem", "pypi", "--quiet"])

    assert result.exit_code == 1
    assert "1 vulnerability found" in result.output


def test_check_exit_zero_reports_without_failing(monkeypatch):
    _patch_check_scan(
        monkeypatch,
        [
            Vulnerability(
                id="CVE-2023-30861",
                summary="Session cookie disclosure",
                severity=Severity.HIGH,
                fixed_version="2.3.2",
            )
        ],
    )

    result = CliRunner().invoke(main, ["check", "flask@2.2.0", "--ecosystem", "pypi", "--exit-zero"])

    assert result.exit_code == 0
    assert "reported without failing due to --exit-zero" in result.output


def test_check_fail_on_severity_exits_zero_when_findings_below_threshold(monkeypatch):
    _patch_check_scan(
        monkeypatch,
        [
            Vulnerability(
                id="CVE-2026-0001",
                summary="Moderate issue",
                severity=Severity.MEDIUM,
                fixed_version="2.0.0",
            )
        ],
    )

    result = CliRunner().invoke(
        main,
        ["check", "demo@1.0.0", "--ecosystem", "pypi", "--fail-on-severity", "high", "--format", "json", "--quiet"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["fail_on_severity"] == "high"
    assert payload["fail_on_severity_count"] == 0


def test_check_fail_on_severity_exits_one_when_threshold_matches(monkeypatch):
    _patch_check_scan(
        monkeypatch,
        [
            Vulnerability(
                id="CVE-2026-0002",
                summary="Critical issue",
                severity=Severity.CRITICAL,
                fixed_version="2.0.0",
            )
        ],
    )

    result = CliRunner().invoke(
        main,
        ["check", "demo@1.0.0", "--ecosystem", "pypi", "--fail-on-severity", "high", "--format", "json", "--quiet"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["fail_on_severity"] == "high"
    assert payload["fail_on_severity_count"] == 1


def test_check_incomplete_offline_scan_exits_two(monkeypatch):
    async def _scan_packages(_pkgs, **_kwargs):
        raise IncompleteScanError("Offline mode requires a populated local vulnerability DB.")

    monkeypatch.setattr("agent_bom.scanners.scan_packages", _scan_packages)
    monkeypatch.setattr("agent_bom.parsers.os_parsers.enrich_os_package_context", lambda pkg: True)

    result = CliRunner().invoke(main, ["check", "django@4.1.0", "--ecosystem", "pypi"])

    assert result.exit_code == 2
    assert "populated local vulnerability DB" in result.output


class _DummyResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_check_uses_version_aware_ecosystem_resolution(monkeypatch):
    seen_ecosystems = []

    def _fake_sync_get(url, timeout=3):  # noqa: ARG001
        host = urlparse(url).hostname or ""
        if host == "pypi.org":
            return _DummyResponse(200, {"releases": {"2.33.0": [{}]}})
        if host == "registry.npmjs.org":
            return _DummyResponse(200, {"versions": {"0.0.1": {}}})
        return None

    async def _scan_packages(pkgs, **_kwargs):
        for pkg in pkgs:
            seen_ecosystems.append(pkg.ecosystem)
            pkg.vulnerabilities = []

    monkeypatch.setattr("agent_bom.http_client.sync_get", _fake_sync_get)
    monkeypatch.setattr("agent_bom.scanners.scan_packages", _scan_packages)
    monkeypatch.setattr("agent_bom.parsers.os_parsers.enrich_os_package_context", lambda pkg: True)

    result = CliRunner().invoke(main, ["check", "requests@2.33.0"])

    assert result.exit_code == 0
    assert seen_ecosystems == ["pypi"]


def test_check_requires_explicit_ecosystem_when_name_stays_ambiguous(monkeypatch):
    def _fake_sync_get(url, timeout=3):  # noqa: ARG001
        host = urlparse(url).hostname or ""
        if host == "pypi.org":
            return _DummyResponse(200, {"releases": {"1.0.0": [{}]}})
        if host == "registry.npmjs.org":
            return _DummyResponse(200, {"versions": {"1.0.0": {}}})
        return None

    monkeypatch.setattr("agent_bom.http_client.sync_get", _fake_sync_get)

    result = CliRunner().invoke(main, ["check", "sharedpkg@1.0.0"])

    assert result.exit_code == 2
    assert "Specify --ecosystem pypi or --ecosystem npm" in result.output


def test_mcp_scan_delegates_to_package_check(monkeypatch):
    _patch_check_scan(monkeypatch, [])

    result = CliRunner().invoke(main, ["mcp", "scan", "requests@2.33.0", "--ecosystem", "pypi"])

    assert result.exit_code == 0
    assert "No known vulnerabilities" in result.output


def test_mcp_scan_empty_spec_is_usage_error():
    result = CliRunner().invoke(main, ["mcp", "scan", ""])

    assert result.exit_code == 2
    assert "cannot be empty" in result.output


def test_sbom_missing_file_is_usage_error():
    result = CliRunner().invoke(main, ["sbom", "/missing.json"])

    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_check_quiet_suppresses_scan_chatter(monkeypatch):
    async def _scan_packages(pkgs, **_kwargs):
        import agent_bom.scanners as scanners

        scanners.console.print("scanner noise that should stay hidden")
        for pkg in pkgs:
            pkg.vulnerabilities = [
                Vulnerability(
                    id="CVE-2023-30861",
                    summary="Session cookie disclosure",
                    severity=Severity.HIGH,
                    fixed_version="2.3.2",
                )
            ]

    monkeypatch.setattr("agent_bom.scanners.scan_packages", _scan_packages)
    monkeypatch.setattr("agent_bom.parsers.os_parsers.enrich_os_package_context", lambda pkg: True)

    result = CliRunner().invoke(main, ["check", "flask@2.2.0", "--ecosystem", "pypi", "--quiet"])

    assert result.exit_code == 1
    assert "scanner noise" not in result.output
    assert "Checking flask@2.2.0" not in result.output
    assert "1 vulnerability found" in result.output


def test_check_pluralizes_vulnerability_count(monkeypatch):
    _patch_check_scan(
        monkeypatch,
        [
            Vulnerability(
                id="CVE-2023-30861",
                summary="Session cookie disclosure",
                severity=Severity.HIGH,
                fixed_version="2.3.2",
            ),
            Vulnerability(
                id="CVE-2024-00002",
                summary="Second issue",
                severity=Severity.MEDIUM,
                fixed_version="2.3.3",
            ),
        ],
    )

    result = CliRunner().invoke(main, ["check", "flask@2.2.0", "--ecosystem", "pypi", "--quiet"])

    assert result.exit_code == 1
    assert "2 vulnerabilities found" in result.output


def test_check_json_output_is_machine_readable(monkeypatch):
    _patch_check_scan(
        monkeypatch,
        [
            Vulnerability(
                id="CVE-2023-30861",
                summary="Session cookie disclosure",
                severity=Severity.HIGH,
                fixed_version="2.3.2",
            )
        ],
    )

    result = CliRunner().invoke(
        main,
        ["check", "flask@2.2.0", "--ecosystem", "pypi", "--format", "json", "--quiet"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["package"] == "flask"
    assert payload["version"] == "2.2.0"
    assert payload["verdict"] == "unsafe"
    assert payload["vulnerability_count"] == 1
    assert payload["vulnerabilities"][0]["id"] == "CVE-2023-30861"


def test_check_agent_mode_emits_machine_envelope_without_rich_table(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_AGENT_MODE", raising=False)
    _patch_check_scan(
        monkeypatch,
        [
            Vulnerability(
                id="CVE-2023-30861",
                summary="Session cookie disclosure",
                severity=Severity.HIGH,
                fixed_version="2.3.2",
            )
        ],
    )

    result = CliRunner().invoke(main, ["--agent-mode", "check", "flask@2.2.0", "--ecosystem", "pypi"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1"
    assert payload["mode"] == "agent"
    assert payload["ok"] is False
    assert payload["command"] == "check"
    assert payload["exit_code"] == 1
    assert payload["error"]["type"] == "unsafe_package"
    assert payload["summary"]["packages"] == 1
    assert payload["summary"]["vulnerabilities"] == 1
    assert payload["summary"]["severity_counts"]["high"] == 1
    assert payload["data"]["document_type"] == "PACKAGE-CHECK"
    assert payload["data"]["vulnerabilities"][0]["id"] == "CVE-2023-30861"
    assert "flask@2.2.0 — 1 vulnerability found" not in result.output
    assert "┏" not in result.output
    assert "AGENT_BOM_AGENT_MODE" not in os.environ


def test_check_agent_mode_env_emits_clean_envelope_for_clean_package(monkeypatch):
    _patch_check_scan(monkeypatch, [])

    result = CliRunner().invoke(
        main,
        ["check", "django@4.1.0", "--ecosystem", "pypi"],
        env={"AGENT_BOM_AGENT_MODE": "1"},
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["mode"] == "agent"
    assert payload["ok"] is True
    assert payload["data"]["verdict"] == "clean"
    assert payload["summary"]["vulnerabilities"] == 0


def test_check_output_requires_json_format(monkeypatch):
    _patch_check_scan(monkeypatch, [])

    result = CliRunner().invoke(
        main,
        ["check", "django@4.1.0", "--ecosystem", "pypi", "--output", "report.json"],
    )

    assert result.exit_code == 1
    assert "--format json" in result.output
