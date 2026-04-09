from __future__ import annotations

import json
from urllib.parse import urlparse

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Severity, Vulnerability
from agent_bom.scanners import IncompleteScanError


def _patch_check_scan(monkeypatch, vulns):
    async def _scan_packages(pkgs):
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


def test_check_incomplete_offline_scan_exits_two(monkeypatch):
    async def _scan_packages(_pkgs):
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

    async def _scan_packages(pkgs):
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


def test_check_quiet_suppresses_scan_chatter(monkeypatch):
    async def _scan_packages(pkgs):
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
    assert "1 vulnerability/ies found" in result.output


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


def test_check_output_requires_json_format(monkeypatch):
    _patch_check_scan(monkeypatch, [])

    result = CliRunner().invoke(
        main,
        ["check", "django@4.1.0", "--ecosystem", "pypi", "--output", "report.json"],
    )

    assert result.exit_code == 1
    assert "--format json" in result.output
