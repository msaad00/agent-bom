from __future__ import annotations

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Severity, Vulnerability


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
