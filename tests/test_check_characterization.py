"""Characterization golden for ``agent-bom check``.

Pins stdout, stderr, exit code and any written output file for a matrix of
option combinations and scan outcomes, so structural refactors of the command
must reproduce its observable behavior exactly. The scanner, enrichment,
registry resolution and OS-context enrichment are replaced the same way the
existing ``check`` tests replace them, so no network is touched.

Regenerate only for an intended behavior change:
``REGEN_CHECK_GOLDEN=1 pytest tests/test_check_characterization.py``.
"""

from __future__ import annotations

import json
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from agent_bom import __version__
from agent_bom.cli import main
from agent_bom.cli._agent_mode import AGENT_MODE_ENV_VAR
from agent_bom.models import Severity, Vulnerability
from agent_bom.scanners import IncompleteScanError
from agent_bom.scanners import state as scanner_state

GOLDEN = Path(__file__).parent / "fixtures" / "check_characterization" / "golden.json"
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")


def _vulns() -> list[Vulnerability]:
    return [
        Vulnerability(
            id="CVE-2023-0001",
            summary="Remote code execution through a crafted template that is long enough to truncate",
            severity=Severity.CRITICAL,
            fixed_version="2.3.2",
            cvss_score=9.8,
            is_kev=True,
            cwe_ids=["CWE-94"],
        ),
        Vulnerability(
            id="CVE-2023-0002",
            summary="Session cookie disclosure",
            severity=Severity.HIGH,
            fixed_version=None,
            cwe_ids=["CWE-200"],
        ),
        Vulnerability(
            id="GHSA-xxxx-yyyy-zzzz",
            summary="No description available",
            severity=Severity.LOW,
            aliases=["CVE-2023-0003", "PYSEC-2023-1"],
        ),
        Vulnerability(id="CVE-2023-0004", summary="", severity=Severity.MEDIUM),
    ]


def _low_only() -> list[Vulnerability]:
    return [Vulnerability(id="CVE-2023-0009", summary="Minor issue", severity=Severity.LOW, fixed_version="1.0.1")]


def _install(monkeypatch: pytest.MonkeyPatch, outcome: str, *, os_complete: bool = True, enrich: str = "ok") -> None:
    async def _scan_packages(pkgs, **_kwargs):
        if outcome == "incomplete_error":
            raise IncompleteScanError("advisory source unavailable")
        if outcome in {"offline_gap", "remote_gap"}:
            scanner_state.record_scan_warning("1 package lookup error(s)")
            kind = "offline_ecosystem_gap" if outcome == "offline_gap" else "remote_lookup_gap"
            scanner_state.record_coverage_warning({"kind": kind})
            return
        if outcome == "warning_vulns":
            scanner_state.record_scan_warning("partial advisory data")
        for pkg in pkgs:
            if outcome in {"vulns", "warning_vulns"}:
                pkg.vulnerabilities = _vulns()
            elif outcome == "low_only":
                pkg.vulnerabilities = _low_only()
            elif outcome in {"malicious", "malicious_no_reason"}:
                pkg.vulnerabilities = _low_only()
                pkg.is_malicious = True
                pkg.malicious_reason = "MAL-2024-0001" if outcome == "malicious" else None
            else:
                pkg.vulnerabilities = []

    async def _enrich_vulnerabilities(vulns, **_kwargs):
        if enrich == "fail":
            raise RuntimeError("NVD unreachable")
        for vuln in vulns:
            vuln.epss_score = 0.5

    async def _resolve_package_version(pkg, _client):
        if outcome == "latest_fail":
            return False
        pkg.version = "9.9.9"
        return True

    @asynccontextmanager
    async def _create_client(**_kwargs):
        yield object()

    monkeypatch.setattr("agent_bom.scanners.scan_packages", _scan_packages)
    monkeypatch.setattr("agent_bom.parsers.os_parsers.enrich_os_package_context", lambda pkg: os_complete)
    monkeypatch.setattr("agent_bom.enrichment.enrich_vulnerabilities", _enrich_vulnerabilities)
    monkeypatch.setattr("agent_bom.resolver.resolve_package_version", _resolve_package_version)
    monkeypatch.setattr("agent_bom.http_client.create_client", _create_client)
    monkeypatch.delenv(AGENT_MODE_ENV_VAR, raising=False)


# name -> (outcome, argv, extra install kwargs)
CASES: dict[str, tuple[str, list[str], dict[str, Any]]] = {
    "clean_console": ("clean", ["check", "django@4.1.0", "-e", "pypi"], {}),
    "clean_quiet": ("clean", ["check", "django@4.1.0", "-e", "pypi", "--quiet"], {}),
    "clean_json": ("clean", ["check", "django@4.1.0", "-e", "pypi", "-f", "json"], {}),
    "clean_sarif": ("clean", ["check", "django@4.1.0", "-e", "pypi", "-f", "sarif"], {}),
    "clean_offline_json": ("clean", ["check", "django@4.1.0", "-e", "pypi", "--offline", "-f", "json"], {}),
    "vulns_console": ("vulns", ["check", "flask@2.2.0", "-e", "pypi"], {}),
    "vulns_no_color": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "--no-color"], {}),
    "vulns_quiet": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "-q"], {}),
    "vulns_json": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "-f", "json"], {}),
    "vulns_json_file": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "-f", "json", "-o", "{out}"], {}),
    "vulns_json_stdout_dash": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "-f", "json", "-o", "-"], {}),
    "vulns_sarif": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "-f", "SARIF"], {}),
    "vulns_sarif_file": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "-f", "sarif", "-o", "{out}"], {}),
    "vulns_exit_zero_console": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "--exit-zero"], {}),
    "vulns_exit_zero_quiet": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "--exit-zero", "-q"], {}),
    "vulns_exit_zero_json": (
        "vulns",
        ["check", "flask@2.2.0", "-e", "pypi", "--exit-zero", "-f", "json", "--fail-on-severity", "high"],
        {},
    ),
    "vulns_fail_critical_console": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "--fail-on-severity", "CRITICAL"], {}),
    "vulns_fail_critical_json": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "--fail-on-severity", "critical", "-f", "json"], {}),
    "low_fail_high_console": ("low_only", ["check", "flask@2.2.0", "-e", "pypi", "--fail-on-severity", "high"], {}),
    "low_fail_high_quiet": ("low_only", ["check", "flask@2.2.0", "-e", "pypi", "--fail-on-severity", "high", "-q"], {}),
    "low_fail_high_json": ("low_only", ["check", "flask@2.2.0", "-e", "pypi", "--fail-on-severity", "high", "-f", "json"], {}),
    "low_fail_low_console": ("low_only", ["check", "flask@2.2.0", "-e", "pypi", "--fail-on-severity", "low"], {}),
    "warning_vulns_console": ("warning_vulns", ["check", "flask@2.2.0", "-e", "pypi"], {}),
    "warning_vulns_json": ("warning_vulns", ["check", "flask@2.2.0", "-e", "pypi", "-f", "json"], {}),
    "enrich_ok_json": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "--enrich", "-f", "json"], {}),
    "enrich_fail_console": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "--enrich"], {"enrich": "fail"}),
    "enrich_fail_json": ("vulns", ["check", "flask@2.2.0", "-e", "pypi", "--enrich", "-f", "json"], {"enrich": "fail"}),
    "enrich_clean_skipped": ("clean", ["check", "django@4.1.0", "-e", "pypi", "--enrich", "-q"], {"enrich": "fail"}),
    "malicious_console": ("malicious", ["check", "reqeusts@1.0.0", "-e", "pypi"], {}),
    "malicious_quiet": ("malicious", ["check", "reqeusts@1.0.0", "-e", "pypi", "-q", "--exit-zero"], {}),
    "malicious_json": ("malicious", ["check", "reqeusts@1.0.0", "-e", "pypi", "-f", "json"], {}),
    "malicious_no_reason_console": ("malicious_no_reason", ["check", "reqeusts@1.0.0", "-e", "pypi"], {}),
    "incomplete_error_console": ("incomplete_error", ["check", "flask@2.2.0", "-e", "pypi"], {}),
    "incomplete_error_json": ("incomplete_error", ["check", "flask@2.2.0", "-e", "pypi", "-f", "json"], {}),
    "offline_gap_console": ("offline_gap", ["check", "flask@2.2.0", "-e", "pypi", "--offline"], {}),
    "offline_gap_quiet": ("offline_gap", ["check", "flask@2.2.0", "-e", "pypi", "--offline", "-q"], {}),
    "offline_gap_json": ("offline_gap", ["check", "flask@2.2.0", "-e", "pypi", "--offline", "-f", "json"], {}),
    "offline_gap_online_is_clean": ("offline_gap", ["check", "flask@2.2.0", "-e", "pypi"], {}),
    "remote_gap_console": ("remote_gap", ["check", "jinja2@3.1.2", "-e", "pypi"], {}),
    "remote_gap_quiet": ("remote_gap", ["check", "jinja2@3.1.2", "-e", "pypi", "-q"], {}),
    "remote_gap_json_file": ("remote_gap", ["check", "jinja2@3.1.2", "-e", "pypi", "-f", "json", "-o", "{out}"], {}),
    "remote_gap_offline_is_clean": ("remote_gap", ["check", "jinja2@3.1.2", "-e", "pypi", "--offline", "-q"], {}),
    "os_incomplete_console": ("clean", ["check", "ncurses-bin@6.5+20250216-2", "-e", "deb"], {"os_complete": False}),
    "os_incomplete_quiet": ("clean", ["check", "ncurses-bin@6.5+20250216-2", "-e", "deb", "-q"], {"os_complete": False}),
    "os_incomplete_json": ("clean", ["check", "ncurses-bin@6.5+20250216-2", "-e", "deb", "-f", "json"], {"os_complete": False}),
    "os_complete_clean": ("clean", ["check", "ncurses-bin@6.5+20250216-2", "-e", "deb", "-q"], {}),
    "no_version_console": ("clean", ["check", "somepkg", "-e", "pypi"], {}),
    "no_version_json": ("clean", ["check", "somepkg", "-e", "pypi", "-f", "json"], {}),
    "maven_bare_console": ("clean", ["check", "log4j-core@2.14.1", "-e", "maven"], {}),
    "maven_bare_json": ("clean", ["check", "log4j-core@2.14.1", "-e", "maven", "-f", "json"], {}),
    "malformed_console": ("clean", ["check", "flask==@@@bad", "-e", "pypi"], {}),
    "latest_resolved_console": ("vulns", ["check", "flask@latest", "-e", "pypi"], {}),
    "latest_resolved_quiet": ("clean", ["check", "flask@latest", "-e", "pypi", "-q"], {}),
    "latest_fail_console": ("latest_fail", ["check", "flask@latest", "-e", "pypi"], {}),
    "latest_fail_json": ("latest_fail", ["check", "flask@latest", "-e", "pypi", "-f", "json"], {}),
    "output_requires_structured": ("clean", ["check", "django@4.1.0", "-e", "pypi", "-o", "{out}"], {}),
    "agent_mode_sarif_rejected": ("clean", ["--agent-mode", "check", "django@4.1.0", "-e", "pypi", "-f", "sarif"], {}),
    "agent_mode_vulns": ("vulns", ["--agent-mode", "check", "flask@2.2.0", "-e", "pypi"], {}),
    "agent_mode_clean": ("clean", ["--agent-mode", "check", "django@4.1.0", "-e", "pypi"], {}),
    "npx_spec_console": ("clean", ["check", "npx @modelcontextprotocol/server-filesystem@1.0.0", "-e", "npm"], {}),
}


def _normalize(text: str, tmp: Path) -> str:
    text = text.replace(str(tmp), "<TMP>").replace(__version__, "<VERSION>")
    return _TIMESTAMP_RE.sub("<TIMESTAMP>", text)


def _run_case(name: str, monkeypatch: pytest.MonkeyPatch, tmp: Path) -> dict[str, Any]:
    outcome, argv, kwargs = CASES[name]
    scanner_state.reset_scan_warnings()
    _install(monkeypatch, outcome, **kwargs)
    out = tmp / f"{name}.out"
    result = CliRunner().invoke(main, [a.replace("{out}", str(out)) for a in argv])
    scanner_state.reset_scan_warnings()
    record: dict[str, Any] = {
        "exit_code": result.exit_code,
        "stdout": _normalize(result.stdout, tmp),
        "stderr": _normalize(result.stderr, tmp),
        "exception": None if result.exception is None or isinstance(result.exception, SystemExit) else type(result.exception).__name__,
        "file": _normalize(out.read_text(), tmp) if out.exists() else None,
    }
    return record


def _load() -> dict[str, Any]:
    return json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}


@pytest.mark.parametrize("name", sorted(CASES))
def test_check_characterization(name: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    actual = _run_case(name, monkeypatch, tmp_path)
    if os.environ.get("REGEN_CHECK_GOLDEN") == "1":
        golden = _load()
        golden[name] = actual
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(golden, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    assert actual == _load()[name]


def test_check_characterization_covers_every_exit_code() -> None:
    golden = _load()
    assert sorted(golden) == sorted(CASES)
    assert {record["exit_code"] for record in golden.values()} == {0, 1, 2}
    assert any(record["file"] for record in golden.values())
    assert all(record["exception"] is None for record in golden.values())
