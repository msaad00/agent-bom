"""Tests for .agent-bom-ignore suppression rules."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from agent_bom.ignore import IgnoreRules, apply_ignore_rules, load_ignore_file

# ── Unit tests for IgnoreRules ────────────────────────────────────────────────


def test_empty_rules():
    r = IgnoreRules()
    assert r.is_empty
    assert r.rule_count == 0
    assert not r.should_ignore_vuln("CVE-2024-1234", "npm", "express")


def test_cve_suppression():
    r = IgnoreRules()
    r.add_cve("CVE-2024-1234")
    assert r.should_ignore_vuln("CVE-2024-1234", "npm", "express")
    assert r.should_ignore_vuln("cve-2024-1234", "pypi", "requests")  # case insensitive
    assert not r.should_ignore_vuln("CVE-2024-9999", "npm", "express")


def test_package_suppression():
    r = IgnoreRules()
    r.add_package("npm", "lodash")
    assert r.should_ignore_vuln("CVE-2024-1234", "npm", "lodash")
    assert r.should_ignore_vuln("CVE-2099-9999", "npm", "lodash")
    assert not r.should_ignore_vuln("CVE-2024-1234", "pypi", "lodash")


def test_cve_package_pair():
    r = IgnoreRules()
    r.add_cve_package("CVE-2024-1234", "npm", "express")
    assert r.should_ignore_vuln("CVE-2024-1234", "npm", "express")
    assert not r.should_ignore_vuln("CVE-2024-1234", "npm", "lodash")
    assert not r.should_ignore_vuln("CVE-2024-9999", "npm", "express")


def test_rule_count():
    r = IgnoreRules()
    r.add_cve("CVE-2024-1234")
    r.add_package("npm", "lodash")
    r.add_cve_package("CVE-2024-5678", "pypi", "flask")
    assert r.rule_count == 3
    assert not r.is_empty


# ── File parsing tests ────────────────────────────────────────────────────────


def test_load_ignore_file(tmp_path: Path):
    ignore = tmp_path / ".agent-bom-ignore"
    ignore.write_text("# Comment line\n\nCVE-2024-1234\nGHSA-abcd-efgh-ijkl\nnpm:lodash\nCVE-2024-5678:pypi:flask\n")
    rules = load_ignore_file(ignore)
    assert rules.rule_count == 4
    assert rules.should_ignore_vuln("CVE-2024-1234", "npm", "anything")
    assert rules.should_ignore_vuln("GHSA-abcd-efgh-ijkl", "npm", "anything")
    assert rules.should_ignore_vuln("CVE-9999-0001", "npm", "lodash")
    assert rules.should_ignore_vuln("CVE-2024-5678", "pypi", "flask")
    assert not rules.should_ignore_vuln("CVE-2024-5678", "npm", "flask")


def test_load_missing_file():
    rules = load_ignore_file(Path("/nonexistent/.agent-bom-ignore"))
    assert rules.is_empty


def test_malformed_lines_skipped(tmp_path: Path):
    ignore = tmp_path / ".agent-bom-ignore"
    ignore.write_text("not-a-cve\nCVE-2024-1234\n")
    rules = load_ignore_file(ignore)
    assert rules.rule_count == 1  # only the valid CVE


# ── apply_ignore_rules integration ────────────────────────────────────────────


def _make_pkg(name: str, ecosystem: str, vuln_ids: list[str]):
    vulns = [SimpleNamespace(id=vid) for vid in vuln_ids]
    return SimpleNamespace(name=name, ecosystem=ecosystem, vulnerabilities=vulns)


def test_apply_removes_suppressed():
    r = IgnoreRules()
    r.add_cve("CVE-2024-1234")
    pkg = _make_pkg("express", "npm", ["CVE-2024-1234", "CVE-2024-9999"])
    removed = apply_ignore_rules([pkg], r)
    assert removed == 1
    assert len(pkg.vulnerabilities) == 1
    assert pkg.vulnerabilities[0].id == "CVE-2024-9999"


def test_apply_empty_rules_noop():
    r = IgnoreRules()
    pkg = _make_pkg("express", "npm", ["CVE-2024-1234"])
    removed = apply_ignore_rules([pkg], r)
    assert removed == 0
    assert len(pkg.vulnerabilities) == 1
