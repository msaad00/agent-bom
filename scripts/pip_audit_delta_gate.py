#!/usr/bin/env python3
"""Evaluate pip-audit JSON output for PR and strict dependency gates."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SEVERE_LEVELS = {"HIGH", "CRITICAL"}


@dataclass(frozen=True, order=True)
class AuditFinding:
    package: str
    version: str
    vulnerability_id: str
    severe: bool
    fix_versions: tuple[str, ...]

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.package.lower(), self.version, self.vulnerability_id)

    @property
    def actionable(self) -> bool:
        return self.severe or bool(self.fix_versions)

    def summary(self) -> str:
        parts = [self.package, self.version, self.vulnerability_id]
        if self.severe:
            parts.append("severity=HIGH/CRITICAL")
        if self.fix_versions:
            parts.append(f"fixes={','.join(self.fix_versions)}")
        return " ".join(parts)


def load_audit(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"pip-audit did not produce {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def actionable_findings(data: dict[str, Any]) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for dependency in data.get("dependencies", []):
        dep_name = str(dependency.get("name") or "<unknown>")
        dep_version = str(dependency.get("version") or "<unknown>")
        for vuln in dependency.get("vulns", []):
            vuln_id = str(vuln.get("id") or "<unknown>")
            severity = str(vuln.get("severity") or vuln.get("severity_level") or "").upper()
            fix_versions = tuple(str(version) for version in (vuln.get("fix_versions") or []))
            finding = AuditFinding(
                package=dep_name,
                version=dep_version,
                vulnerability_id=vuln_id,
                severe=severity in SEVERE_LEVELS,
                fix_versions=fix_versions,
            )
            if finding.actionable:
                findings.append(finding)
    return sorted(findings)


def introduced_findings(current: list[AuditFinding], base: list[AuditFinding]) -> list[AuditFinding]:
    base_ids = {finding.identity for finding in base}
    return [finding for finding in current if finding.identity not in base_ids]


def emit_blocking(kind: str, findings: list[AuditFinding]) -> None:
    print(f"::error::pip-audit found {len(findings)} {kind} actionable finding(s):")
    for finding in findings[:20]:
        print(finding.summary())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True, help="pip-audit JSON for the current checkout")
    parser.add_argument("--base", type=Path, help="pip-audit JSON for the PR base branch")
    parser.add_argument("--mode", choices=("strict", "delta"), default="strict")
    args = parser.parse_args(argv)

    current = actionable_findings(load_audit(args.current))
    if args.mode == "strict":
        if current:
            emit_blocking("current", current)
            return 1
        print("pip-audit strict gate passed: no HIGH/CRITICAL or fixable findings")
        return 0

    if args.base is None:
        raise SystemExit("--base is required in delta mode")
    base = actionable_findings(load_audit(args.base))
    introduced = introduced_findings(current, base)
    if introduced:
        emit_blocking("new", introduced)
        print(f"Base branch already had {len(base)} actionable finding(s); only new PR-introduced findings block this gate.")
        return 1
    if current:
        print(f"::warning::pip-audit found {len(current)} actionable finding(s), all already present on the base branch")
    print("pip-audit PR delta gate passed: no new HIGH/CRITICAL or fixable findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
