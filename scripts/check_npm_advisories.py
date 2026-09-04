#!/usr/bin/env python3
"""Fail closed on high/critical advisories for an npm lockfile."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

BLOCKING_SEVERITIES = {"high", "critical"}
VALID_SEVERITIES = {"info", "low", "moderate", "high", "critical"}
MAX_AUDIT_REPORT_BYTES = 32 * 1024 * 1024
NPM_AUDIT_TIMEOUT_SECONDS = 360


def _package_name(package_path: str, record: dict[str, Any]) -> str | None:
    if name := record.get("name"):
        return str(name)
    marker = "node_modules/"
    if marker not in package_path:
        return None
    tail = package_path.rsplit(marker, 1)[1]
    if tail.startswith("@"):
        parts = tail.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return tail.split("/", 1)[0]


def lockfile_payload(path: Path) -> dict[str, list[str]]:
    """Return npm's bulk-advisory payload from exact locked versions."""
    document = json.loads(path.read_text(encoding="utf-8"))
    packages = document.get("packages")
    if document.get("lockfileVersion") not in {2, 3} or not isinstance(packages, dict):
        raise ValueError(f"{path} is not a supported npm lockfile")

    versions: dict[str, set[str]] = {}
    for package_path, raw_record in packages.items():
        if not package_path or not isinstance(raw_record, dict):
            continue
        version = raw_record.get("version")
        name = _package_name(package_path, raw_record)
        if name and isinstance(version, str) and version:
            versions.setdefault(name, set()).add(version)

    if not versions:
        raise ValueError(f"{path} contains no auditable locked packages")
    return {name: sorted(package_versions) for name, package_versions in sorted(versions.items())}


def validate_audit_report(report: Any, payload: dict[str, list[str]]) -> dict[str, int]:
    if not isinstance(report, dict):
        raise ValueError("npm advisory response must be an object")
    if report.get("auditReportVersion") != 2:
        raise ValueError("npm advisory response has an unsupported report version")
    vulnerabilities = report.get("vulnerabilities")
    metadata = report.get("metadata")
    raw_counts = metadata.get("vulnerabilities") if isinstance(metadata, dict) else None
    dependencies = metadata.get("dependencies") if isinstance(metadata, dict) else None
    if not isinstance(vulnerabilities, dict) or not isinstance(raw_counts, dict) or not isinstance(dependencies, dict):
        raise ValueError("npm advisory response is incomplete")

    counts: dict[str, int] = {}
    for severity in (*sorted(VALID_SEVERITIES), "total"):
        value = raw_counts.get(severity)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("npm advisory response has an invalid vulnerability count")
        counts[severity] = value
    if counts["total"] != sum(counts[severity] for severity in VALID_SEVERITIES):
        raise ValueError("npm advisory response vulnerability counts do not add up")

    observed = {severity: 0 for severity in VALID_SEVERITIES}
    for package, raw_vulnerability in vulnerabilities.items():
        if not isinstance(package, str) or package not in payload or not isinstance(raw_vulnerability, dict):
            raise ValueError("npm advisory response has an invalid package entry")
        severity = raw_vulnerability.get("severity")
        if not isinstance(severity, str) or severity.lower() not in VALID_SEVERITIES:
            raise ValueError("npm advisory response has an invalid severity")
        observed[severity.lower()] += 1
    if any(counts[severity] != observed[severity] for severity in VALID_SEVERITIES):
        raise ValueError("npm advisory response counts do not match its package entries")

    audited = dependencies.get("total")
    if isinstance(audited, bool) or not isinstance(audited, int) or audited < len(payload):
        raise ValueError("npm advisory response did not audit the exact lockfile projection")
    return counts


def run_npm_audit(path: Path) -> tuple[dict[str, Any], int]:
    """Run npm's supported bulk-advisory client with bounded output and time."""
    command = [
        "npm",
        "audit",
        "--package-lock-only",
        "--ignore-scripts",
        "--audit-level=high",
        "--json",
    ]
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        result = subprocess.run(  # noqa: S603 -- fixed npm command and arguments
            command,
            cwd=path.parent,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            check=False,
            timeout=NPM_AUDIT_TIMEOUT_SECONDS,
        )
        stdout.seek(0)
        body = stdout.read(MAX_AUDIT_REPORT_BYTES + 1)
    if len(body) > MAX_AUDIT_REPORT_BYTES:
        raise ValueError("npm advisory response exceeds the size limit")
    if result.returncode not in {0, 1}:
        raise OSError("npm audit transport failed")
    report = json.loads(body.decode("utf-8"))
    if not isinstance(report, dict):
        raise ValueError("npm advisory response must be an object")
    return report, result.returncode


def run(path: Path) -> int:
    try:
        payload = lockfile_payload(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"::error::invalid npm lockfile for advisory scan ({type(exc).__name__})", file=sys.stderr)
        return 2

    try:
        report, returncode = run_npm_audit(path)
        counts = validate_audit_report(report, payload)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"::error::npm audit failed closed ({type(exc).__name__})", file=sys.stderr)
        return 2
    has_blocking = any(counts[severity] for severity in BLOCKING_SEVERITIES)
    if returncode != int(has_blocking):
        print("::error::npm audit exit status does not match the validated report", file=sys.stderr)
        return 2
    if has_blocking:
        print(json.dumps({"blocking_severity_counts": counts}, indent=2, sort_keys=True))
        return 1
    print(f"npm advisory gate passed: {len(payload)} package names, no high/critical vulnerabilities")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lockfile", type=Path)
    args = parser.parse_args()
    return run(args.lockfile)


if __name__ == "__main__":
    raise SystemExit(main())
