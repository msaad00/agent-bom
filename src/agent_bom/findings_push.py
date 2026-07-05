"""Load external scanner output or finding JSON for bulk control-plane ingest."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_bom.models import Package, Severity


def _severity_value(severity: Severity | str) -> str:
    if isinstance(severity, Severity):
        return severity.value
    return str(severity)


def packages_to_bulk_findings(
    packages: list[Package],
    *,
    source: str = "external_scan",
) -> list[dict[str, Any]]:
    """Project scanner packages into bulk-ingest finding rows."""

    findings: list[dict[str, Any]] = []
    for pkg in packages:
        for vuln in pkg.vulnerabilities:
            vulnerability_id = vuln.id or "unknown"
            findings.append(
                {
                    "id": f"{vulnerability_id}:{pkg.name}:{pkg.version}",
                    "vulnerability_id": vulnerability_id,
                    "cve_id": vulnerability_id if vulnerability_id.upper().startswith("CVE-") else None,
                    "package": pkg.name,
                    "package_name": pkg.name,
                    "package_version": pkg.version,
                    "ecosystem": pkg.ecosystem,
                    "severity": _severity_value(vuln.severity),
                    "title": vuln.summary or vulnerability_id,
                    "summary": vuln.summary,
                    "fixed_version": vuln.fixed_version,
                    "cvss_score": vuln.cvss_score,
                    "is_kev": bool(vuln.is_kev),
                    "source": source,
                    "origin": "bulk_ingest",
                }
            )
    return findings


def load_push_findings(payload: object, *, source: str = "external_scan") -> list[dict[str, Any]]:
    """Normalize a JSON payload into bulk-ingest finding rows."""

    if isinstance(payload, list):
        rows = [row for row in payload if isinstance(row, dict)]
        if rows:
            return rows
        raise ValueError("findings JSON list is empty")

    if not isinstance(payload, dict):
        raise ValueError("findings JSON must be an object or list")

    embedded = payload.get("findings")
    if isinstance(embedded, list):
        rows = [row for row in embedded if isinstance(row, dict)]
        if rows:
            return rows

    from agent_bom.parsers.external_scanners import detect_and_parse

    packages = detect_and_parse(payload)
    findings = packages_to_bulk_findings(packages, source=source)
    if not findings:
        raise ValueError("scanner JSON parsed successfully but produced zero vulnerability findings")
    return findings


def load_push_findings_file(path: str | Path, *, source: str = "external_scan") -> list[dict[str, Any]]:
    """Read a JSON file and normalize it for bulk ingest."""

    text = Path(path).read_text(encoding="utf-8")
    payload = json.loads(text)
    return load_push_findings(payload, source=source)
