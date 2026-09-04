#!/usr/bin/env python3
"""Fail closed on high/critical advisories for an npm lockfile."""

from __future__ import annotations

import argparse
import gzip
import io
import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

AUDIT_URL = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"
BLOCKING_SEVERITIES = {"high", "critical"}
VALID_SEVERITIES = {"info", "low", "moderate", "high", "critical"}
MAX_COMPRESSED_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_DECOMPRESSED_RESPONSE_BYTES = 32 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 120


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


def _validate_report(report: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(report, dict):
        raise ValueError("npm advisory response must be an object")
    for package, advisories in report.items():
        if not isinstance(package, str) or not isinstance(advisories, list):
            raise ValueError("npm advisory response has an invalid package entry")
        if any(not isinstance(advisory, dict) for advisory in advisories):
            raise ValueError("npm advisory response has an invalid advisory entry")
        for advisory in advisories:
            severity = advisory.get("severity")
            if not isinstance(severity, str) or severity.lower() not in VALID_SEVERITIES:
                raise ValueError("npm advisory response has an invalid severity")
    return report


def decode_report(body: bytes) -> dict[str, list[dict[str, Any]]]:
    """Decode a size-bounded response, including npm's unlabelled gzip."""
    if len(body) > MAX_COMPRESSED_RESPONSE_BYTES:
        raise ValueError("npm advisory compressed response exceeds the size limit")
    if body.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
            body = stream.read(MAX_DECOMPRESSED_RESPONSE_BYTES + 1)
        if len(body) > MAX_DECOMPRESSED_RESPONSE_BYTES:
            raise ValueError("npm advisory decompressed response exceeds the size limit")
    return _validate_report(json.loads(body.decode("utf-8")))


def blocking_advisories(report: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    blocking: list[dict[str, Any]] = []
    for package, advisories in sorted(report.items()):
        for advisory in advisories:
            severity = str(advisory.get("severity", "")).lower()
            if severity in BLOCKING_SEVERITIES:
                blocking.append(
                    {
                        "package": package,
                        "id": advisory.get("id"),
                        "severity": severity,
                        "title": advisory.get("title"),
                        "url": advisory.get("url"),
                    }
                )
    return blocking


def fetch_report(payload: dict[str, list[str]]) -> dict[str, list[dict[str, Any]]]:
    encoded = gzip.compress(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    request = urllib.request.Request(
        AUDIT_URL,
        data=encoded,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Encoding": "gzip",
            "Content-Type": "application/json",
            "User-Agent": "agent-bom-npm-advisory-gate/1",
        },
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310 -- fixed HTTPS registry URL
        return decode_report(response.read(MAX_COMPRESSED_RESPONSE_BYTES + 1))


def npm_install_audit_counts(path: Path) -> tuple[dict[str, int], int]:
    """Validate severity counts emitted by npm ci --json's completed audit."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("npm install report must be an object")
    audited = document.get("audited")
    if isinstance(audited, bool) or not isinstance(audited, int) or audited < 1:
        raise ValueError("npm install report did not audit any packages")
    audit = document.get("audit")
    counts = audit.get("vulnerabilities") if isinstance(audit, dict) else None
    required = (*sorted(VALID_SEVERITIES), "total")
    if not isinstance(counts, dict):
        raise ValueError("npm install report is missing vulnerability counts")
    normalized: dict[str, int] = {}
    for severity in required:
        value = counts.get(severity)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("npm install report has an invalid vulnerability count")
        normalized[severity] = value
    if normalized["total"] != sum(normalized[severity] for severity in VALID_SEVERITIES):
        raise ValueError("npm install report vulnerability total does not match severity counts")
    return normalized, audited


def run(path: Path, *, npm_install_report: Path | None = None) -> int:
    try:
        payload = lockfile_payload(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"::error::invalid npm lockfile for advisory scan ({type(exc).__name__})", file=sys.stderr)
        return 2

    if npm_install_report is not None:
        try:
            counts, audited = npm_install_audit_counts(npm_install_report)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"::error::invalid npm install audit report ({type(exc).__name__})", file=sys.stderr)
            return 2
        if audited < len(payload) + 1:
            print("::error::npm install audit report did not cover the exact lockfile inventory", file=sys.stderr)
            return 2
        if counts["high"] or counts["critical"]:
            print(json.dumps({"blocking_severity_counts": counts}, indent=2, sort_keys=True))
            return 1
        print(f"npm install audit gate passed: {len(payload)} package names, no high/critical vulnerabilities")
        return 0

    report: dict[str, list[dict[str, Any]]] | None = None
    for attempt in range(1, 4):
        try:
            report = _validate_report(fetch_report(payload))
            break
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            if attempt == 3:
                print(
                    f"::error::npm bulk advisory request failed after 3 attempts ({type(exc).__name__})",
                    file=sys.stderr,
                )
                return 2
            print(f"::warning::npm bulk advisory attempt {attempt} failed; retrying", file=sys.stderr)
            time.sleep(attempt * 2)

    assert report is not None
    blocking = blocking_advisories(report)
    if blocking:
        print(json.dumps({"blocking_advisories": blocking}, indent=2, sort_keys=True))
        return 1
    print(f"npm advisory gate passed: {len(payload)} package names, no high/critical vulnerabilities")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lockfile", type=Path)
    parser.add_argument(
        "--npm-install-report",
        type=Path,
        default=None,
        help="Validated JSON emitted by npm ci --json for the same exact lockfile.",
    )
    args = parser.parse_args()
    return run(args.lockfile, npm_install_report=args.npm_install_report)


if __name__ == "__main__":
    raise SystemExit(main())
