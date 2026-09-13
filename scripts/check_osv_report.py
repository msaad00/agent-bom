"""Fail closed on OSV execution/report errors; allow only unfixed advisories.

Consumes OSV-Scanner v2 JSON, never its human-readable table. Exit status 1
means findings; other nonzero statuses are scanner failures, not exemptions.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def evaluate(report: object, status: int) -> bool:
    """Return whether a complete, structurally valid report passes the gate."""
    if status not in (0, 1) or not isinstance(report, dict):
        return False
    results = report.get("results")
    if not isinstance(results, list):
        return False
    findings = 0
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("packages"), list):
            return False
        for package in result["packages"]:
            if not isinstance(package, dict):
                return False
            vulnerabilities = package.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                return False
            for vulnerability in vulnerabilities:
                findings += 1
                if not isinstance(vulnerability, dict) or not vulnerability.get("id"):
                    return False
                affected = vulnerability.get("affected")
                if not isinstance(affected, list) or not affected:
                    return False
                for item in affected:
                    if not isinstance(item, dict) or not isinstance(item.get("package"), dict):
                        return False
                    ranges = item.get("ranges", [])
                    if not isinstance(ranges, list):
                        return False
                    for version_range in ranges:
                        if not isinstance(version_range, dict) or not isinstance(version_range.get("events"), list):
                            return False
                        for event in version_range["events"]:
                            if not isinstance(event, dict) or "fixed" in event:
                                return False
    # A findings exit without findings is not evidence for an exemption.
    return (status == 0 and findings == 0) or (status == 1 and findings > 0)


def main() -> int:
    try:
        report = json.loads(Path(sys.argv[1]).read_text())
        status = int(sys.argv[2])
    except (OSError, ValueError, IndexError):
        print("::error::OSV report is missing or invalid")
        return 1
    if not evaluate(report, status):
        print("::error::OSV scan failed, report is incomplete, or a finding has an available fix")
        return 1
    print("OSV gate passed: no findings or only advisories without recorded fixes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
