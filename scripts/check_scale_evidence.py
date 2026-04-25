#!/usr/bin/env python3
"""Verify the scale-evidence documentation scaffold is release-ready.

This intentionally checks structure, not performance values. The first PR for
#1806 should make the evidence lanes hard to forget without pretending the
numbers have already been measured.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PERF_DIR = ROOT / "docs" / "perf"

REQUIRED_FILES = (
    PERF_DIR / "p95-p99-graph-query.md",
    PERF_DIR / "ingest-throughput.md",
    PERF_DIR / "fleet-reconciliation.md",
)

REQUIRED_MARKERS = (
    "Evidence status:",
    "Owner issue: #1806",
    "## Claim",
    "## Scope",
    "## Environment",
    "## Commands",
    "## Results",
    "## Gaps",
)


def _check_file(path: Path) -> list[str]:
    errors: list[str] = []
    if not path.exists():
        return [f"missing required evidence file: {path.relative_to(ROOT)}"]
    text = path.read_text(encoding="utf-8")
    for marker in REQUIRED_MARKERS:
        if marker not in text:
            errors.append(f"{path.relative_to(ROOT)} missing marker: {marker}")
    if "TBD" not in text and "Evidence status: measured" not in text:
        errors.append(f"{path.relative_to(ROOT)} must either keep TBD placeholders or declare measured evidence")
    return errors


def main() -> int:
    errors: list[str] = []
    for path in REQUIRED_FILES:
        errors.extend(_check_file(path))
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
