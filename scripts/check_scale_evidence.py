#!/usr/bin/env python3
"""Verify the scale-evidence documentation scaffold is release-ready.

This checks structure and verifies measured pages point at checked-in raw
artifacts without pretending local synthetic results cover the broader
enterprise/EKS evidence tracked in #1806.
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
    "Owner issue:",
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
    if "Evidence status: measured" in text:
        marker = "Raw result artifact: `"
        if marker not in text:
            errors.append(f"{path.relative_to(ROOT)} missing measured raw result artifact")
        else:
            artifact = text.split(marker, 1)[1].split("`", 1)[0]
            artifact_path = ROOT / artifact
            if not artifact_path.exists():
                errors.append(f"{path.relative_to(ROOT)} references missing raw result artifact: {artifact}")
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
