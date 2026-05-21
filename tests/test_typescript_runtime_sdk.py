"""Static contract checks for the TypeScript runtime SDK."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_INDEX = ROOT / "sdks" / "typescript" / "src" / "index.ts"


def test_runtime_sdk_detector_count_matches_exports() -> None:
    body = RUNTIME_INDEX.read_text(encoding="utf-8")

    header_count_match = re.search(r"\*\s+(\d+) detectors that analyze MCP JSON-RPC traffic", body)
    assert header_count_match is not None

    detector_exports = re.findall(r"^export \{ (?:[A-Z][A-Za-z]+(?:Detector|Analyzer|Tracker|Inspector)) \}", body, re.MULTILINE)

    assert int(header_count_match.group(1)) == len(detector_exports)
