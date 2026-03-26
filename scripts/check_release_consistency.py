#!/usr/bin/env python3
"""Validate README/docs storefront and release-surface consistency."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
DEMO_TAPE = ROOT / "docs" / "demo.tape"
DEMO_LATEST = ROOT / "docs" / "images" / "demo-latest.gif"


def _load_version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("pyproject.toml version not found")
    return match.group(1)


def _fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    version = _load_version()
    readme = README.read_text()
    demo_tape = DEMO_TAPE.read_text()

    required_readme_markers = [
        "img.shields.io/pypi/v/agent-bom",
        "img.shields.io/docker/pulls/agentbom/agent-bom",
        "docs/images/demo-latest.gif",
    ]
    for marker in required_readme_markers:
        if marker not in readme:
            _fail(f"README is missing required storefront marker: {marker}")

    forbidden_readme_markers = [
        "github/actions/workflow/status",
        "api.securityscorecards.dev",
        "img.shields.io/badge/OpenSSF",
        "img.shields.io/ossf-scorecard",
        "demo-v0.",
    ]
    for marker in forbidden_readme_markers:
        if marker in readme:
            _fail(f"README contains forbidden stale/noisy storefront marker: {marker}")

    if "demo-latest.gif" not in readme:
        _fail("README must reference docs/images/demo-latest.gif")
    if re.search(r"demo-v\d+\.\d+\.\d+\.gif", readme):
        _fail("README must not reference versioned demo GIF filenames")
    if "Output docs/images/demo-latest.gif" not in demo_tape:
        _fail("docs/demo.tape must render to docs/images/demo-latest.gif")
    if not DEMO_LATEST.exists():
        _fail("docs/images/demo-latest.gif is missing")

    leaked_patterns = [
        r"/Users/[^/\s]+",
        r"[A-Za-z]:\\Users\\[^\\\s]+",
    ]
    scan_roots = [ROOT / "README.md", ROOT / "docs"]
    for path in scan_roots:
        files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
        for file in files:
            if file.suffix.lower() in {".gif", ".png", ".jpg", ".jpeg", ".svg", ".ico"}:
                continue
            text = file.read_text(errors="ignore")
            for pattern in leaked_patterns:
                if re.search(pattern, text):
                    _fail(f"personal/local path leak found in {file.relative_to(ROOT)}")

    if f"agent-bom v{version}" not in demo_tape:
        _fail(f"docs/demo.tape header must include v{version}")

    print("README/docs release consistency checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
