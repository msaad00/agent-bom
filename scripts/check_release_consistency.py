#!/usr/bin/env python3
"""Validate README/docs storefront and release-surface consistency."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
PYPI_README = ROOT / "PYPI_README.md"
DEMO_TAPE = ROOT / "docs" / "demo.tape"
DEMO_LATEST = ROOT / "docs" / "images" / "demo-latest.gif"
GLAMA_SERVER = ROOT / "integrations" / "glama" / "server.json"
DOCKER_README = ROOT / "DOCKER_HUB_README.md"
TOP_DOCKERFILE = ROOT / "Dockerfile"
PYPROJECT = ROOT / "pyproject.toml"


def _load_version() -> str:
    text = PYPROJECT.read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("pyproject.toml version not found")
    return match.group(1)


def _load_description() -> str:
    text = PYPROJECT.read_text()
    match = re.search(r'^description\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("pyproject.toml description not found")
    return match.group(1)


def _fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    version = _load_version()
    description = _load_description()
    readme = README.read_text()
    pypi_readme = PYPI_README.read_text()
    demo_tape = DEMO_TAPE.read_text()

    required_github_markers = [
        "img.shields.io/github/actions/workflow/status",
        "img.shields.io/pypi/v/agent-bom",
        "img.shields.io/docker/pulls/agentbom/agent-bom",
        "img.shields.io/ossf-scorecard",
        "docs/images/demo-latest.gif",
    ]
    for marker in required_github_markers:
        if marker not in readme:
            _fail(f"README is missing required storefront marker: {marker}")

    required_pypi_markers = [
        "mcp-name: io.github.msaad00/agent-bom",
        "docs/images/demo-latest.gif",
        "docs/images/scan-pipeline-light.svg",
        "docs/images/blast-radius-light.svg",
    ]
    for marker in required_pypi_markers:
        if marker not in pypi_readme:
            _fail(f"PYPI_README.md is missing required storefront marker: {marker}")

    forbidden_pypi_markers = [
        "img.shields.io/github/actions/workflow/status",
        "img.shields.io/ossf-scorecard",
        "api.securityscorecards.dev",
        "```mermaid",
        "flowchart ",
        "demo-v0.",
        "@mcp/server-filesystem /tmp",
    ]
    for marker in forbidden_pypi_markers:
        if marker in pypi_readme:
            _fail(f"PYPI_README.md contains forbidden storefront marker: {marker}")

    if "demo-latest.gif" not in readme:
        _fail("README must reference docs/images/demo-latest.gif")
    if "demo-latest.gif" not in pypi_readme:
        _fail("PYPI_README.md must reference docs/images/demo-latest.gif")
    if re.search(r"demo-v\d+\.\d+\.\d+\.gif", readme):
        _fail("README must not reference versioned demo GIF filenames")
    if re.search(r"demo-v\d+\.\d+\.\d+\.gif", pypi_readme):
        _fail("PYPI_README.md must not reference versioned demo GIF filenames")
    if "Output docs/images/demo-latest.gif" not in demo_tape:
        _fail("docs/demo.tape must render to docs/images/demo-latest.gif")
    if not DEMO_LATEST.exists():
        _fail("docs/images/demo-latest.gif is missing")

    if len(description) > 120:
        _fail("pyproject.toml description must stay concise for PyPI storefront rendering")
    stale_description_markers = [
        "Security scanner for AI infrastructure and supply chain.",
        "19 output formats",
        "20-page Next.js dashboard",
        "14-framework compliance",
    ]
    for marker in stale_description_markers:
        if marker in description:
            _fail(f"pyproject.toml description contains stale storefront phrase: {marker}")

    leaked_patterns = [
        r"/Users/[^/\s]+",
        r"[A-Za-z]:\\Users\\[^\\\s]+",
    ]
    scan_roots = [ROOT / "README.md", ROOT / "PYPI_README.md", ROOT / "docs"]
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

    glama_text = GLAMA_SERVER.read_text()
    if f'"version": "{version}"' not in glama_text:
        _fail(f"integrations/glama/server.json must be aligned to {version}")
    if f"`v{version}` | Current stable version (pinned)" not in DOCKER_README.read_text():
        _fail(f"DOCKER_HUB_README.md must mark v{version} as the current stable version")
    if f"ARG VERSION={version}" not in TOP_DOCKERFILE.read_text():
        _fail(f"Dockerfile ARG VERSION must be {version}")

    print("README/PyPI/docs release consistency checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
