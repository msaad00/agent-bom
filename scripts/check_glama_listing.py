#!/usr/bin/env python3
"""Verify Glama's public listing is not serving stale release content."""

from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
README = ROOT / "README.md"
DEFAULT_URL = "https://glama.ai/mcp/servers/msaad00/agent-bom"


def _load_version() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("pyproject.toml version not found")
    return match.group(1)


def _load_readme_tool_count() -> str:
    text = README.read_text(encoding="utf-8")
    match = re.search(r"MCP server mode advertises\s+(\d+)\s+MCP tools", text)
    if not match:
        raise SystemExit("README.md MCP tool count sentence not found")
    return match.group(1)


def _fetch(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "agent-bom-release-check/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _check(page: str, version: str, tool_count: str) -> list[str]:
    failures: list[str] = []
    expected_tokens = [
        f"v{version}",
        f"MCP server mode advertises {tool_count} MCP tools",
    ]
    for token in expected_tokens:
        if token not in page:
            failures.append(f"missing current Glama listing token: {token!r}")

    stale_patterns = [
        r"uses:\s*msaad00/agent-bom@v0\.88\.4",
        r"MCP server mode advertises\s+55\s+MCP tools",
        r"18 tools for CVE scanning",
    ]
    for pattern in stale_patterns:
        if re.search(pattern, page):
            failures.append(f"stale Glama listing pattern still present: {pattern}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--delay-seconds", type=int, default=30)
    args = parser.parse_args()

    version = _load_version()
    tool_count = _load_readme_tool_count()
    last_error = ""
    for attempt in range(1, max(1, args.retries) + 1):
        try:
            page = _fetch(args.url, args.timeout)
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = f"failed to fetch Glama listing: {exc}"
        else:
            failures = _check(page, version, tool_count)
            if not failures:
                print(f"Glama listing is fresh for agent-bom v{version} with {tool_count} MCP tools")
                return 0
            last_error = "\n".join(failures)

        if attempt < args.retries:
            print(f"Glama listing freshness check failed on attempt {attempt}/{args.retries}: {last_error}")
            time.sleep(args.delay_seconds)

    print(f"ERROR: Glama listing is stale or unreachable:\n{last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
