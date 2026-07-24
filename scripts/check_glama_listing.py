#!/usr/bin/env python3
"""Verify Glama's public listing is not serving stale release content."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
README = ROOT / "README.md"
DEFAULT_URL = "https://glama.ai/mcp/servers/msaad00/agent-bom"


def _env_or(name: str, default: str) -> str:
    """Return env var if non-blank; otherwise ``default``.

    GitHub Actions injects unset ``vars.*`` as empty strings into ``env:``,
    so ``os.environ.get(name, default)`` would keep ``""`` and skip the default.
    """
    value = (os.environ.get(name) or "").strip()
    return value or default

GLAMA_DOCKERFILE = "integrations/glama/Dockerfile"
GLAMA_MANIFESTS = (ROOT / "glama.json", ROOT / "integrations" / "glama" / "server.json")


def _is_current_checkout_ref(git_ref: str) -> bool:
    return git_ref in {"HEAD", ".", ""}


def _read_repo_file(relative_path: str, *, git_ref: str | None = None) -> str:
    if not git_ref:
        return (ROOT / relative_path).read_text(encoding="utf-8")
    try:
        return subprocess.check_output(
            ["git", "show", f"{git_ref}:{relative_path}"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        if _is_current_checkout_ref(git_ref):
            checkout_path = ROOT / relative_path
            if checkout_path.exists():
                return checkout_path.read_text(encoding="utf-8")
        detail = (exc.stderr or "").strip()
        raise FileNotFoundError(f"{relative_path} at {git_ref}: {detail}") from exc


def _load_version() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("pyproject.toml version not found")
    return match.group(1)


def _load_readme_tool_count() -> str:
    text = README.read_text(encoding="utf-8")
    # Prefer the current README phrasing ("exposes"); keep "advertises" as a
    # fallback so older release tags still parse during surface-freshness probes.
    match = re.search(r"MCP server mode (?:exposes|advertises)\s+(\d+)\s+MCP tools", text)
    if not match:
        raise SystemExit("README.md MCP tool count sentence not found")
    return match.group(1)


def verify_build_manifest(git_ref: str | None = None) -> list[str]:
    """Ensure Glama manifests point at the curated Dockerfile before rebuild."""

    failures: list[str] = []
    try:
        dockerfile_text = _read_repo_file(GLAMA_DOCKERFILE, git_ref=git_ref)
    except FileNotFoundError:
        location = f" at {git_ref}" if git_ref else ""
        failures.append(f"missing Glama Dockerfile at {GLAMA_DOCKERFILE}{location}")
    else:
        if "RUN uv sync --locked --no-dev --no-editable --extra mcp-server" not in dockerfile_text:
            failures.append(f"{GLAMA_DOCKERFILE} must install the mcp-server extra from the reviewed uv.lock")
        if "COPY --from=builder /app/.venv /app/.venv" not in dockerfile_text:
            failures.append(f"{GLAMA_DOCKERFILE} must copy the locked virtual environment into the runtime image")
        if "ENV VIRTUAL_ENV=/app/.venv" not in dockerfile_text:
            failures.append(f"{GLAMA_DOCKERFILE} must expose the locked virtual environment")
        if 'ENV PATH="/app/.venv/bin:${PATH}"' not in dockerfile_text:
            failures.append(f"{GLAMA_DOCKERFILE} must put the locked virtual environment on mcp-proxy PATH")
        if 'ENTRYPOINT ["agent-bom", "mcp", "server"]' not in dockerfile_text:
            failures.append(f"{GLAMA_DOCKERFILE} must ENTRYPOINT agent-bom mcp server")

    for manifest in GLAMA_MANIFESTS:
        manifest_path = str(manifest.relative_to(ROOT))
        try:
            manifest_text = _read_repo_file(manifest_path, git_ref=git_ref)
        except FileNotFoundError:
            location = f" at {git_ref}" if git_ref else ""
            failures.append(f"missing Glama manifest: {manifest_path}{location}")
            continue
        data = json.loads(manifest_text)
        if data.get("dockerfile") != GLAMA_DOCKERFILE:
            failures.append(f"{manifest_path} dockerfile must be {GLAMA_DOCKERFILE!r}, found {data.get('dockerfile')!r}")
    return failures


def _fetch(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "agent-bom-release-check/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _check(page: str, version: str, tool_count: str) -> list[str]:
    expected_tokens = [
        f"v{version}",
        # Accept either phrasing while Glama's rendered README catches up.
        # Presence of the tool-count sentence is what matters for freshness.
    ]
    failures = [f"missing current Glama listing token: {token!r}" for token in expected_tokens if token not in page]
    tool_count_ok = bool(
        re.search(rf"MCP server mode (?:exposes|advertises)\s+{re.escape(tool_count)}\s+MCP tools", page)
        or f"MCP server mode exposes {tool_count} MCP tools" in page
        or f"MCP server mode advertises {tool_count} MCP tools" in page
    )
    if not tool_count_ok:
        failures.append(f"missing current Glama listing token: 'MCP server mode exposes|advertises {tool_count} MCP tools'")

    stale_patterns = [
        r"uses:\s*msaad00/agent-bom@v0\.88\.4",
        r"MCP server mode (?:exposes|advertises)\s+55\s+MCP tools",
        r"18 tools for CVE scanning",
        r"98c3e543",  # pre-0.92.0 pinned Glama build ref from audit #3472
        r"git checkout 98c3e543",
    ]
    failures.extend(f"stale Glama listing pattern still present: {pattern}" for pattern in stale_patterns if re.search(pattern, page))
    return failures


def _extract_listing_version(page: str) -> str:
    """Best-effort version extraction from Glama's rendered listing."""

    patterns = [
        r"uses:\s*msaad00/agent-bom@v([0-9]+\.[0-9]+\.[0-9]+)",
        r"\bv([0-9]+\.[0-9]+\.[0-9]+)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, page)
        if match:
            return match.group(1)
    return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=_env_or("GLAMA_LISTING_URL", DEFAULT_URL))
    parser.add_argument("--expected", default=None, help="Expected version; defaults to pyproject.toml.")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable freshness result.")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--delay-seconds", type=int, default=30)
    parser.add_argument(
        "--verify-manifest",
        action="store_true",
        help="Validate glama.json/server.json and integrations/glama/Dockerfile, then exit.",
    )
    parser.add_argument(
        "--git-ref",
        default=None,
        help="Read manifest files from this git ref/SHA while running trusted checker code.",
    )
    args = parser.parse_args(argv)

    if args.verify_manifest:
        failures = verify_build_manifest(args.git_ref)
        if failures:
            print("ERROR: Glama build manifest check failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        suffix = f" at {args.git_ref}" if args.git_ref else ""
        print(f"Glama build manifest is valid ({GLAMA_DOCKERFILE}{suffix})")
        return 0

    version = (args.expected or _load_version()).lstrip("v").strip()
    tool_count = _load_readme_tool_count()
    last_error = ""
    listing_version = "unknown"
    for attempt in range(1, max(1, args.retries) + 1):
        try:
            page = _fetch(args.url, args.timeout)
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = f"failed to fetch Glama listing: {exc}"
        else:
            listing_version = _extract_listing_version(page)
            failures = _check(page, version, tool_count)
            if not failures:
                if args.json:
                    print(
                        json.dumps(
                            {
                                "surface": "Glama",
                                "status": "fresh",
                                "expected": version,
                                "listing_version": listing_version,
                                "tool_count": tool_count,
                            },
                            separators=(",", ":"),
                        )
                    )
                    return 0
                print(f"Glama listing is fresh for agent-bom v{version} with {tool_count} MCP tools")
                return 0
            last_error = "\n".join(failures)

        if attempt < args.retries:
            print(f"Glama listing freshness check failed on attempt {attempt}/{args.retries}: {last_error}")
            time.sleep(args.delay_seconds)

    if args.json:
        print(
            json.dumps(
                {
                    "surface": "Glama",
                    "status": "stale" if listing_version != "unknown" else "unreachable",
                    "expected": version,
                    "listing_version": listing_version,
                    "tool_count": tool_count,
                    "error": last_error,
                },
                separators=(",", ":"),
            )
        )
    print(f"ERROR: Glama listing is stale or unreachable:\n{last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
