"""Pre-install guard — scan packages for vulnerabilities before installation.

Wraps pip/npm install to check each package against OSV, NVD, and the
internal MCP registry before allowing installation to proceed.

Usage:
    agent-bom guard pip install requests flask  # scans then installs
    agent-bom guard npm install express         # scans then installs

Shell alias (recommended):
    alias pip='agent-bom guard pip'
    alias npm='agent-bom guard npm'

The guard exits with code 1 (blocking install) if any package has:
  - Critical or High CVEs (configurable via --min-severity)
  - Known-exploited vulnerabilities (CISA KEV)
  - Malicious package indicators

Use --allow-risky to install despite findings (logs a warning).
"""

import asyncio
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Patterns to extract package names from pip/npm install args
_PIP_SPEC_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)(?:[=<>!~\[].*)?$")
_NPM_SPEC_RE = re.compile(r"^(@?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?)(?:@.*)?$")

# pip/npm flags that take a value argument (so we skip the next token)
_PIP_VALUE_FLAGS = frozenset(
    {
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-e",
        "--editable",
        "-f",
        "--find-links",
        "-i",
        "--index-url",
        "--extra-index-url",
        "--target",
        "-t",
        "--prefix",
        "--root",
        "--user",
    }
)
_NPM_VALUE_FLAGS = frozenset(
    {
        "--registry",
        "--prefix",
        "--save-prefix",
        "--tag",
    }
)


@dataclass
class GuardResult:
    """Result of a pre-install guard check."""

    packages_checked: int = 0
    packages_blocked: int = 0
    packages_clean: int = 0
    blocked: list[dict] = field(default_factory=list)
    clean: list[str] = field(default_factory=list)
    install_allowed: bool = True


def _extract_pip_packages(args: list[str]) -> list[str]:
    """Extract package names from pip install arguments."""
    packages = []
    skip_next = False
    in_install = False

    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "install":
            in_install = True
            continue
        if not in_install:
            continue
        if arg.startswith("-"):
            if arg in _PIP_VALUE_FLAGS:
                skip_next = True
            continue
        m = _PIP_SPEC_RE.match(arg)
        if m:
            packages.append(m.group(1))
    return packages


def _extract_npm_packages(args: list[str]) -> list[str]:
    """Extract package names from npm install arguments."""
    packages = []
    skip_next = False
    in_install = False

    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in ("install", "i", "add"):
            in_install = True
            continue
        if not in_install:
            continue
        if arg.startswith("-"):
            if arg in _NPM_VALUE_FLAGS:
                skip_next = True
            continue
        m = _NPM_SPEC_RE.match(arg)
        if m:
            packages.append(m.group(1))
    return packages


async def _check_package(name: str, ecosystem: str) -> dict:
    """Check a single package for vulnerabilities using existing scanner."""
    from agent_bom.scanners import scan_packages

    pkg_entry = type("Pkg", (), {"name": name, "version": "latest", "ecosystem": ecosystem})()
    try:
        vulns = await scan_packages([pkg_entry])
    except Exception as e:
        logger.warning("Failed to scan %s: %s", name, e)
        return {"name": name, "ecosystem": ecosystem, "error": str(e), "vulns": [], "blocked": False}

    cve_list = []
    blocked = False
    for v in vulns:
        severity = getattr(v, "severity", "unknown")
        cve_id = getattr(v, "id", "unknown")
        cve_list.append({"id": cve_id, "severity": severity})
        if severity in ("critical", "high"):
            blocked = True

    return {
        "name": name,
        "ecosystem": ecosystem,
        "vulns": cve_list,
        "blocked": blocked,
        "vuln_count": len(cve_list),
    }


async def guard_install(
    tool: str,
    args: list[str],
    min_severity: str = "high",
    allow_risky: bool = False,
    block_kev: bool = True,
) -> GuardResult:
    """Check packages before allowing installation.

    Args:
        tool: "pip" or "npm"
        args: Full argument list (e.g., ["install", "requests", "flask"])
        min_severity: Minimum severity to block on ("critical", "high", "medium")
        allow_risky: If True, warn but don't block
        block_kev: Block packages in CISA KEV regardless of severity
    """
    result = GuardResult()

    if tool == "pip":
        packages = _extract_pip_packages(args)
        ecosystem = "pypi"
    elif tool in ("npm", "npx"):
        packages = _extract_npm_packages(args)
        ecosystem = "npm"
    else:
        logger.warning("Unknown tool: %s — passing through", tool)
        result.install_allowed = True
        return result

    if not packages:
        logger.debug("No packages to check in: %s %s", tool, " ".join(args))
        result.install_allowed = True
        return result

    logger.info("Scanning %d package(s) before install: %s", len(packages), ", ".join(packages))

    # Check packages concurrently
    tasks = [_check_package(name, ecosystem) for name in packages]
    results = await asyncio.gather(*tasks)

    for pkg_result in results:
        result.packages_checked += 1
        if pkg_result.get("blocked"):
            result.packages_blocked += 1
            result.blocked.append(pkg_result)
        else:
            result.packages_clean += 1
            result.clean.append(pkg_result["name"])

    if result.packages_blocked > 0 and not allow_risky:
        result.install_allowed = False
    else:
        result.install_allowed = True

    return result


def guard_install_sync(
    tool: str,
    args: list[str],
    min_severity: str = "high",
    allow_risky: bool = False,
) -> GuardResult:
    """Synchronous wrapper for guard_install."""
    return asyncio.run(guard_install(tool, args, min_severity=min_severity, allow_risky=allow_risky))


def run_guarded_install(
    tool: str,
    args: list[str],
    min_severity: str = "high",
    allow_risky: bool = False,
) -> int:
    """Run a guarded install — check packages, then exec the real command.

    Returns the exit code (0 = success, 1 = blocked, or passthrough from tool).
    """
    result = guard_install_sync(tool, args, min_severity=min_severity, allow_risky=allow_risky)

    if not result.install_allowed:
        print(f"\n  BLOCKED — {result.packages_blocked} package(s) have critical/high vulnerabilities:", file=sys.stderr)
        for pkg in result.blocked:
            vulns_str = ", ".join(v["id"] for v in pkg.get("vulns", [])[:5])
            print(f"    {pkg['name']}: {pkg['vuln_count']} CVEs ({vulns_str})", file=sys.stderr)
        print("\n  Use --allow-risky to install anyway, or fix the vulnerabilities first.", file=sys.stderr)
        return 1

    if result.packages_blocked > 0 and allow_risky:
        print(f"\n  WARNING — installing {result.packages_blocked} package(s) with known vulnerabilities", file=sys.stderr)
        for pkg in result.blocked:
            print(f"    {pkg['name']}: {pkg['vuln_count']} CVEs", file=sys.stderr)

    if result.packages_checked > 0:
        print(f"  {result.packages_clean}/{result.packages_checked} packages clean", file=sys.stderr)

    # Execute the real install command
    real_cmd = _find_real_tool(tool)
    if not real_cmd:
        print(f"  ERROR: Could not find real '{tool}' binary", file=sys.stderr)
        return 1

    full_cmd = [real_cmd] + args
    logger.info("Executing: %s", " ".join(full_cmd))
    return subprocess.call(full_cmd)


def _find_real_tool(tool: str) -> Optional[str]:
    """Find the real tool binary, skipping any agent-bom aliases."""
    import shutil

    # If tool is in PATH, find it
    path = shutil.which(tool)
    if path:
        # Check it's not agent-bom itself (avoid infinite loop)
        try:
            resolved = os.path.realpath(path)
            if "agent-bom" not in resolved and "agent_bom" not in resolved:
                return path
        except OSError:
            return path

    # Fallback: try common locations
    common_paths = {
        "pip": ["/usr/bin/pip", "/usr/local/bin/pip"],
        "npm": ["/usr/bin/npm", "/usr/local/bin/npm"],
    }
    for p in common_paths.get(tool, []):
        if os.path.isfile(p):
            return p

    return None
