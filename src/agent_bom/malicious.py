"""Malicious package detection — MAL- prefix from OSV + typosquat heuristics.

The OpenSSF Malicious Packages repository publishes reports in OSV format
with MAL- prefixed IDs. These are indexed in OSV.dev and returned in
agent-bom's existing batch scan results. This module makes detection
explicit and adds typosquat distance checking against popular packages.

Reference: https://github.com/ossf/malicious-packages
"""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import Package


def is_malicious_vuln(vuln_id: str) -> bool:
    """Check if a vulnerability ID indicates a known malicious package."""
    return vuln_id.upper().startswith("MAL-")


def flag_malicious_from_vulns(package: Package) -> None:
    """Flag a package as malicious if any of its vulnerabilities have MAL- IDs.

    Mutates package.is_malicious and package.malicious_reason in-place.
    """
    mal_ids = [v.id for v in package.vulnerabilities if is_malicious_vuln(v.id)]
    if mal_ids:
        package.is_malicious = True
        package.malicious_reason = f"Known malicious package ({', '.join(mal_ids[:3])})"


# ─── Typosquat detection ─────────────────────────────────────────────────────

# Popular packages commonly targeted by typosquat attacks.
# Sourced from npm/PyPI download counts + known typosquat campaigns.
_POPULAR_PACKAGES: dict[str, frozenset[str]] = {
    "npm": frozenset(
        {
            "express",
            "lodash",
            "axios",
            "react",
            "react-dom",
            "next",
            "typescript",
            "webpack",
            "babel-core",
            "eslint",
            "prettier",
            "commander",
            "chalk",
            "inquirer",
            "dotenv",
            "cors",
            "jsonwebtoken",
            "bcrypt",
            "mongoose",
            "sequelize",
            "socket.io",
            "nodemailer",
            "passport",
            "helmet",
            "uuid",
            "moment",
            "dayjs",
            "zod",
            "yup",
        }
    ),
    "pypi": frozenset(
        {
            "requests",
            "flask",
            "django",
            "numpy",
            "pandas",
            "scipy",
            "tensorflow",
            "torch",
            "transformers",
            "scikit-learn",
            "boto3",
            "httpx",
            "fastapi",
            "uvicorn",
            "pydantic",
            "sqlalchemy",
            "celery",
            "redis",
            "pillow",
            "beautifulsoup4",
            "cryptography",
            "paramiko",
            "fabric",
            "ansible",
            "openai",
            "anthropic",
            "langchain",
            "litellm",
        }
    ),
}


def check_typosquat(name: str, ecosystem: str, threshold: float = 0.85) -> str | None:
    """Check if a package name looks like a typosquat of a popular package.

    Returns the suspected target package name, or None if no match.
    Uses SequenceMatcher ratio — same approach as parsers/skill_audit.py.
    """
    popular = _POPULAR_PACKAGES.get(ecosystem.lower(), frozenset())
    if not popular:
        return None

    # Exact match = not a typosquat
    if name.lower() in {p.lower() for p in popular}:
        return None

    best_ratio = 0.0
    best_match = ""
    for pkg_name in popular:
        ratio = SequenceMatcher(None, name.lower(), pkg_name.lower()).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_match = pkg_name

    if best_ratio >= threshold:
        return best_match
    return None


# ── Dependency confusion detection ─────────────────────────────────────────
#
# Dependency confusion attacks exploit the gap between private/internal
# package registries and public ones. An attacker publishes a package on
# PyPI/npm with the same name as an internal package, at a higher version,
# and the package manager prefers the public one.
#
# Detection heuristics (no network — static analysis only):
# 1. Package name matches common internal naming patterns
# 2. Package not found in OSV/NVD (no vulnerability data = likely private)
# 3. Package has no registry metadata (version resolution failed)

# Patterns that suggest internal/private package names
_INTERNAL_NAME_PATTERNS: frozenset[str] = frozenset(
    {
        "internal-",
        "private-",
        "corp-",
        "company-",
        "-internal",
        "-private",
        "-corp",
        "-infra",
        "-platform",
        "-shared",
        "-common",
        "-utils",
        "-core",
        "-sdk",
        "-lib",
        "-service",
        "-api",
    }
)

# Scoped npm packages from known orgs are NOT confusion risks
_SAFE_NPM_SCOPES: frozenset[str] = frozenset(
    {
        "@modelcontextprotocol/",
        "@anthropic-ai/",
        "@google-cloud/",
        "@azure/",
        "@aws-sdk/",
        "@types/",
        "@babel/",
        "@eslint/",
        "@testing-library/",
        "@playwright/",
        "@vercel/",
        "@next/",
    }
)


def check_dependency_confusion(package: "Package") -> str | None:
    """Check if a package name looks like it could be a dependency confusion target.

    Returns a warning string if the name matches internal naming patterns
    and has no vulnerability data (suggesting it may be a private package
    that an attacker could shadow on a public registry).

    Returns None if no confusion risk detected.
    """
    name = package.name.lower()
    eco = package.ecosystem.lower()

    # Scoped npm packages from known orgs are safe
    if eco == "npm" and any(name.startswith(scope) for scope in _SAFE_NPM_SCOPES):
        return None

    # Check for internal naming patterns
    has_internal_pattern = any(pat in name for pat in _INTERNAL_NAME_PATTERNS)
    if not has_internal_pattern:
        return None

    # If the package has vulnerability data, it's a known public package
    if package.vulnerabilities:
        return None

    # If version was resolved from a registry, it's a known public package
    if package.version not in ("unknown", "latest", ""):
        # Has a resolved version — likely exists on public registry
        # Only flag if it also has internal naming AND no scorecard data
        if getattr(package, "scorecard_score", None) is not None:
            return None

    return (
        f"Dependency confusion risk: '{package.name}' matches internal naming patterns "
        f"and has no public vulnerability or scorecard data. Verify this package is "
        f"from your intended registry."
    )
