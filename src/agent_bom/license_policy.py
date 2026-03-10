"""License policy engine — categorize, evaluate, and report license compliance.

Uses the ``license-expression`` library (transitive dep via cyclonedx-python-lib)
for proper SPDX expression parsing, deprecated ID normalization, and access to the
full ScanCode license index (2,500+ licenses with category metadata).

Provides SPDX license categorization, policy evaluation against configurable
block/warn lists, and Rich console output for license findings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from fnmatch import fnmatch

from agent_bom.models import Agent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SPDX license index — built from license-expression's vendored ScanCode data
# ---------------------------------------------------------------------------

# Map library categories → our risk tiers
_CATEGORY_TO_TIER: dict[str, tuple[str, str]] = {
    "Permissive": ("permissive", "low"),
    "Public Domain": ("permissive", "low"),
    "Copyleft Limited": ("weak_copyleft", "medium"),
    "Copyleft": ("strong_copyleft", "high"),
    "Source-available": ("source_available", "high"),
    "Free Restricted": ("restricted", "medium"),
    "Proprietary Free": ("proprietary", "medium"),
    "Commercial": ("commercial_risk", "critical"),
    "CLA": ("permissive", "low"),
    "Patent License": ("permissive", "low"),
    "Unstated License": ("unknown", "medium"),
}

# Network-copyleft overrides — AGPL/EUPL/OSL are stricter than regular copyleft.
# These get "network_copyleft" category with "critical" risk because they trigger
# on network use (not just distribution), which catches SaaS/API deployments.
_NETWORK_COPYLEFT: set[str] = {
    "AGPL-1.0-only",
    "AGPL-1.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "EUPL-1.1",
    "EUPL-1.2",
    "OSL-3.0",
    "OSL-2.1",
    "OSL-2.0",
    "OSL-1.0",
    "RPL-1.1",
    "RPL-1.5",
    "Watcom-1.0",
}

# Commercial/source-available overrides — these are NOT open source despite
# sometimes appearing in open ecosystems (MariaDB BSL→BUSL, MongoDB SSPL, etc.)
_COMMERCIAL_RISK: set[str] = {
    "SSPL-1.0",
    "BUSL-1.1",  # Business Source License — SPDX key is BUSL, not BSL
    "Elastic-2.0",
}

# Backward compat aliases — users may pass non-SPDX IDs in policy files
_ALIASES: dict[str, str] = {
    "BSL-1.1": "BUSL-1.1",
    "Commons-Clause": "Commons-Clause",  # Not in SPDX index, flagged as unknown
}


def _build_spdx_index() -> dict[str, tuple[str, str]]:
    """Build SPDX key → (category, risk_level) lookup from license-expression index.

    Falls back to hardcoded sets if the library is unavailable.
    """
    index: dict[str, tuple[str, str]] = {}

    try:
        from license_expression import get_license_index

        for entry in get_license_index():
            spdx_key = entry.get("spdx_license_key", "")
            if not spdx_key or entry.get("is_exception"):
                continue

            # Network-copyleft overrides
            if spdx_key in _NETWORK_COPYLEFT:
                index[spdx_key] = ("network_copyleft", "critical")
                continue

            # Commercial-risk overrides
            if spdx_key in _COMMERCIAL_RISK:
                index[spdx_key] = ("commercial_risk", "critical")
                continue

            category = entry.get("category", "")
            tier = _CATEGORY_TO_TIER.get(category, ("unknown", "medium"))
            index[spdx_key] = tier

    except ImportError:
        logger.debug("license-expression not available, using hardcoded license sets")
        # Fallback: hardcoded sets from original implementation
        for lic in (
            "MIT",
            "Apache-2.0",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "0BSD",
            "Unlicense",
            "CC0-1.0",
            "CC-BY-4.0",
            "Zlib",
            "BSL-1.0",
            "PSF-2.0",
            "Python-2.0",
            "BlueOak-1.0.0",
        ):
            index[lic] = ("permissive", "low")
        for lic in (
            "LGPL-2.1-only",
            "LGPL-2.1-or-later",
            "LGPL-3.0-only",
            "LGPL-3.0-or-later",
            "MPL-2.0",
            "EPL-2.0",
            "EPL-1.0",
            "CDDL-1.0",
            "CDDL-1.1",
            "CPL-1.0",
        ):
            index[lic] = ("weak_copyleft", "medium")
        for lic in ("GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later"):
            index[lic] = ("strong_copyleft", "high")
        for lic in _NETWORK_COPYLEFT:
            index[lic] = ("network_copyleft", "critical")
        for lic in _COMMERCIAL_RISK:
            index[lic] = ("commercial_risk", "critical")
        index["SSPL-1.0"] = ("commercial_risk", "critical")
        index["Elastic-2.0"] = ("commercial_risk", "critical")

    return index


# Module-level singleton — built once at import time
_SPDX_INDEX: dict[str, tuple[str, str]] = _build_spdx_index()

# Expose legacy sets for backward compatibility (tests reference these)
PERMISSIVE: set[str] = {k for k, v in _SPDX_INDEX.items() if v[0] == "permissive"}
WEAK_COPYLEFT: set[str] = {k for k, v in _SPDX_INDEX.items() if v[0] == "weak_copyleft"}
STRONG_COPYLEFT: set[str] = {k for k, v in _SPDX_INDEX.items() if v[0] == "strong_copyleft"}
COMMERCIAL_RISK: set[str] = {k for k, v in _SPDX_INDEX.items() if v[0] == "commercial_risk"}
NETWORK_COPYLEFT: set[str] = {k for k, v in _SPDX_INDEX.items() if v[0] == "network_copyleft"}

# Default policy: block strong/network copyleft + commercial risk, warn weak copyleft
DEFAULT_LICENSE_POLICY: dict = {
    "license_block": ["GPL-*", "AGPL-*", "SSPL-*", "BUSL-*", "BSL-1.1", "Elastic-*", "EUPL-*", "OSL-*"],
    "license_warn": ["LGPL-*", "MPL-*", "EPL-*", "CDDL-*"],
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class LicenseFinding:
    """A single license compliance finding."""

    package_name: str
    package_version: str
    ecosystem: str
    license_id: str  # SPDX identifier
    license_expression: str  # Full SPDX expression if available
    category: str  # permissive, weak_copyleft, strong_copyleft, network_copyleft, commercial_risk, unknown
    risk_level: str  # low, medium, high, critical
    reason: str  # Human-readable explanation
    agents: list[str] = field(default_factory=list)


@dataclass
class LicenseReport:
    """Aggregated license compliance report."""

    findings: list[LicenseFinding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    compliant: bool = True
    unknown_count: int = 0
    total_packages: int = 0


# ---------------------------------------------------------------------------
# SPDX expression parsing
# ---------------------------------------------------------------------------

_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _parse_expression_keys(expression: str) -> list[str]:
    """Parse an SPDX expression into individual license keys.

    Uses license-expression for proper parsing (handles WITH exceptions,
    nested parens, deprecated ID normalization like GPL-2.0 → GPL-2.0-only).
    Falls back to naive split on OR/AND if library unavailable.
    """
    try:
        from license_expression import get_spdx_licensing

        spdx = get_spdx_licensing()
        parsed = spdx.parse(expression)
        if parsed is not None:
            return spdx.license_keys(parsed)
    except (ImportError, Exception):  # noqa: BLE001
        pass

    # Fallback: naive split (original behavior)
    cleaned = expression.replace("(", "").replace(")", "")
    parts = []
    for chunk in cleaned.split(" OR "):
        for sub in chunk.split(" AND "):
            key = sub.strip()
            # Strip WITH exceptions (e.g., "GPL-2.0-only WITH Classpath-exception-2.0")
            if " WITH " in key:
                key = key.split(" WITH ")[0].strip()
            if key:
                parts.append(key)
    return parts


def _categorize_single(spdx_key: str) -> tuple[str, str]:
    """Categorize a single SPDX license key (not an expression)."""
    if not spdx_key:
        return "unknown", "medium"

    # Check alias map
    resolved = _ALIASES.get(spdx_key, spdx_key)

    # Look up in index
    if resolved in _SPDX_INDEX:
        return _SPDX_INDEX[resolved]

    return "unknown", "medium"


def categorize_license(spdx_id: str) -> tuple[str, str]:
    """Categorize an SPDX license identifier or expression.

    Returns (category, risk_level) where:
    - category: permissive, weak_copyleft, strong_copyleft, network_copyleft,
                commercial_risk, source_available, restricted, proprietary, unknown
    - risk_level: low, medium, high, critical

    Handles compound expressions:
    - OR: licensee chooses → picks the most permissive (lowest risk)
    - AND: all apply → picks the most restrictive (highest risk)
    - WITH: exception modifies base license → categorize base only
    """
    if not spdx_id:
        return "unknown", "medium"

    normalized = spdx_id.strip()
    if not normalized:
        return "unknown", "medium"

    # Try direct lookup first (fast path for simple IDs)
    direct = _categorize_single(normalized)
    if direct[0] != "unknown":
        return direct

    # Check if it's a compound expression
    is_compound = any(op in normalized for op in (" OR ", " AND ", " WITH "))
    if not is_compound:
        # Try parsing as deprecated ID (e.g., GPL-2.0 → GPL-2.0-only)
        keys = _parse_expression_keys(normalized)
        if len(keys) == 1 and keys[0] != normalized:
            return _categorize_single(keys[0])
        return "unknown", "medium"

    # Parse compound expression
    keys = _parse_expression_keys(normalized)
    if not keys:
        return "unknown", "medium"

    categories = [_categorize_single(k) for k in keys]

    # Determine if OR or AND dominates
    if " OR " in normalized and " AND " not in normalized:
        # Pure OR: pick most permissive
        return min(categories, key=lambda c: _RISK_ORDER.get(c[1], 99))
    elif " AND " in normalized and " OR " not in normalized:
        # Pure AND: pick most restrictive
        return max(categories, key=lambda c: _RISK_ORDER.get(c[1], 99))
    else:
        # Mixed: let the parser handle it, take most restrictive (conservative)
        return max(categories, key=lambda c: _RISK_ORDER.get(c[1], 99))


def _matches_pattern(license_id: str, patterns: list[str]) -> bool:
    """Check if a license ID matches any of the glob patterns."""
    for pattern in patterns:
        if fnmatch(license_id, pattern):
            return True
        # Also match BSL-1.1 alias for BUSL-1.1
        resolved = _ALIASES.get(license_id, "")
        if resolved and fnmatch(resolved, pattern):
            return True
    return False


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------


def evaluate_license_policy(
    agents: list[Agent],
    policy: dict | None = None,
) -> LicenseReport:
    """Evaluate all packages across agents against a license policy.

    Args:
        agents: List of agents with their servers and packages.
        policy: Optional policy dict with keys:
            - license_block: list of SPDX glob patterns to block (e.g., ["GPL-*"])
            - license_warn: list of SPDX glob patterns to warn (e.g., ["LGPL-*"])
            If None, uses DEFAULT_LICENSE_POLICY.

    Returns:
        LicenseReport with findings, summary, and compliance status.
    """
    if policy is None:
        policy = DEFAULT_LICENSE_POLICY

    block_patterns = policy.get("license_block", [])
    warn_patterns = policy.get("license_warn", [])

    report = LicenseReport()
    seen_packages: set[tuple[str, str, str]] = set()  # (name, version, ecosystem)

    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                pkg_key = (pkg.name, pkg.version, pkg.ecosystem)
                if pkg_key in seen_packages:
                    # Already evaluated, just add agent name to existing finding
                    for f in report.findings:
                        if f.package_name == pkg.name and f.package_version == pkg.version:
                            if agent.name not in f.agents:
                                f.agents.append(agent.name)
                    continue
                seen_packages.add(pkg_key)
                report.total_packages += 1

                lic_id = pkg.license or ""
                lic_expr = pkg.license_expression or lic_id

                if not lic_id:
                    report.unknown_count += 1
                    report.findings.append(
                        LicenseFinding(
                            package_name=pkg.name,
                            package_version=pkg.version,
                            ecosystem=pkg.ecosystem,
                            license_id="UNKNOWN",
                            license_expression="UNKNOWN",
                            category="unknown",
                            risk_level="medium",
                            reason="No license information available",
                            agents=[agent.name],
                        )
                    )
                    continue

                category, risk_level = categorize_license(lic_id)

                # Check block patterns
                if _matches_pattern(lic_id, block_patterns):
                    report.compliant = False
                    report.findings.append(
                        LicenseFinding(
                            package_name=pkg.name,
                            package_version=pkg.version,
                            ecosystem=pkg.ecosystem,
                            license_id=lic_id,
                            license_expression=lic_expr,
                            category=category,
                            risk_level="critical",
                            reason=f"License {lic_id} is blocked by policy",
                            agents=[agent.name],
                        )
                    )
                elif _matches_pattern(lic_id, warn_patterns):
                    report.findings.append(
                        LicenseFinding(
                            package_name=pkg.name,
                            package_version=pkg.version,
                            ecosystem=pkg.ecosystem,
                            license_id=lic_id,
                            license_expression=lic_expr,
                            category=category,
                            risk_level="high",
                            reason=f"License {lic_id} requires review (policy warning)",
                            agents=[agent.name],
                        )
                    )
                elif category in ("strong_copyleft", "network_copyleft", "commercial_risk", "source_available"):
                    report.compliant = False if category in ("network_copyleft", "commercial_risk") else report.compliant
                    report.findings.append(
                        LicenseFinding(
                            package_name=pkg.name,
                            package_version=pkg.version,
                            ecosystem=pkg.ecosystem,
                            license_id=lic_id,
                            license_expression=lic_expr,
                            category=category,
                            risk_level=risk_level,
                            reason=f"License {lic_id} is {category.replace('_', ' ')}",
                            agents=[agent.name],
                        )
                    )
                elif category == "unknown":
                    report.findings.append(
                        LicenseFinding(
                            package_name=pkg.name,
                            package_version=pkg.version,
                            ecosystem=pkg.ecosystem,
                            license_id=lic_id,
                            license_expression=lic_expr,
                            category=category,
                            risk_level="medium",
                            reason=f"License {lic_id} is not recognized in SPDX catalog",
                            agents=[agent.name],
                        )
                    )

    # Build summary
    cat_counts: dict[str, int] = {}
    risk_counts: dict[str, int] = {}
    for f in report.findings:
        cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
        risk_counts[f.risk_level] = risk_counts.get(f.risk_level, 0) + 1

    report.summary = {
        "total_packages": report.total_packages,
        "findings_count": len(report.findings),
        "unknown_count": report.unknown_count,
        "compliant": report.compliant,
        "by_category": cat_counts,
        "by_risk": risk_counts,
    }

    return report


def to_serializable(report: LicenseReport) -> dict:
    """Convert LicenseReport to a JSON-serializable dict."""
    return {
        "compliant": report.compliant,
        "total_packages": report.total_packages,
        "unknown_count": report.unknown_count,
        "summary": report.summary,
        "findings": [
            {
                "package_name": f.package_name,
                "package_version": f.package_version,
                "ecosystem": f.ecosystem,
                "license_id": f.license_id,
                "license_expression": f.license_expression,
                "category": f.category,
                "risk_level": f.risk_level,
                "reason": f.reason,
                "agents": f.agents,
            }
            for f in report.findings
        ],
    }


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------


def print_license_report(report: LicenseReport, console: object) -> None:
    """Print license compliance report using Rich console."""
    from rich.table import Table

    if not report.findings:
        console.print("\n  [green]\u2713[/green] License compliance: no findings\n")
        return

    status = "[green]COMPLIANT[/green]" if report.compliant else "[red]NON-COMPLIANT[/red]"
    console.print(f"\n  License Compliance: {status}")
    console.print(f"  {report.total_packages} packages evaluated, {len(report.findings)} finding(s), {report.unknown_count} unknown\n")

    table = Table(show_header=True, header_style="bold", pad_edge=False, box=None)
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Version", style="dim")
    table.add_column("License", style="bold")
    table.add_column("Category", no_wrap=True)
    table.add_column("Risk", no_wrap=True)
    table.add_column("Reason")

    risk_colors = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green"}
    cat_colors = {
        "permissive": "green",
        "weak_copyleft": "yellow",
        "strong_copyleft": "red",
        "network_copyleft": "red",
        "commercial_risk": "red",
        "source_available": "yellow",
        "restricted": "yellow",
        "proprietary": "cyan",
        "unknown": "dim",
    }

    for f in sorted(report.findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.risk_level, 4)):
        risk_color = risk_colors.get(f.risk_level, "white")
        cat_color = cat_colors.get(f.category, "white")
        table.add_row(
            f.package_name,
            f.package_version,
            f.license_id,
            f"[{cat_color}]{f.category.replace('_', ' ')}[/{cat_color}]",
            f"[{risk_color}]{f.risk_level}[/{risk_color}]",
            f.reason,
        )

    console.print(table)
    console.print()
