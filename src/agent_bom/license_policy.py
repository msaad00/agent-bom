"""License policy engine — categorize, evaluate, and report license compliance.

Provides SPDX license categorization, policy evaluation against configurable
block/warn lists, and Rich console output for license findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch

from agent_bom.models import Agent

# ---------------------------------------------------------------------------
# SPDX license categories
# ---------------------------------------------------------------------------

PERMISSIVE: set[str] = {
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
    "BSL-1.0",  # Boost, not Business Source License
    "PSF-2.0",
    "Python-2.0",
    "BlueOak-1.0.0",
}

WEAK_COPYLEFT: set[str] = {
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
}

STRONG_COPYLEFT: set[str] = {
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
}

COMMERCIAL_RISK: set[str] = {
    "SSPL-1.0",
    "BSL-1.1",  # Business Source License (MariaDB/HashiCorp)
    "Elastic-2.0",
    "Commons-Clause",
}

# Default policy: block strong copyleft + commercial risk, warn weak copyleft
DEFAULT_LICENSE_POLICY: dict = {
    "license_block": ["GPL-*", "AGPL-*", "SSPL-*", "BSL-1.1", "Elastic-*"],
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
    category: str  # permissive, weak_copyleft, strong_copyleft, commercial_risk, unknown
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
# License categorization
# ---------------------------------------------------------------------------


def categorize_license(spdx_id: str) -> tuple[str, str]:
    """Categorize an SPDX license identifier.

    Returns (category, risk_level) where:
    - category: permissive, weak_copyleft, strong_copyleft, commercial_risk, unknown
    - risk_level: low, medium, high, critical
    """
    if not spdx_id:
        return "unknown", "medium"

    normalized = spdx_id.strip()

    if normalized in PERMISSIVE:
        return "permissive", "low"
    if normalized in WEAK_COPYLEFT:
        return "weak_copyleft", "medium"
    if normalized in STRONG_COPYLEFT:
        return "strong_copyleft", "high"
    if normalized in COMMERCIAL_RISK:
        return "commercial_risk", "critical"

    # Handle SPDX expressions (e.g., "Apache-2.0 OR MIT" → permissive)
    if " OR " in normalized:
        parts = [p.strip() for p in normalized.split(" OR ")]
        categories = [categorize_license(p) for p in parts]
        # OR means user can choose — pick the most permissive
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        best = min(categories, key=lambda c: risk_order.get(c[1], 99))
        return best

    if " AND " in normalized:
        parts = [p.strip() for p in normalized.split(" AND ")]
        categories = [categorize_license(p) for p in parts]
        # AND means all apply — pick the most restrictive
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        worst = max(categories, key=lambda c: risk_order.get(c[1], 99))
        return worst

    return "unknown", "medium"


def _matches_pattern(license_id: str, patterns: list[str]) -> bool:
    """Check if a license ID matches any of the glob patterns."""
    for pattern in patterns:
        if fnmatch(license_id, pattern):
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
                elif category in ("strong_copyleft", "commercial_risk"):
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
        console.print("\n  [green]✓[/green] License compliance: no findings\n")
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
        "commercial_risk": "red",
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
