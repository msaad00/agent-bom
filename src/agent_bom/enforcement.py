"""MCP tool poisoning detection and enforcement engine.

Composes existing capabilities into a unified enforcement scan:
- Tool description injection detection (reuses prompt_scanner patterns)
- Dangerous capability combination scoring (reuses risk_analyzer)
- Undeclared tool drift detection (reuses mcp_introspect)
- CVE-aware enforcement (flags servers with critical/high CVEs)
- Pass/fail verdict with structured findings
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from agent_bom.models import MCPServer, Severity

if TYPE_CHECKING:
    from agent_bom.mcp_introspect import IntrospectionReport, ServerIntrospection

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class EnforcementFinding:
    """A single enforcement finding."""

    severity: str  # critical, high, medium, low
    category: str  # injection, drift, cve_exposure, dangerous_combo
    server_name: str
    tool_name: Optional[str] = None
    reason: str = ""
    recommendation: str = ""


@dataclass
class EnforcementReport:
    """Aggregated enforcement results."""

    findings: list[EnforcementFinding] = field(default_factory=list)
    servers_checked: int = 0
    tools_checked: int = 0
    passed: bool = True

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def to_dict(self) -> dict:
        """Serialize for JSON output and AIBOMReport storage."""
        return {
            "passed": self.passed,
            "servers_checked": self.servers_checked,
            "tools_checked": self.tools_checked,
            "findings_count": len(self.findings),
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "server_name": f.server_name,
                    "tool_name": f.tool_name,
                    "reason": f.reason,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
        }


def scan_tool_descriptions(server: MCPServer) -> list[EnforcementFinding]:
    """Scan MCP tool descriptions for injection patterns.

    Reuses the regex library from prompt_scanner.py to detect
    jailbreak patterns, unsafe instructions, and data exfiltration
    vectors hidden in tool description fields.
    """
    from agent_bom.parsers.prompt_scanner import (
        _INJECTION_PATTERNS,
        _UNSAFE_INSTRUCTION_PATTERNS,
    )

    findings: list[EnforcementFinding] = []
    for tool in server.tools:
        text = (tool.description or "").strip()
        if not text:
            continue

        # Check injection patterns (high severity)
        for pattern, title in _INJECTION_PATTERNS:
            if pattern.search(text):
                findings.append(EnforcementFinding(
                    severity="high",
                    category="injection",
                    server_name=server.name,
                    tool_name=tool.name,
                    reason=f"Tool description contains injection pattern: {title}",
                    recommendation="Review tool description for hidden instructions. Consider removing or replacing this MCP server.",
                ))

        # Check unsafe instruction patterns (high severity)
        for pattern, title in _UNSAFE_INSTRUCTION_PATTERNS:
            if pattern.search(text):
                findings.append(EnforcementFinding(
                    severity="high",
                    category="injection",
                    server_name=server.name,
                    tool_name=tool.name,
                    reason=f"Tool description contains unsafe instruction: {title}",
                    recommendation="Remove unsafe instructions from tool descriptions. Verify the MCP server source.",
                ))

    return findings


def score_capability_risk(server: MCPServer) -> list[EnforcementFinding]:
    """Detect dangerous capability combinations across a server's tools.

    Reuses risk_analyzer.classify_tool() and DANGEROUS_COMBOS.
    """
    from agent_bom.risk_analyzer import (
        DANGEROUS_COMBOS,
        ToolCapability,
        classify_tool,
    )

    findings: list[EnforcementFinding] = []
    all_caps: set[ToolCapability] = set()

    for tool in server.tools:
        caps = classify_tool(tool.name, tool.description or "")
        all_caps.update(caps)

    for combo_set, description in DANGEROUS_COMBOS:
        if combo_set.issubset(all_caps):
            findings.append(EnforcementFinding(
                severity="high",
                category="dangerous_combo",
                server_name=server.name,
                reason=f"Dangerous capability combination: {description}",
                recommendation="Restrict tool permissions or split capabilities across separate servers.",
            ))

    return findings


def check_cve_exposure(server: MCPServer) -> list[EnforcementFinding]:
    """Flag servers whose packages have critical/high CVEs.

    Uses already-scanned vulnerability data on server.packages.
    """
    findings: list[EnforcementFinding] = []

    for pkg in server.packages:
        for vuln in pkg.vulnerabilities:
            if vuln.severity in (Severity.CRITICAL, Severity.HIGH):
                sev = vuln.severity.value
                findings.append(EnforcementFinding(
                    severity=sev,
                    category="cve_exposure",
                    server_name=server.name,
                    reason=f"{vuln.id} ({sev.upper()}) in {pkg.name}@{pkg.version}",
                    recommendation=f"Upgrade {pkg.name} to {vuln.fixed_version or 'latest'}.",
                ))

    return findings


def check_drift(
    server: MCPServer,
    introspection_result: ServerIntrospection | None = None,
) -> list[EnforcementFinding]:
    """Detect undeclared tools discovered via runtime introspection.

    Reuses mcp_introspect.ServerIntrospection drift data.
    """
    if introspection_result is None:
        return []

    findings: list[EnforcementFinding] = []

    for tool_name in introspection_result.tools_added:
        findings.append(EnforcementFinding(
            severity="high",
            category="drift",
            server_name=server.name,
            tool_name=tool_name,
            reason=f"Undeclared tool '{tool_name}' found at runtime but not in config",
            recommendation="Verify tool origin. Update config to declare it, or block the server.",
        ))

    return findings


def run_enforcement(
    servers: list[MCPServer],
    introspection_report: IntrospectionReport | None = None,
    fail_on_severity: str = "high",
) -> EnforcementReport:
    """Run full enforcement scan across all servers.

    Orchestrates all four checks and produces a unified report.
    """
    report = EnforcementReport()
    report.servers_checked = len(servers)

    # Build introspection lookup
    intro_map: dict[str, ServerIntrospection] = {}
    if introspection_report is not None:
        for result in introspection_report.results:
            intro_map[result.server_name] = result

    for server in servers:
        report.tools_checked += len(server.tools)

        # 1. Scan tool descriptions for injection
        report.findings.extend(scan_tool_descriptions(server))

        # 2. Check dangerous capability combos
        report.findings.extend(score_capability_risk(server))

        # 3. Check CVE exposure
        report.findings.extend(check_cve_exposure(server))

        # 4. Check drift (if introspection data available)
        intro = intro_map.get(server.name)
        report.findings.extend(check_drift(server, intro))

    # Determine pass/fail based on threshold
    threshold = _SEVERITY_ORDER.get(fail_on_severity, 1)
    for finding in report.findings:
        if _SEVERITY_ORDER.get(finding.severity, 3) <= threshold:
            report.passed = False
            break

    return report
