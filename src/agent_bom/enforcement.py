"""MCP tool poisoning detection and enforcement engine.

Composes existing capabilities into a unified enforcement scan:
- Tool description injection detection (reuses prompt_scanner patterns)
- inputSchema property description scanning (catches hidden instructions in parameter schemas)
- Unicode normalization (strips homoglyphs, zero-width chars before pattern matching)
- Dangerous capability combination scoring (reuses risk_analyzer)
- Undeclared tool drift detection (reuses mcp_introspect)
- Tool description drift detection (hash comparison of config vs runtime descriptions)
- CVE-aware enforcement (flags servers with critical/high CVEs)
- Pass/fail verdict with structured findings
"""

from __future__ import annotations

import hashlib
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from agent_bom.models import MCPServer, Severity

if TYPE_CHECKING:
    from agent_bom.mcp_introspect import IntrospectionReport, ServerIntrospection

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Zero-width and invisible Unicode characters commonly used for evasion
_INVISIBLE_RE = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad\u034f\u115f\u1160\u17b4\u17b5]"
)


@dataclass
class EnforcementFinding:
    """A single enforcement finding."""

    severity: str  # critical, high, medium, low
    category: str  # injection, drift, cve_exposure, dangerous_combo, schema_injection, description_drift
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


def _normalize_text(text: str) -> str:
    """Normalize text for pattern matching: strip invisible chars, normalize Unicode."""
    # Strip zero-width and invisible characters
    text = _INVISIBLE_RE.sub("", text)
    # NFKD normalization: decomposes ligatures, converts fullwidth chars, etc.
    text = unicodedata.normalize("NFKD", text)
    return text


def _extract_schema_descriptions(input_schema: dict | None) -> list[str]:
    """Extract all description strings from a JSON Schema (inputSchema).

    Walks properties, items, allOf/anyOf/oneOf recursively.
    """
    if not input_schema or not isinstance(input_schema, dict):
        return []

    descriptions: list[str] = []

    # Top-level description
    if "description" in input_schema and isinstance(input_schema["description"], str):
        descriptions.append(input_schema["description"])

    # Properties
    props = input_schema.get("properties")
    if isinstance(props, dict):
        for _name, prop_schema in props.items():
            if isinstance(prop_schema, dict):
                descriptions.extend(_extract_schema_descriptions(prop_schema))

    # Array items
    items = input_schema.get("items")
    if isinstance(items, dict):
        descriptions.extend(_extract_schema_descriptions(items))

    # Combinators
    for key in ("allOf", "anyOf", "oneOf"):
        combinator = input_schema.get(key)
        if isinstance(combinator, list):
            for sub in combinator:
                if isinstance(sub, dict):
                    descriptions.extend(_extract_schema_descriptions(sub))

    return descriptions


def scan_tool_descriptions(server: MCPServer) -> list[EnforcementFinding]:
    """Scan MCP tool descriptions AND inputSchema for injection patterns.

    Reuses the regex library from prompt_scanner.py to detect
    jailbreak patterns, unsafe instructions, and data exfiltration
    vectors hidden in tool description fields and parameter schemas.
    Applies Unicode normalization before matching to resist homoglyph evasion.
    """
    from agent_bom.parsers.prompt_scanner import (
        _INJECTION_PATTERNS,
        _UNSAFE_INSTRUCTION_PATTERNS,
    )

    findings: list[EnforcementFinding] = []
    for tool in server.tools:
        # Collect all scannable text surfaces for this tool
        surfaces: list[tuple[str, str]] = []  # (text, source_label)

        desc = (tool.description or "").strip()
        if desc:
            surfaces.append((desc, "description"))

        # inputSchema property descriptions (the #1 real-world attack vector)
        schema_descs = _extract_schema_descriptions(tool.input_schema)
        for sd in schema_descs:
            sd = sd.strip()
            if sd:
                surfaces.append((sd, "inputSchema"))

        for raw_text, source in surfaces:
            text = _normalize_text(raw_text)

            category = "injection" if source == "description" else "schema_injection"

            # Check injection patterns (high severity)
            for pattern, title in _INJECTION_PATTERNS:
                if pattern.search(text):
                    findings.append(EnforcementFinding(
                        severity="high",
                        category=category,
                        server_name=server.name,
                        tool_name=tool.name,
                        reason=f"Tool {source} contains injection pattern: {title}",
                        recommendation=(
                            "Review tool parameter schemas for hidden instructions. "
                            "Consider removing or replacing this MCP server."
                            if source == "inputSchema"
                            else "Review tool description for hidden instructions. "
                            "Consider removing or replacing this MCP server."
                        ),
                    ))

            # Check unsafe instruction patterns (high severity)
            for pattern, title in _UNSAFE_INSTRUCTION_PATTERNS:
                if pattern.search(text):
                    findings.append(EnforcementFinding(
                        severity="high",
                        category=category,
                        server_name=server.name,
                        tool_name=tool.name,
                        reason=f"Tool {source} contains unsafe instruction: {title}",
                        recommendation=(
                            "Remove unsafe instructions from parameter schemas. "
                            "Verify the MCP server source."
                            if source == "inputSchema"
                            else "Remove unsafe instructions from tool descriptions. "
                            "Verify the MCP server source."
                        ),
                    ))

    return findings


def score_capability_risk(server: MCPServer) -> list[EnforcementFinding]:
    """Detect dangerous capability combinations across a server's tools.

    Reuses risk_analyzer.classify_tool() and DANGEROUS_COMBOS.
    Uses word-boundary matching to reduce false positives from substrings.
    """
    from agent_bom.risk_analyzer import (
        DANGEROUS_COMBOS,
        ToolCapability,
    )

    findings: list[EnforcementFinding] = []
    all_caps: set[ToolCapability] = set()

    for tool in server.tools:
        caps = _classify_tool_word_boundary(tool.name, tool.description or "")
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


def _classify_tool_word_boundary(tool_name: str, description: str) -> list:
    """Classify tool capabilities using word-boundary matching to avoid false positives.

    Unlike risk_analyzer.classify_tool() which uses substring matching (e.g. "bread"
    matches "read"), this uses \\b word boundaries for accurate classification.
    """
    from agent_bom.risk_analyzer import CAPABILITY_PATTERNS, ToolCapability

    # Split tool_name on common separators for word-level matching
    combined = re.sub(r"[_\-.]", " ", tool_name).lower() + " " + description.lower()
    caps: set[ToolCapability] = set()

    for capability, patterns in CAPABILITY_PATTERNS.items():
        for pattern in patterns:
            if re.search(r"\b" + re.escape(pattern) + r"\b", combined):
                caps.add(capability)
                break

    return sorted(caps, key=lambda c: c.value)


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


def _hash_tool_description(tool_name: str, description: str) -> str:
    """Compute a stable hash of a tool's name + description for drift detection."""
    content = f"{tool_name}:{description or ''}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def check_drift(
    server: MCPServer,
    introspection_result: ServerIntrospection | None = None,
) -> list[EnforcementFinding]:
    """Detect undeclared tools AND description changes via runtime introspection.

    Checks two things:
    1. Tools present at runtime but not in config (undeclared tools)
    2. Tools whose descriptions changed between config and runtime (description drift)
    """
    if introspection_result is None:
        return []

    findings: list[EnforcementFinding] = []

    # 1. Undeclared tools (existing check)
    for tool_name in introspection_result.tools_added:
        findings.append(EnforcementFinding(
            severity="high",
            category="drift",
            server_name=server.name,
            tool_name=tool_name,
            reason=f"Undeclared tool '{tool_name}' found at runtime but not in config",
            recommendation="Verify tool origin. Update config to declare it, or block the server.",
        ))

    # 2. Description drift on existing tools
    config_tools = {t.name: t for t in server.tools}
    runtime_tools = {t.name: t for t in introspection_result.runtime_tools}

    for name, config_tool in config_tools.items():
        runtime_tool = runtime_tools.get(name)
        if runtime_tool is None:
            continue  # Tool removed at runtime, already captured in tools_removed
        config_hash = _hash_tool_description(name, config_tool.description or "")
        runtime_hash = _hash_tool_description(name, runtime_tool.description or "")
        if config_hash != runtime_hash:
            findings.append(EnforcementFinding(
                severity="medium",
                category="description_drift",
                server_name=server.name,
                tool_name=name,
                reason=f"Tool '{name}' description changed between config and runtime",
                recommendation="Review the runtime description for injected instructions. Pin the server version.",
            ))

    return findings


def run_enforcement(
    servers: list[MCPServer],
    introspection_report: IntrospectionReport | None = None,
    fail_on_severity: str = "high",
) -> EnforcementReport:
    """Run full enforcement scan across all servers.

    Orchestrates all checks and produces a unified report.
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

        # 1. Scan tool descriptions + inputSchema for injection
        report.findings.extend(scan_tool_descriptions(server))

        # 2. Check dangerous capability combos (word-boundary matching)
        report.findings.extend(score_capability_risk(server))

        # 3. Check CVE exposure
        report.findings.extend(check_cve_exposure(server))

        # 4. Check drift — undeclared tools + description changes
        intro = intro_map.get(server.name)
        report.findings.extend(check_drift(server, intro))

    # Determine pass/fail based on threshold
    threshold = _SEVERITY_ORDER.get(fail_on_severity, 1)
    for finding in report.findings:
        if _SEVERITY_ORDER.get(finding.severity, 3) <= threshold:
            report.passed = False
            break

    return report
