"""Runtime ↔ scan correlation engine.

Cross-references proxy audit logs (actual tool calls) with vulnerability scan
results (CVE findings) to answer: "which vulnerable tools were actually called?"

This bridges two previously separate systems:
- Proxy audit logs (JSONL): records of actual MCP tool invocations
- Scan results (BlastRadius): CVE findings with affected servers/tools

The correlation produces ``CorrelatedFinding`` objects that combine:
- The vulnerability (CVE ID, severity, EPSS)
- The tool that was called (name, arguments)
- The server hosting the tool
- Call frequency and recency
- Risk amplification (a called vulnerable tool is higher risk than an idle one)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ToolCallRecord:
    """A single tool call from the proxy audit log."""

    timestamp: str
    tool_name: str
    arguments: dict[str, Any]
    policy_result: str  # "allowed" or "blocked"
    reason: str = ""
    payload_sha256: str = ""
    message_id: int | str | None = None


@dataclass
class CorrelatedFinding:
    """A vulnerability finding correlated with actual runtime tool calls."""

    vulnerability_id: str
    severity: str
    cvss_score: float
    epss_score: float
    is_kev: bool
    package_name: str
    package_version: str

    # Tool call correlation
    tool_name: str
    server_name: str
    call_count: int  # How many times this tool was called
    last_called: str  # ISO timestamp of most recent call
    first_called: str  # ISO timestamp of first call
    was_blocked: bool  # Whether any calls were blocked by policy

    # Risk context
    risk_amplifier: float  # Multiplier: called tools are higher risk
    original_risk_score: float
    correlated_risk_score: float  # risk_score * risk_amplifier
    affected_agents: list[str] = field(default_factory=list)
    exposed_credentials: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerability_id": self.vulnerability_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "is_kev": self.is_kev,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "tool_name": self.tool_name,
            "server_name": self.server_name,
            "call_count": self.call_count,
            "last_called": self.last_called,
            "first_called": self.first_called,
            "was_blocked": self.was_blocked,
            "risk_amplifier": self.risk_amplifier,
            "original_risk_score": round(self.original_risk_score, 2),
            "correlated_risk_score": round(self.correlated_risk_score, 2),
            "affected_agents": self.affected_agents,
            "exposed_credentials": self.exposed_credentials,
        }


@dataclass
class CorrelationReport:
    """Summary of runtime ↔ scan correlation."""

    total_tool_calls: int
    unique_tools_called: int
    vulnerable_tools_called: int
    correlated_findings: list[CorrelatedFinding]
    uncalled_vulnerable_tools: list[dict[str, Any]]  # Vulnerable but never called
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "total_tool_calls": self.total_tool_calls,
            "unique_tools_called": self.unique_tools_called,
            "vulnerable_tools_called": self.vulnerable_tools_called,
            "correlated_findings": [f.to_dict() for f in self.correlated_findings],
            "uncalled_vulnerable_tools": self.uncalled_vulnerable_tools,
            "summary": {
                "called_and_vulnerable": self.vulnerable_tools_called,
                "highest_correlated_risk": max(
                    (f.correlated_risk_score for f in self.correlated_findings),
                    default=0.0,
                ),
                "kev_tools_called": sum(1 for f in self.correlated_findings if f.is_kev),
            },
        }


# ─── Audit log parsing ─────────────────────────────────────────────────────


def load_audit_log(path: str | Path) -> list[ToolCallRecord]:
    """Load tool call records from a proxy audit JSONL file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Audit log not found: {path}")

    records: list[ToolCallRecord] = []
    for line_num, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Skipping invalid JSON at line %d", line_num)
            continue

        if data.get("type") != "tools/call":
            continue

        records.append(
            ToolCallRecord(
                timestamp=data.get("ts", ""),
                tool_name=data.get("tool", ""),
                arguments=data.get("args", {}),
                policy_result=data.get("policy", "allowed"),
                reason=data.get("reason", ""),
                payload_sha256=data.get("payload_sha256", ""),
                message_id=data.get("message_id"),
            )
        )

    return records


def _aggregate_calls(
    records: list[ToolCallRecord],
) -> dict[str, dict[str, Any]]:
    """Aggregate tool calls by tool name.

    Returns a dict of tool_name → {count, first_called, last_called, was_blocked}.
    """
    aggregated: dict[str, dict[str, Any]] = {}
    for rec in records:
        name = rec.tool_name
        if name not in aggregated:
            aggregated[name] = {
                "count": 0,
                "first_called": rec.timestamp,
                "last_called": rec.timestamp,
                "was_blocked": False,
            }
        agg = aggregated[name]
        agg["count"] += 1
        if rec.timestamp < agg["first_called"]:
            agg["first_called"] = rec.timestamp
        if rec.timestamp > agg["last_called"]:
            agg["last_called"] = rec.timestamp
        if rec.policy_result == "blocked":
            agg["was_blocked"] = True

    return aggregated


# ─── Risk amplification ────────────────────────────────────────────────────

# A vulnerable tool that was actually called is a confirmed attack surface,
# not just a theoretical one. These multipliers reflect that.
RISK_AMPLIFIER_CALLED = 1.5  # Called at least once
RISK_AMPLIFIER_FREQUENT = 2.0  # Called 10+ times
RISK_AMPLIFIER_RECENT = 1.8  # Called in last 24 hours
RISK_AMPLIFIER_KEV_CALLED = 2.5  # KEV vuln AND actively called
RISK_AMPLIFIER_MAX = 3.0  # Cap


def _compute_amplifier(
    call_info: dict[str, Any],
    is_kev: bool,
    recency_hours: float = 24.0,
) -> float:
    """Compute risk amplification factor for a called vulnerable tool."""
    amp = RISK_AMPLIFIER_CALLED

    if call_info["count"] >= 10:
        amp += RISK_AMPLIFIER_FREQUENT - RISK_AMPLIFIER_CALLED  # +0.5 bonus for frequent

    # Check recency
    try:
        last = datetime.fromisoformat(call_info["last_called"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        hours_since = (now - last).total_seconds() / 3600
        if hours_since <= recency_hours:
            amp += 0.3  # Recency bonus (additive)
    except (ValueError, TypeError):
        pass

    if is_kev:
        amp += RISK_AMPLIFIER_KEV_CALLED - RISK_AMPLIFIER_CALLED  # +1.0 bonus for KEV

    return min(amp, RISK_AMPLIFIER_MAX)


# ─── Core correlation ──────────────────────────────────────────────────────


def correlate(
    blast_radii: list,
    audit_log_path: str | Path | None = None,
    audit_records: list[ToolCallRecord] | None = None,
) -> CorrelationReport:
    """Cross-reference vulnerability findings with runtime tool call data.

    Args:
        blast_radii: List of BlastRadius objects from a scan.
        audit_log_path: Path to proxy audit JSONL file.
        audit_records: Pre-loaded audit records (alternative to file path).

    Returns:
        CorrelationReport with findings sorted by correlated risk score.
    """
    # Load audit data
    if audit_records is not None:
        records = audit_records
    elif audit_log_path is not None:
        records = load_audit_log(audit_log_path)
    else:
        # No audit data — return empty correlation
        return CorrelationReport(
            total_tool_calls=0,
            unique_tools_called=0,
            vulnerable_tools_called=0,
            correlated_findings=[],
            uncalled_vulnerable_tools=[],
        )

    # Aggregate calls by tool name
    call_agg = _aggregate_calls(records)
    called_tools = set(call_agg.keys())

    # Build tool → vulnerability mapping from blast radii
    correlated: list[CorrelatedFinding] = []
    uncalled: list[dict[str, Any]] = []
    vulnerable_tools_seen: set[str] = set()

    for br in blast_radii:
        vuln = br.vulnerability
        pkg = br.package

        for tool in br.exposed_tools:
            tool_name = tool.name if hasattr(tool, "name") else str(tool)

            if tool_name in called_tools:
                # This vulnerable tool was actually called
                vulnerable_tools_seen.add(tool_name)
                call_info = call_agg[tool_name]
                amplifier = _compute_amplifier(call_info, vuln.is_kev)

                server_names = [s.name if hasattr(s, "name") else str(s) for s in br.affected_servers]

                correlated.append(
                    CorrelatedFinding(
                        vulnerability_id=vuln.id,
                        severity=vuln.severity.value,
                        cvss_score=vuln.cvss_score or 0.0,
                        epss_score=vuln.epss_score or 0.0,
                        is_kev=vuln.is_kev,
                        package_name=pkg.name,
                        package_version=pkg.version,
                        tool_name=tool_name,
                        server_name=server_names[0] if server_names else "unknown",
                        call_count=call_info["count"],
                        last_called=call_info["last_called"],
                        first_called=call_info["first_called"],
                        was_blocked=call_info["was_blocked"],
                        risk_amplifier=amplifier,
                        original_risk_score=br.risk_score,
                        correlated_risk_score=min(br.risk_score * amplifier, 10.0),
                        affected_agents=[a.name if hasattr(a, "name") else str(a) for a in br.affected_agents],
                        exposed_credentials=br.exposed_credentials,
                    )
                )
            else:
                uncalled.append(
                    {
                        "vulnerability_id": vuln.id,
                        "tool_name": tool_name,
                        "severity": vuln.severity.value,
                        "risk_score": round(br.risk_score, 2),
                        "note": "vulnerable but never called (theoretical risk only)",
                    }
                )

    # Sort by correlated risk score (highest first)
    correlated.sort(key=lambda f: f.correlated_risk_score, reverse=True)

    return CorrelationReport(
        total_tool_calls=len(records),
        unique_tools_called=len(called_tools),
        vulnerable_tools_called=len(vulnerable_tools_seen),
        correlated_findings=correlated,
        uncalled_vulnerable_tools=uncalled,
    )
