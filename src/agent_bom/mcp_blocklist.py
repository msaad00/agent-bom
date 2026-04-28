"""Curated MCP server blocklist matching.

Phase 1 intentionally stays offline and bundled. It checks discovered server
identity strings against exact entries and suspicious patterns, then emits
unified findings and server warnings for existing scan surfaces.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import Agent, MCPServer

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MCPBlocklistMatch:
    """One blocklist hit against a discovered MCP server."""

    entry_id: str
    title: str
    description: str
    match_type: str
    severity: str
    matched_value: str
    source: str
    references: tuple[str, ...] = ()


def load_mcp_blocklist() -> dict[str, Any]:
    """Load the bundled MCP blocklist data.

    Returns an empty blocklist if the package data is unavailable or malformed
    so scans do not fail closed because of a catalog packaging issue.
    """
    try:
        text = resources.files("agent_bom.data").joinpath("mcp-blocklist.json").read_text(encoding="utf-8")
        data = json.loads(text)
    except (json.JSONDecodeError, OSError, FileNotFoundError) as exc:
        logger.warning("Failed to load MCP blocklist: %s", exc)
        return {"entries": []}
    return data if isinstance(data, dict) else {"entries": []}


def _norm(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _server_match_values(server: MCPServer) -> list[str]:
    values: list[str] = [
        server.name,
        server.registry_id or "",
        server.command,
        " ".join([server.command, *server.args]).strip(),
        server.url or "",
    ]
    values.extend(pkg.name for pkg in server.packages)
    values.extend(pkg.purl or "" for pkg in server.packages)

    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = str(value or "").strip()
        key = _norm(cleaned)
        if cleaned and key not in seen:
            seen.add(key)
            result.append(cleaned)
    return result


def match_mcp_server(server: MCPServer, blocklist: dict[str, Any] | None = None) -> list[MCPBlocklistMatch]:
    """Return blocklist matches for one MCP server.

    Exact matches are critical by policy. Pattern matches are high severity by
    default unless an entry explicitly lowers the severity for future data.
    """
    data = blocklist if blocklist is not None else load_mcp_blocklist()
    raw_entries = data.get("entries", []) if isinstance(data, dict) else []
    entries = raw_entries if isinstance(raw_entries, list) else []
    values = _server_match_values(server)
    normalized_values = {_norm(value): value for value in values}

    matches: list[MCPBlocklistMatch] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_id = str(entry.get("id") or "mcp-blocklist-entry")
        title = str(entry.get("title") or "MCP server blocklist match")
        description = str(entry.get("description") or "")
        source = str(entry.get("source") or "agent-bom-curated")
        references = tuple(str(ref) for ref in entry.get("references", []) if isinstance(ref, str))

        exact_values: list[object] = []
        for field_name in ("names", "exact", "registry_ids", "packages"):
            raw_values = entry.get(field_name, [])
            if isinstance(raw_values, list):
                exact_values.extend(raw_values)
        if exact_values:
            for raw_exact in exact_values:
                expected = _norm(raw_exact)
                if not expected or expected not in normalized_values:
                    continue
                key = (entry_id, "exact", expected)
                if key in seen:
                    continue
                seen.add(key)
                matches.append(
                    MCPBlocklistMatch(
                        entry_id=entry_id,
                        title=title,
                        description=description,
                        match_type="exact",
                        severity="critical",
                        matched_value=normalized_values[expected],
                        source=source,
                        references=references,
                    )
                )

        patterns = entry.get("patterns", [])
        if not isinstance(patterns, list):
            continue
        for raw_pattern in patterns:
            if not isinstance(raw_pattern, str) or not raw_pattern.strip():
                continue
            try:
                pattern = re.compile(raw_pattern, re.IGNORECASE)
            except re.error as exc:
                logger.warning("Invalid MCP blocklist pattern %r in %s: %s", raw_pattern, entry_id, exc)
                continue
            for value in values:
                if not pattern.search(value):
                    continue
                key = (entry_id, "pattern", raw_pattern)
                if key in seen:
                    continue
                seen.add(key)
                severity = str(entry.get("severity") or "high").lower()
                matches.append(
                    MCPBlocklistMatch(
                        entry_id=entry_id,
                        title=title,
                        description=description,
                        match_type="pattern",
                        severity=severity if severity in {"critical", "high", "medium", "low"} else "high",
                        matched_value=value,
                        source=source,
                        references=references,
                    )
                )
                break

    return matches


def blocklist_findings_for_agents(agents: list[Agent], blocklist: dict[str, Any] | None = None) -> list[Finding]:
    """Create unified findings for MCP blocklist hits and stamp server warnings."""
    findings: list[Finding] = []
    for agent in agents:
        for server in agent.mcp_servers:
            for match in match_mcp_server(server, blocklist):
                warning = f"MCP_BLOCKLIST[{match.severity}/{match.match_type}]: {match.entry_id} matched {match.matched_value!r}"
                if warning not in server.security_warnings:
                    server.security_warnings.append(warning)
                if match.severity == "critical":
                    server.security_blocked = True

                findings.append(
                    Finding(
                        finding_type=FindingType.MCP_BLOCKLIST,
                        source=FindingSource.MCP_SCAN,
                        asset=Asset(
                            name=server.name,
                            asset_type="mcp_server",
                            identifier=server.registry_id,
                            location=server.config_path or server.command or None,
                        ),
                        severity=match.severity,
                        title=match.title,
                        description=match.description,
                        remediation_guidance="Remove or disable the matched MCP server until the blocklist entry is reviewed.",
                        owasp_mcp_tags=["MCP04", "MCP07"],
                        evidence={
                            "agent_name": agent.name,
                            "server_name": server.name,
                            "server_stable_id": server.stable_id,
                            "entry_id": match.entry_id,
                            "match_type": match.match_type,
                            "matched_value": match.matched_value,
                            "blocklist_source": match.source,
                            "references": list(match.references),
                        },
                        risk_score=10.0 if match.severity == "critical" else 8.0,
                    )
                )
    return findings
