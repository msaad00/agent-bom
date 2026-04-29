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
from urllib.parse import urlsplit, urlunsplit

from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import Agent, MCPServer
from agent_bom.security import sanitize_command_args, sanitize_sensitive_payload, sanitize_text

logger = logging.getLogger(__name__)

_CONFIDENCE_LEVELS = {"confirmed_malicious", "suspicious", "heuristic"}
_RECOMMENDATIONS = {"block", "warn", "review"}
_SOURCE_TYPES = {"security_advisory", "vendor_statement", "community_report", "package_registry", "heuristic"}
_INTELLIGENCE_STRING_FIELDS = {
    "entry_id",
    "title",
    "severity",
    "confidence",
    "default_recommendation",
    "source_type",
    "source",
    "match_type",
    "matched_value",
    "ecosystem",
    "package",
    "affected_versions",
    "first_seen",
    "last_verified",
}


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
    confidence: str = "heuristic"
    default_recommendation: str = "review"
    source_type: str = "heuristic"
    ecosystem: str = ""
    package: str = ""
    affected_versions: str = ""
    first_seen: str = ""
    last_verified: str = ""
    remediation_actions: tuple[str, ...] = ()

    def to_intelligence(self) -> dict[str, object]:
        """Serialize the match as the stable MCP intelligence contract."""
        return sanitize_security_intelligence_entry(
            {
                "entry_id": self.entry_id,
                "title": self.title,
                "severity": self.severity,
                "confidence": self.confidence,
                "default_recommendation": self.default_recommendation,
                "source_type": self.source_type,
                "source": self.source,
                "match_type": self.match_type,
                "matched_value": self.matched_value,
                "ecosystem": self.ecosystem,
                "package": self.package,
                "affected_versions": self.affected_versions,
                "first_seen": self.first_seen,
                "last_verified": self.last_verified,
                "references": list(self.references),
                "remediation_actions": list(self.remediation_actions),
            }
        )


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


def _entry_str(entry: dict[str, Any], key: str, default: str = "") -> str:
    value = entry.get(key, default)
    return str(value or default)


def _entry_choice(entry: dict[str, Any], key: str, allowed: set[str], default: str) -> str:
    value = _entry_str(entry, key, default).lower()
    return value if value in allowed else default


def _entry_strings(entry: dict[str, Any], key: str) -> tuple[str, ...]:
    values = entry.get(key, [])
    if not isinstance(values, list):
        return ()
    return tuple(str(value) for value in values if isinstance(value, str) and value.strip())


def _safe_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.scheme or not parsed.netloc:
        return value
    host = parsed.hostname or parsed.netloc.rsplit("@", 1)[-1]
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def _safe_references(values: tuple[str, ...] | list[object]) -> list[str]:
    references: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            parsed = urlsplit(value)
        except ValueError:
            continue
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        references.append(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")))
    return references


def _safe_match_value(value: str) -> str:
    """Return evidence-safe match text without raw secret-bearing values."""
    redacted = sanitize_command_args(str(value or "").split())
    safe = " ".join(redacted)
    return safe if len(safe) <= 180 else f"{safe[:177]}..."


def sanitize_security_intelligence_entry(entry: dict[str, object]) -> dict[str, object]:
    """Sanitize externally surfaced MCP intelligence evidence."""
    sanitized: dict[str, object] = {}
    for field_name in _INTELLIGENCE_STRING_FIELDS:
        if field_name not in entry:
            continue
        value = entry.get(field_name)
        if field_name == "matched_value":
            sanitized[field_name] = _safe_match_value(str(value or ""))
        else:
            safe_value = sanitize_sensitive_payload(value, key=field_name, max_str_len=500)
            sanitized[field_name] = sanitize_text(safe_value, max_len=500) if safe_value is not None else ""

    references = entry.get("references")
    if isinstance(references, list):
        sanitized["references"] = _safe_references(references)
    elif isinstance(references, tuple):
        sanitized["references"] = _safe_references(list(references))
    else:
        sanitized["references"] = []

    actions = entry.get("remediation_actions")
    if isinstance(actions, (list, tuple)):
        sanitized["remediation_actions"] = [
            sanitize_text(sanitize_sensitive_payload(action, key="remediation_action"), max_len=500)
            for action in actions
            if action is not None
        ][:10]
    elif "remediation_actions" in entry:
        safe_action = sanitize_sensitive_payload(actions, key="remediation_action")
        sanitized["remediation_actions"] = [sanitize_text(safe_action, max_len=500)] if safe_action else []

    return sanitized


def _match_from_entry(
    entry: dict[str, Any],
    *,
    entry_id: str,
    title: str,
    description: str,
    source: str,
    references: tuple[str, ...],
    match_type: str,
    severity: str,
    matched_value: str,
) -> MCPBlocklistMatch:
    normalized_severity = severity if severity in {"critical", "high", "medium", "low"} else "high"
    default_recommendation = "block" if normalized_severity == "critical" else "review"
    return MCPBlocklistMatch(
        entry_id=entry_id,
        title=title,
        description=description,
        match_type=match_type,
        severity=normalized_severity,
        matched_value=matched_value,
        source=source,
        references=tuple(_safe_references(references)),
        confidence=_entry_choice(entry, "confidence", _CONFIDENCE_LEVELS, "heuristic"),
        default_recommendation=_entry_choice(entry, "default_recommendation", _RECOMMENDATIONS, default_recommendation),
        source_type=_entry_choice(entry, "source_type", _SOURCE_TYPES, "heuristic"),
        ecosystem=_entry_str(entry, "ecosystem"),
        package=_entry_str(entry, "package"),
        affected_versions=_entry_str(entry, "affected_versions"),
        first_seen=_entry_str(entry, "first_seen"),
        last_verified=_entry_str(entry, "last_verified"),
        remediation_actions=_entry_strings(entry, "remediation_actions"),
    )


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
        entry_severity = str(entry.get("severity") or "high").lower()

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
                    _match_from_entry(
                        entry,
                        entry_id=entry_id,
                        title=title,
                        description=description,
                        match_type="exact",
                        severity="critical",
                        matched_value=_safe_match_value(normalized_values[expected]),
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
                matches.append(
                    _match_from_entry(
                        entry,
                        entry_id=entry_id,
                        title=title,
                        description=description,
                        match_type="pattern",
                        severity=entry_severity,
                        matched_value=_safe_match_value(value),
                        source=source,
                        references=references,
                    )
                )
                break

    return matches


def _stamp_server_match(server: MCPServer, match: MCPBlocklistMatch) -> bool:
    warning = f"MCP_BLOCKLIST[{match.severity}/{match.match_type}]: {match.entry_id} matched {match.matched_value!r}"
    if warning not in server.security_warnings:
        server.security_warnings.append(warning)
    intelligence = match.to_intelligence()
    existing_keys = {
        (str(item.get("entry_id")), str(item.get("matched_value"))) for item in server.security_intelligence if isinstance(item, dict)
    }
    intel_key = (match.entry_id, match.matched_value)
    if intel_key not in existing_keys:
        server.security_intelligence.append(intelligence)
    if match.default_recommendation == "block":
        server.security_blocked = True
        return True
    return False


def flag_blocklisted_mcp_servers(agents: list[Agent], blocklist: dict[str, Any] | None = None) -> int:
    """Stamp blocklist warnings on discovered MCP servers.

    This is intentionally side-effect only so scan pipelines can run it before
    package extraction and avoid deeper inspection of a server that already
    matches a confirmed critical blocklist entry by name, command, registry id,
    or package identity carried in the discovered config.
    """
    flagged = 0
    for agent in agents:
        for server in agent.mcp_servers:
            server_flagged = False
            for match in match_mcp_server(server, blocklist):
                server_flagged = _stamp_server_match(server, match) or server_flagged
            if server_flagged:
                flagged += 1
    return flagged


def blocklist_findings_for_agents(agents: list[Agent], blocklist: dict[str, Any] | None = None) -> list[Finding]:
    """Create unified findings for MCP blocklist hits and stamp server warnings."""
    findings: list[Finding] = []
    for agent in agents:
        for server in agent.mcp_servers:
            for match in match_mcp_server(server, blocklist):
                _stamp_server_match(server, match)

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
                            "confidence": match.confidence,
                            "default_recommendation": match.default_recommendation,
                            "source_type": match.source_type,
                            "ecosystem": match.ecosystem,
                            "package": match.package,
                            "affected_versions": match.affected_versions,
                            "first_seen": match.first_seen,
                            "last_verified": match.last_verified,
                            "remediation_actions": list(match.remediation_actions),
                            "references": list(match.references),
                        },
                        risk_score=10.0 if match.severity == "critical" else 8.0,
                    )
                )
    return findings
