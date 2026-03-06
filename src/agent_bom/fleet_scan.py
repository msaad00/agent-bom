"""Fleet scan — batch registry lookup + risk scoring for MCP server inventories.

Accepts a list of MCP server names (e.g. from CrowdStrike, SIEM, CSV export)
and returns per-server risk assessments using the local registry.

Every field is traceable to a source:
- risk_category: derived from registry category (filesystem→high, search→low)
- risk_justification: human-written per registry entry
- tools/credentials: from registry metadata
- known_cves: from registry CVE enrichment (if populated)
- verdict: composite of registry match + risk level
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_REGISTRY_PATH = Path(__file__).parent / "mcp_registry.json"


@dataclass
class ServerResult:
    """Result of scanning a single server name against the registry."""

    server_name: str
    registry_match: bool = False
    registry_id: str = ""
    display_name: str = ""
    package: str = ""
    ecosystem: str = ""
    category: str = ""
    risk_category: str = ""  # high, medium, low
    risk_justification: str = ""
    verified: bool = False
    license: str = ""
    tools: list[str] = field(default_factory=list)
    credential_env_vars: list[str] = field(default_factory=list)
    known_cves: list[str] = field(default_factory=list)
    latest_version: str = ""
    source_url: str = ""
    verdict: str = ""  # known-high-risk, known-medium, known-low, unknown-unvetted

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FleetScanResult:
    """Aggregated fleet scan results."""

    total: int = 0
    matched: int = 0
    unmatched: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    with_cves: int = 0
    servers: list[ServerResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total": self.total,
                "matched": self.matched,
                "unmatched": self.unmatched,
                "high_risk": self.high_risk,
                "medium_risk": self.medium_risk,
                "low_risk": self.low_risk,
                "with_known_cves": self.with_cves,
            },
            "servers": [s.to_dict() for s in self.servers],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _load_registry() -> dict:
    """Load bundled MCP registry JSON."""
    try:
        return json.loads(_REGISTRY_PATH.read_text()).get("servers", {})
    except (json.JSONDecodeError, OSError):
        return {}


def _match_server(name: str, registry: dict) -> tuple[str, dict] | None:
    """Find a registry entry matching the given server name.

    Tries exact key match, then package match, then display name match,
    then substring match. Returns (registry_key, entry) or None.
    """
    name_lower = name.lower().strip()
    if not name_lower:
        return None

    # 1. Exact key match
    for key, entry in registry.items():
        if key.lower() == name_lower:
            return key, entry

    # 2. Package name match
    for key, entry in registry.items():
        if entry.get("package", "").lower() == name_lower:
            return key, entry

    # 3. Display name match
    for key, entry in registry.items():
        if entry.get("name", "").lower() == name_lower:
            return key, entry

    # 4. Command pattern match
    for key, entry in registry.items():
        for pattern in entry.get("command_patterns", []):
            if pattern.lower() == name_lower or name_lower.endswith(pattern.lower()):
                return key, entry

    # 5. Substring match (last resort — match on key or package)
    for key, entry in registry.items():
        if name_lower in key.lower() or name_lower in entry.get("package", "").lower():
            return key, entry

    return None


def _compute_verdict(matched: bool, risk_level: str, cves: list[str]) -> str:
    """Compute a verdict string from match status and risk level."""
    if not matched:
        return "unknown-unvetted"
    level = risk_level.lower()
    if cves:
        return f"known-{level}-risk-with-cves"
    if level == "high":
        return "known-high-risk"
    if level == "medium":
        return "known-medium"
    return "known-low"


def fleet_scan(
    server_names: list[str],
    registry: dict | None = None,
) -> FleetScanResult:
    """Scan a list of MCP server names against the registry.

    Args:
        server_names: List of server names (e.g. from CrowdStrike endpoint data,
            CSV export, SIEM query). Can include npm-style scoped packages
            (@org/name), plain names, or command names.
        registry: Optional pre-loaded registry dict. Loaded from disk if None.

    Returns:
        FleetScanResult with per-server assessments and aggregate summary.
    """
    if registry is None:
        registry = _load_registry()

    result = FleetScanResult(total=len(server_names))
    seen: set[str] = set()

    for name in server_names:
        name = name.strip()
        if not name:
            continue

        # Deduplicate
        name_key = name.lower()
        if name_key in seen:
            result.total -= 1
            continue
        seen.add(name_key)

        match = _match_server(name, registry)

        if match is None:
            srv = ServerResult(
                server_name=name,
                registry_match=False,
                verdict="unknown-unvetted",
            )
            result.unmatched += 1
        else:
            key, entry = match
            risk_level = entry.get("risk_level", "unknown")
            cves = entry.get("known_cves", [])
            srv = ServerResult(
                server_name=name,
                registry_match=True,
                registry_id=key,
                display_name=entry.get("name", key),
                package=entry.get("package", ""),
                ecosystem=entry.get("ecosystem", ""),
                category=entry.get("category", ""),
                risk_category=risk_level,
                risk_justification=entry.get("risk_justification", ""),
                verified=entry.get("verified", False),
                license=entry.get("license", ""),
                tools=entry.get("tools", []),
                credential_env_vars=entry.get("credential_env_vars", []),
                known_cves=cves,
                latest_version=entry.get("latest_version", ""),
                source_url=entry.get("source_url", ""),
                verdict=_compute_verdict(True, risk_level, cves),
            )
            result.matched += 1
            if risk_level == "high":
                result.high_risk += 1
            elif risk_level == "medium":
                result.medium_risk += 1
            else:
                result.low_risk += 1
            if cves:
                result.with_cves += 1

        result.servers.append(srv)

    return result
