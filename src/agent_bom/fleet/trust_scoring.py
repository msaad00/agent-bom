"""Dynamic trust scoring engine for fleet agents.

Computes a 0–100 trust score based on multiple factors:
- Registry verification status
- Vulnerability posture
- Credential hygiene
- Permission profile
- Configuration quality

Higher score = more trusted.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import Agent


def compute_trust_score(
    agent: "Agent",
    vuln_counts: dict | None = None,
    *,
    runtime_findings: list[dict] | None = None,
) -> tuple[float, dict]:
    """Compute a trust score (0–100) for an agent.

    Args:
        agent: Discovered agent with MCP servers.
        vuln_counts: Optional dict with keys ``critical``, ``high``, ``medium``,
            ``low`` representing vulnerability counts for this agent.

    Returns:
        Tuple of (score, factors_dict) where factors_dict shows breakdown.
    """
    factors: dict[str, object] = {}
    evidence: dict[str, list[str]] = {}

    # 1. Registry Verification (0-20)
    servers = agent.mcp_servers
    if servers:
        verified = sum(1 for s in servers if s.registry_verified)
        factors["registry_verification"] = round((verified / len(servers)) * 20, 1)
    else:
        factors["registry_verification"] = 10.0  # No servers = neutral

    # 2. Vulnerability Posture (0-25)
    if vuln_counts:
        crit = vuln_counts.get("critical", 0)
        high = vuln_counts.get("high", 0)
        med = vuln_counts.get("medium", 0)
        low = vuln_counts.get("low", 0)
        weighted = crit * 10 + high * 5 + med * 2 + low * 0.5
        # Deduct from max 25, floor at 0
        factors["vulnerability_posture"] = round(max(25.0 - weighted, 0.0), 1)
    else:
        factors["vulnerability_posture"] = 25.0  # No scan data = assume clean

    # 3. Credential Hygiene (0-15)
    cred_count = sum(len(s.credential_names) for s in servers)
    if cred_count == 0:
        factors["credential_hygiene"] = 15.0
    elif cred_count <= 2:
        factors["credential_hygiene"] = 10.0
    elif cred_count <= 5:
        factors["credential_hygiene"] = 5.0
    else:
        factors["credential_hygiene"] = 0.0

    # 4. Permission Profile (0-15)
    perm_score = 15.0
    for srv in servers:
        if srv.permission_profile:
            level = srv.permission_profile.privilege_level
            if level == "critical":
                perm_score = min(perm_score, 0.0)
            elif level == "high":
                perm_score = min(perm_score, 5.0)
            elif level == "medium":
                perm_score = min(perm_score, 10.0)
    factors["permission_profile"] = perm_score

    # 5. Enforcement Health (0-15)
    # Without runtime data, give a neutral score
    factors["enforcement_health"] = 10.0

    # 6. Configuration Quality (0-10)
    config_score = 0.0
    if agent.config_path:
        config_score += 3.0
    if agent.version:
        config_score += 2.0
    if servers:
        config_score += 2.0
        # Bonus for tools declared
        has_tools = any(s.tools for s in servers)
        if has_tools:
            config_score += 3.0
        else:
            config_score += 1.0
    factors["configuration_quality"] = min(config_score, 10.0)

    # 7. Discovery provenance adjustment (-5 to +5)
    discovery_score, discovery_evidence = _score_discovery_provenance(agent)
    factors["discovery_provenance"] = discovery_score
    evidence["discovery_provenance"] = discovery_evidence

    # 8. Supply-chain provenance adjustment (-5 to +5)
    provenance_score, provenance_evidence = _score_supply_chain_provenance(agent)
    factors["supply_chain_provenance"] = provenance_score
    evidence["supply_chain_provenance"] = provenance_evidence

    # 9. Runtime drift adjustment (-10 to +3)
    drift_score, drift_evidence = _score_runtime_drift(runtime_findings)
    factors["runtime_drift"] = drift_score
    evidence["runtime_drift"] = drift_evidence

    # 10. Inventory freshness adjustment (-8 to +2)
    freshness_score, freshness_evidence = _score_inventory_freshness(agent)
    factors["inventory_freshness"] = freshness_score
    evidence["inventory_freshness"] = freshness_evidence

    factors["evidence"] = evidence

    numeric_factors = [float(value) for value in factors.values() if isinstance(value, int | float)]
    total = round(min(max(sum(numeric_factors), 0.0), 100.0), 1)
    return total, factors


def _score_discovery_provenance(agent: "Agent") -> tuple[float, list[str]]:
    servers = agent.mcp_servers
    source_counts = [len(getattr(server, "discovery_sources", []) or []) for server in servers]
    if any(count >= 2 for count in source_counts):
        return 5.0, ["at least one MCP server was observed by multiple discovery sources"]
    if any(count == 1 for count in source_counts):
        return 3.0, ["MCP server discovery includes source provenance"]
    if agent.source:
        return 2.0, [f"agent source recorded as {agent.source}"]
    if agent.config_path:
        return 1.0, ["agent has a concrete config path but no merged source provenance"]
    return -5.0, ["agent has no config path or discovery source provenance"]


def _score_supply_chain_provenance(agent: "Agent") -> tuple[float, list[str]]:
    packages = [pkg for server in agent.mcp_servers for pkg in server.packages]
    provenance_values = [getattr(pkg, "provenance_attested", None) for pkg in packages]
    known = [value for value in provenance_values if value is not None]
    if not known:
        return 0.0, ["no package provenance attestation data available"]
    attested = sum(1 for value in known if value is True)
    if attested == len(known):
        return 5.0, ["all packages with provenance data are attested"]
    if attested:
        return 1.0, [f"{attested}/{len(known)} packages with provenance data are attested"]
    return -5.0, ["packages with provenance data are unsigned or unattested"]


def _score_runtime_drift(runtime_findings: list[dict] | None) -> tuple[float, list[str]]:
    if runtime_findings is None:
        return 0.0, ["no runtime drift evidence supplied"]
    drift_categories = {"drift", "description_drift", "tool_drift"}
    drift_count = sum(1 for finding in runtime_findings if str(finding.get("category", "")).lower() in drift_categories)
    if drift_count:
        return -10.0, [f"{drift_count} runtime drift finding(s) observed"]
    return 3.0, ["runtime drift evidence supplied with no drift findings"]


def _score_inventory_freshness(agent: "Agent") -> tuple[float, list[str]]:
    age_hours = _inventory_age_hours(agent)
    if age_hours is None:
        return 0.0, ["no last-seen inventory timestamp supplied"]
    if age_hours <= 24:
        return 2.0, [f"inventory observed {age_hours:.1f} hour(s) ago"]
    if age_hours <= 168:
        return 0.0, [f"inventory observed {age_hours:.1f} hour(s) ago"]
    return -8.0, [f"inventory is stale at {age_hours:.1f} hour(s) old"]


def _inventory_age_hours(agent: "Agent") -> float | None:
    raw_age = agent.metadata.get("inventory_age_hours") if isinstance(agent.metadata, dict) else None
    if isinstance(raw_age, int | float):
        return float(raw_age)
    raw_seen = agent.metadata.get("last_seen_at") if isinstance(agent.metadata, dict) else None
    if not isinstance(raw_seen, str):
        return None
    try:
        seen_at = datetime.fromisoformat(raw_seen.replace("Z", "+00:00"))
    except ValueError:
        return None
    if seen_at.tzinfo is None:
        seen_at = seen_at.replace(tzinfo=timezone.utc)
    return max((datetime.now(timezone.utc) - seen_at).total_seconds() / 3600, 0.0)
