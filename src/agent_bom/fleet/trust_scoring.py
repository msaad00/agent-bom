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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import Agent


def compute_trust_score(
    agent: "Agent",
    vuln_counts: dict | None = None,
) -> tuple[float, dict]:
    """Compute a trust score (0–100) for an agent.

    Args:
        agent: Discovered agent with MCP servers.
        vuln_counts: Optional dict with keys ``critical``, ``high``, ``medium``,
            ``low`` representing vulnerability counts for this agent.

    Returns:
        Tuple of (score, factors_dict) where factors_dict shows breakdown.
    """
    factors: dict[str, float] = {}

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

    total = round(min(sum(factors.values()), 100.0), 1)
    return total, factors
