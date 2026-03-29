"""Posture scorecard engine — computes a letter grade + compliance % for an AI-BOM report.

The scorecard aggregates multiple security dimensions into a single
enterprise-friendly posture view:

- Vulnerability severity distribution
- Credential exposure footprint
- Supply-chain quality (OpenSSF Scorecard)
- Framework compliance coverage
- Fleet trust score average
- KEV / active exploitation presence

Output: letter grade (A–F), numeric score (0–100), and per-dimension breakdown.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agent_bom.compliance_utils import effective_blast_radius_tags

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport


@dataclass
class PostureScorecard:
    """Enterprise posture scorecard result."""

    grade: str  # A, B, C, D, F
    score: float  # 0-100
    dimensions: dict[str, DimensionScore] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "grade": self.grade,
            "score": self.score,
            "summary": self.summary,
            "dimensions": {k: v.to_dict() for k, v in self.dimensions.items()},
        }


@dataclass
class DimensionScore:
    """Score for a single posture dimension."""

    name: str
    score: float  # 0-100
    weight: float  # 0-1
    details: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "score": self.score,
            "weight": self.weight,
            "weighted_score": round(self.score * self.weight, 1),
            "details": self.details,
        }


def _score_to_grade(score: float) -> str:
    """Convert numeric score to letter grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_posture_scorecard(report: "AIBOMReport") -> PostureScorecard:
    """Compute posture scorecard from an AI-BOM report.

    Dimensions and weights:
        vulnerability_posture  30%  — severity distribution + fix availability
        credential_hygiene     20%  — credential exposure footprint
        supply_chain_quality   15%  — OpenSSF Scorecard coverage
        compliance_coverage    15%  — threat framework tag coverage
        active_exploitation    10%  — KEV / high EPSS presence
        configuration_quality  10%  — registry verification + tool declaration

    Returns:
        PostureScorecard with grade, score, and per-dimension breakdown.
    """
    dimensions: dict[str, DimensionScore] = {}

    # ── 1. Vulnerability Posture (30%) ──
    sev_counts: Counter[str] = Counter()
    fixable = 0
    total_vulns = 0
    for br in report.blast_radii:
        sev = br.vulnerability.severity.value.upper()
        sev_counts[sev] += 1
        total_vulns += 1
        if br.vulnerability.fixed_version:
            fixable += 1

    if total_vulns == 0:
        vuln_score = 100.0
        vuln_detail = "No vulnerabilities found"
    else:
        # Weighted penalty: critical=15, high=8, medium=3, low=1
        penalty = (
            sev_counts.get("CRITICAL", 0) * 15
            + sev_counts.get("HIGH", 0) * 8
            + sev_counts.get("MEDIUM", 0) * 3
            + sev_counts.get("LOW", 0) * 1
        )
        vuln_score = max(0.0, 100.0 - penalty)
        # Bonus for fixable vulns
        fix_ratio = fixable / total_vulns if total_vulns > 0 else 0
        vuln_score = min(100.0, vuln_score + fix_ratio * 10)
        parts = [f"{sev_counts[s]} {s.lower()}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if sev_counts.get(s, 0) > 0]
        vuln_detail = f"{total_vulns} vulns ({', '.join(parts)}), {fixable} fixable"

    dimensions["vulnerability_posture"] = DimensionScore(
        name="Vulnerability Posture",
        score=round(vuln_score, 1),
        weight=0.30,
        details=vuln_detail,
    )

    # ── 2. Credential Hygiene (20%) ──
    total_cred_servers = 0
    unique_creds: set[str] = set()
    for agent in report.agents:
        for server in agent.mcp_servers:
            if server.has_credentials:
                total_cred_servers += 1
                for cred in server.credential_names:
                    unique_creds.add(cred)

    if total_cred_servers == 0:
        cred_score = 100.0
        cred_detail = "No credential exposure detected"
    else:
        # Penalty scales with exposed credential count
        cred_penalty = min(len(unique_creds) * 8 + total_cred_servers * 3, 100)
        cred_score = max(0.0, 100.0 - cred_penalty)
        cred_detail = f"{len(unique_creds)} unique credentials across {total_cred_servers} servers"

    dimensions["credential_hygiene"] = DimensionScore(
        name="Credential Hygiene",
        score=round(cred_score, 1),
        weight=0.20,
        details=cred_detail,
    )

    # ── 3. Supply Chain Quality (15%) ──
    scorecard_scores: list[float] = []
    for agent in report.agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                if pkg.scorecard_score is not None:
                    scorecard_scores.append(pkg.scorecard_score)

    if scorecard_scores:
        avg_scorecard = sum(scorecard_scores) / len(scorecard_scores)
        sc_score = min(100.0, avg_scorecard * 10)  # 0-10 → 0-100
        sc_detail = f"Avg OpenSSF Scorecard: {avg_scorecard:.1f}/10 ({len(scorecard_scores)} packages)"
    else:
        sc_score = 50.0  # Neutral when no scorecard data
        sc_detail = "No OpenSSF Scorecard data available"

    dimensions["supply_chain_quality"] = DimensionScore(
        name="Supply Chain Quality",
        score=round(sc_score, 1),
        weight=0.15,
        details=sc_detail,
    )

    # ── 4. Compliance Coverage (15%) ──
    total_tags = 0
    tagged_findings = 0
    for br in report.blast_radii:
        tags = effective_blast_radius_tags(br)
        total_tags += 1
        has_tag = bool(
            tags["owasp_tags"]
            or tags["atlas_tags"]
            or tags["nist_ai_rmf_tags"]
            or tags["owasp_mcp_tags"]
            or tags["owasp_agentic_tags"]
            or tags["eu_ai_act_tags"]
            or tags["nist_csf_tags"]
            or tags["iso_27001_tags"]
            or tags["soc2_tags"]
            or tags["cis_tags"]
        )
        if has_tag:
            tagged_findings += 1

    if total_tags == 0:
        comp_score = 100.0
        comp_detail = "No findings to map"
    else:
        coverage = tagged_findings / total_tags
        comp_score = min(100.0, coverage * 100)
        comp_detail = f"{tagged_findings}/{total_tags} findings mapped to threat frameworks"

    dimensions["compliance_coverage"] = DimensionScore(
        name="Compliance Coverage",
        score=round(comp_score, 1),
        weight=0.15,
        details=comp_detail,
    )

    # ── 5. Active Exploitation (10%) ──
    from agent_bom.config import EPSS_CRITICAL_THRESHOLD

    kev_ids: set[str] = set()
    high_epss_ids: set[str] = set()
    for br in report.blast_radii:
        vid = br.vulnerability.id
        if br.vulnerability.is_kev:
            kev_ids.add(vid)
        if (br.vulnerability.epss_score or 0) >= EPSS_CRITICAL_THRESHOLD:
            high_epss_ids.add(vid)

    # Deduplicate: vulns that are both KEV and high-EPSS count once at the higher KEV penalty
    kev_only = kev_ids - high_epss_ids
    epss_only = high_epss_ids - kev_ids
    both = kev_ids & high_epss_ids

    if not kev_ids and not high_epss_ids:
        exploit_score = 100.0
        exploit_detail = "No actively exploited vulnerabilities"
    else:
        # KEV penalty=25, EPSS-only penalty=10, both=25 (no double-count)
        exploit_penalty = len(kev_only) * 25 + len(epss_only) * 10 + len(both) * 25
        exploit_score = max(0.0, 100.0 - exploit_penalty)
        parts = []
        if kev_ids:
            parts.append(f"{len(kev_ids)} CISA KEV")
        if high_epss_ids:
            parts.append(f"{len(high_epss_ids)} high-EPSS")
        exploit_detail = ", ".join(parts)

    dimensions["active_exploitation"] = DimensionScore(
        name="Active Exploitation",
        score=round(exploit_score, 1),
        weight=0.10,
        details=exploit_detail,
    )

    # ── 6. Configuration Quality (10%) ──
    total_servers = sum(len(a.mcp_servers) for a in report.agents)
    verified_servers = sum(1 for a in report.agents for s in a.mcp_servers if s.registry_verified)
    servers_with_tools = sum(1 for a in report.agents for s in a.mcp_servers if s.tools)

    if total_servers == 0:
        config_score = 50.0
        config_detail = "No servers to evaluate"
    elif not report.has_mcp_context:
        config_score = 100.0
        config_detail = "N/A for scans without MCP server configuration context"
    else:
        verified_pct = verified_servers / total_servers
        tools_pct = servers_with_tools / total_servers
        config_score = verified_pct * 60 + tools_pct * 40
        config_detail = f"{verified_servers}/{total_servers} verified, {servers_with_tools}/{total_servers} with tool declarations"

    dimensions["configuration_quality"] = DimensionScore(
        name="Configuration Quality",
        score=round(config_score, 1),
        weight=0.10,
        details=config_detail,
    )

    # ── Final score ──
    total_score = sum(d.score * d.weight for d in dimensions.values())
    total_score = round(min(100.0, max(0.0, total_score)), 1)
    grade = _score_to_grade(total_score)

    # Build summary
    if grade in ("A", "B"):
        summary = f"Strong security posture ({grade}, {total_score}%)"
    elif grade == "C":
        summary = f"Moderate security posture ({grade}, {total_score}%) — improvements recommended"
    else:
        summary = f"Weak security posture ({grade}, {total_score}%) — immediate attention required"

    return PostureScorecard(
        grade=grade,
        score=total_score,
        dimensions=dimensions,
        summary=summary,
    )


def compute_credential_risk_ranking(report: "AIBOMReport") -> list[dict]:
    """Rank credentials by blast radius exposure.

    Returns a sorted list of credentials with:
    - credential name
    - exposure count (how many servers)
    - affected agents
    - associated vulnerabilities (critical/high counts)
    - risk tier (critical, high, medium, low)
    """
    cred_data: dict[str, dict] = {}

    for br in report.blast_radii:
        for cred in br.exposed_credentials:
            if cred not in cred_data:
                cred_data[cred] = {
                    "credential": cred,
                    "server_count": 0,
                    "agents": set(),
                    "vuln_critical": 0,
                    "vuln_high": 0,
                    "vuln_total": 0,
                    "max_risk_score": 0.0,
                    "servers": set(),
                }
            entry = cred_data[cred]
            for a in br.affected_agents:
                entry["agents"].add(a.name)
            for s in br.affected_servers:
                entry["servers"].add(s.name)
            sev = br.vulnerability.severity.value.upper()
            if sev == "CRITICAL":
                entry["vuln_critical"] += 1
            elif sev == "HIGH":
                entry["vuln_high"] += 1
            entry["vuln_total"] += 1
            entry["max_risk_score"] = max(entry["max_risk_score"], br.risk_score)

    results = []
    for cred, data in cred_data.items():
        server_count = len(data["servers"])
        agents = sorted(data["agents"])
        risk_score = data["max_risk_score"]

        if data["vuln_critical"] > 0 or risk_score >= 8.0:
            risk_tier = "critical"
        elif data["vuln_high"] > 0 or risk_score >= 6.0:
            risk_tier = "high"
        elif data["vuln_total"] > 3:
            risk_tier = "medium"
        else:
            risk_tier = "low"

        results.append(
            {
                "credential": cred,
                "risk_tier": risk_tier,
                "server_count": server_count,
                "agents": agents,
                "vuln_critical": data["vuln_critical"],
                "vuln_high": data["vuln_high"],
                "vuln_total": data["vuln_total"],
                "max_risk_score": round(risk_score, 1),
            }
        )

    # Sort by risk: critical first, then by max_risk_score descending
    tier_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda x: (tier_order.get(x["risk_tier"], 4), -x["max_risk_score"]))
    return results


def compute_incident_correlation(report: "AIBOMReport") -> list[dict]:
    """Group vulnerabilities by agent for SOC incident correlation.

    Returns a list of agent-centric incident summaries with:
    - agent name, type, config path
    - vulnerability counts by severity
    - unique CVE IDs
    - credential exposure
    - overall incident priority (P1-P4)
    - recommended actions
    """
    agent_incidents: dict[str, dict] = {}

    for br in report.blast_radii:
        for agent in br.affected_agents:
            if agent.name not in agent_incidents:
                agent_incidents[agent.name] = {
                    "agent_name": agent.name,
                    "agent_type": agent.agent_type.value,
                    "config_path": agent.config_path,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "cve_ids": set(),
                    "kev_ids": set(),
                    "credentials_exposed": set(),
                    "packages_affected": set(),
                    "max_risk_score": 0.0,
                    "has_ai_risk": False,
                }

            entry = agent_incidents[agent.name]
            sev = br.vulnerability.severity.value.upper()
            if sev == "CRITICAL":
                entry["critical"] += 1
            elif sev == "HIGH":
                entry["high"] += 1
            elif sev == "MEDIUM":
                entry["medium"] += 1
            else:
                entry["low"] += 1

            entry["cve_ids"].add(br.vulnerability.id)
            if br.vulnerability.is_kev:
                entry["kev_ids"].add(br.vulnerability.id)
            for cred in br.exposed_credentials:
                entry["credentials_exposed"].add(cred)
            entry["packages_affected"].add(f"{br.package.name}@{br.package.version}")
            entry["max_risk_score"] = max(entry["max_risk_score"], br.risk_score)
            if br.ai_risk_context:
                entry["has_ai_risk"] = True

    results = []
    for data in agent_incidents.values():
        # Determine incident priority
        if data["kev_ids"] or data["critical"] >= 3:
            priority = "P1"
            recommended = "Immediate remediation required — actively exploited or multiple critical CVEs"
        elif data["critical"] > 0 or (data["high"] > 0 and data["credentials_exposed"]):
            priority = "P2"
            recommended = "Urgent remediation — critical CVEs or credential-exposed high-severity vulns"
        elif data["high"] > 0:
            priority = "P3"
            recommended = "Scheduled remediation — high-severity vulnerabilities present"
        else:
            priority = "P4"
            recommended = "Monitor and patch during next maintenance window"

        results.append(
            {
                "agent_name": data["agent_name"],
                "agent_type": data["agent_type"],
                "config_path": data["config_path"],
                "priority": priority,
                "severity_counts": {
                    "critical": data["critical"],
                    "high": data["high"],
                    "medium": data["medium"],
                    "low": data["low"],
                },
                "total_vulns": data["critical"] + data["high"] + data["medium"] + data["low"],
                "unique_cves": sorted(data["cve_ids"]),
                "kev_ids": sorted(data["kev_ids"]),
                "credentials_exposed": sorted(data["credentials_exposed"]),
                "packages_affected": sorted(data["packages_affected"]),
                "max_risk_score": round(data["max_risk_score"], 1),
                "has_ai_risk": data["has_ai_risk"],
                "recommended_action": recommended,
            }
        )

    # Sort by priority (P1 first), then by max_risk_score descending
    priority_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    results.sort(key=lambda x: (priority_order.get(x["priority"], 4), -x["max_risk_score"]))
    return results
