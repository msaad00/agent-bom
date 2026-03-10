"""Toxic combination detection — chained risk analysis.

Identifies dangerous combinations of vulnerabilities, credentials, tools,
and blast radius that individually might be acceptable but together form
critical attack chains (e.g., "Critical CVE + exposed API key + EXECUTE tool
+ shared across 3 agents").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius


class ToxicPattern(str, Enum):
    """Categories of toxic combinations."""

    CRED_BLAST = "credential_blast"
    LATERAL_CHAIN = "lateral_chain"
    EXECUTE_EXPLOIT = "execute_exploit"
    MULTI_AGENT_CVE = "multi_agent_cve"
    KEV_WITH_CREDS = "kev_with_credentials"
    TRANSITIVE_CRITICAL = "transitive_critical"
    CACHE_POISON = "cache_poison"
    CROSS_AGENT_POISON = "cross_agent_poison"


def _word_boundary_match(keyword: str, text: str) -> bool:
    """Check if keyword appears as a whole word (not substring) in text.

    Normalizes separators (underscores, hyphens, dots) to spaces first so
    "run" matches "run_command" and "run-task" but not "runner".
    """
    normalized = re.sub(r"[_\-.]", " ", text)
    return bool(re.search(rf"\b{re.escape(keyword)}\b", normalized))


@dataclass
class ToxicCombination:
    """A detected toxic combination of risk factors."""

    pattern: ToxicPattern
    severity: str  # critical, high
    title: str
    description: str
    components: list[dict] = field(default_factory=list)
    risk_score: float = 0.0
    remediation: str = ""


def detect_toxic_combinations(
    report: AIBOMReport,
    context_graph_data: dict | None = None,
) -> list[ToxicCombination]:
    """Analyze a report for toxic combinations using blast radius data.

    Detects patterns where individually-acceptable risks combine into
    critical attack chains.
    """
    combos: list[ToxicCombination] = []

    if report.blast_radii:
        combos.extend(_detect_cred_blast(report.blast_radii))
        combos.extend(_detect_kev_with_creds(report.blast_radii))
        combos.extend(_detect_execute_exploit(report.blast_radii))
        combos.extend(_detect_multi_agent_cve(report.blast_radii))
        combos.extend(_detect_transitive_critical(report.blast_radii))
        # Cache poison can be detected from tool names alone — no context required
        combos.extend(_detect_cache_poison(report.blast_radii, context_graph_data or {}))
        if context_graph_data:
            combos.extend(_detect_lateral_chain(report.blast_radii, context_graph_data))

    # Context-graph-based detectors run even without blast_radii (structural risk)
    if context_graph_data:
        combos.extend(_detect_cross_agent_poison(report.blast_radii, context_graph_data))

    # Deduplicate by (pattern, title)
    seen: set[tuple[str, str]] = set()
    unique: list[ToxicCombination] = []
    for c in combos:
        key = (c.pattern.value, c.title)
        if key not in seen:
            seen.add(key)
            unique.append(c)

    # Sort by risk score descending
    unique.sort(key=lambda c: c.risk_score, reverse=True)
    return unique


# ---------------------------------------------------------------------------
# Pattern detectors
# ---------------------------------------------------------------------------


def _detect_cred_blast(blast_radii: list[BlastRadius]) -> list[ToxicCombination]:
    """Critical/High CVE + exposed credentials = credential blast."""
    results = []
    for br in blast_radii:
        if br.vulnerability.severity.value not in ("critical", "high"):
            continue
        if not br.exposed_credentials:
            continue

        cred_names = ", ".join(br.exposed_credentials[:3])
        extra = f" (+{len(br.exposed_credentials) - 3} more)" if len(br.exposed_credentials) > 3 else ""
        results.append(
            ToxicCombination(
                pattern=ToxicPattern.CRED_BLAST,
                severity="critical",
                title=f"Credential Blast: {br.vulnerability.id} exposes {cred_names}{extra}",
                description=(
                    f"{br.vulnerability.id} ({br.vulnerability.severity.value}) in {br.package.name}@{br.package.version} "
                    f"exposes {len(br.exposed_credentials)} credential(s). An attacker exploiting this vulnerability "
                    f"could extract API keys and tokens for lateral movement."
                ),
                components=[
                    {"type": "cve", "id": br.vulnerability.id, "label": f"{br.vulnerability.severity.value} severity"},
                    *[{"type": "credential", "id": c, "label": c} for c in br.exposed_credentials[:5]],
                    {"type": "package", "id": f"{br.package.name}@{br.package.version}", "label": br.package.ecosystem},
                ],
                risk_score=min(br.risk_score * 1.5, 10.0) if br.risk_score else 9.0,
                remediation=f"Upgrade {br.package.name} to {br.vulnerability.fixed_version or 'latest'}. "
                f"Rotate exposed credentials: {cred_names}.",
            )
        )
    return results


def _detect_kev_with_creds(blast_radii: list[BlastRadius]) -> list[ToxicCombination]:
    """CISA KEV vulnerability + any credential exposure = urgent fix."""
    results = []
    for br in blast_radii:
        if not br.vulnerability.is_kev:
            continue
        if not br.exposed_credentials:
            continue

        results.append(
            ToxicCombination(
                pattern=ToxicPattern.KEV_WITH_CREDS,
                severity="critical",
                title=f"KEV + Credentials: {br.vulnerability.id} actively exploited with exposed secrets",
                description=(
                    f"{br.vulnerability.id} is in CISA's Known Exploited Vulnerabilities catalog "
                    f"and {len(br.exposed_credentials)} credential(s) are accessible through the same "
                    f"server. Active exploitation in the wild makes this an immediate risk."
                ),
                components=[
                    {"type": "cve", "id": br.vulnerability.id, "label": "CISA KEV"},
                    *[{"type": "credential", "id": c, "label": c} for c in br.exposed_credentials[:5]],
                ],
                risk_score=10.0,
                remediation=(
                    f"IMMEDIATE: Patch {br.package.name} to {br.vulnerability.fixed_version or 'latest'}. "
                    f"Rotate all exposed credentials. Check audit logs for unauthorized access."
                ),
            )
        )
    return results


def _detect_execute_exploit(blast_radii: list[BlastRadius]) -> list[ToxicCombination]:
    """CVE + EXECUTE/destructive-capable tool = code execution chain."""
    results = []
    for br in blast_radii:
        if br.vulnerability.severity.value not in ("critical", "high"):
            continue
        if not br.exposed_tools:
            continue

        # Look for tools with execute/write/destructive capabilities
        dangerous_tools = []
        for tool in br.exposed_tools:
            desc_lower = (tool.description or "").lower()
            name_lower = tool.name.lower()
            if any(
                _word_boundary_match(kw, desc_lower) or _word_boundary_match(kw, name_lower)
                for kw in ("execute", "run", "shell", "write", "delete", "destroy", "eval")
            ):
                dangerous_tools.append(tool)

        if not dangerous_tools:
            continue

        tool_names = ", ".join(t.name for t in dangerous_tools[:3])
        results.append(
            ToxicCombination(
                pattern=ToxicPattern.EXECUTE_EXPLOIT,
                severity="critical",
                title=f"Execute Chain: {br.vulnerability.id} + {tool_names}",
                description=(
                    f"{br.vulnerability.id} in {br.package.name} combined with {len(dangerous_tools)} "
                    f"execute-capable tool(s) ({tool_names}) creates a code execution chain. "
                    f"An attacker could exploit the vulnerability to invoke these tools."
                ),
                components=[
                    {"type": "cve", "id": br.vulnerability.id, "label": br.vulnerability.severity.value},
                    *[
                        {"type": "tool", "id": t.name, "label": t.description[:50] if t.description else t.name}
                        for t in dangerous_tools[:5]
                    ],
                ],
                risk_score=min(br.risk_score * 1.3, 10.0) if br.risk_score else 8.5,
                remediation=f"Upgrade {br.package.name}. Review tool permissions for {tool_names}.",
            )
        )
    return results


def _detect_multi_agent_cve(blast_radii: list[BlastRadius]) -> list[ToxicCombination]:
    """Same CVE affects 3+ agents = widespread exposure."""
    # Group by CVE ID
    cve_agents: dict[str, set[str]] = {}
    cve_br: dict[str, BlastRadius] = {}
    for br in blast_radii:
        vid = br.vulnerability.id
        if vid not in cve_agents:
            cve_agents[vid] = set()
            cve_br[vid] = br
        for agent in br.affected_agents:
            cve_agents[vid].add(agent.name)

    results = []
    for vid, agents in cve_agents.items():
        if len(agents) < 3:
            continue
        br = cve_br[vid]
        agent_list = ", ".join(sorted(agents)[:5])
        results.append(
            ToxicCombination(
                pattern=ToxicPattern.MULTI_AGENT_CVE,
                severity="high",
                title=f"Multi-Agent CVE: {vid} across {len(agents)} agents",
                description=(
                    f"{vid} ({br.vulnerability.severity.value}) affects {len(agents)} agents: {agent_list}. "
                    f"Shared vulnerability across multiple agents amplifies blast radius."
                ),
                components=[
                    {"type": "cve", "id": vid, "label": br.vulnerability.severity.value},
                    *[{"type": "agent", "id": a, "label": a} for a in sorted(agents)[:5]],
                ],
                risk_score=min(br.risk_score * 1.2, 10.0) if br.risk_score else 7.5,
                remediation=f"Upgrade {br.package.name} across all {len(agents)} agents.",
            )
        )
    return results


def _detect_transitive_critical(blast_radii: list[BlastRadius]) -> list[ToxicCombination]:
    """Critical vulnerability in a transitive dependency = hidden risk."""
    results = []
    for br in blast_radii:
        if br.vulnerability.severity.value != "critical":
            continue
        if br.package.is_direct:
            continue
        # Transitive + critical = hidden risk
        parent = br.package.parent_package or "unknown"
        results.append(
            ToxicCombination(
                pattern=ToxicPattern.TRANSITIVE_CRITICAL,
                severity="high",
                title=f"Hidden Critical: {br.vulnerability.id} in transitive dep {br.package.name}",
                description=(
                    f"Critical vulnerability {br.vulnerability.id} exists in {br.package.name}@{br.package.version}, "
                    f"a transitive dependency of {parent}. Transitive vulnerabilities are often overlooked "
                    f"but can be equally exploitable."
                ),
                components=[
                    {"type": "cve", "id": br.vulnerability.id, "label": "critical"},
                    {"type": "package", "id": f"{br.package.name}@{br.package.version}", "label": "transitive"},
                    {"type": "package", "id": parent, "label": "parent"},
                ],
                risk_score=min(br.risk_score * 1.1, 10.0) if br.risk_score else 7.0,
                remediation=f"Upgrade {parent} to a version that pulls a patched {br.package.name}.",
            )
        )
    return results


def _detect_lateral_chain(
    blast_radii: list[BlastRadius],
    context_graph_data: dict,
) -> list[ToxicCombination]:
    """CVE + lateral movement path in context graph = attack chain."""
    lateral_paths = context_graph_data.get("lateral_paths", [])
    if not lateral_paths:
        return []

    # Build set of servers involved in lateral movement
    lateral_servers: set[str] = set()
    for path in lateral_paths:
        for node in path if isinstance(path, list) else []:
            if isinstance(node, str):
                lateral_servers.add(node)
            elif isinstance(node, dict):
                lateral_servers.add(node.get("id", node.get("name", "")) or "")

    results = []
    for br in blast_radii:
        if br.vulnerability.severity.value not in ("critical", "high"):
            continue
        # Check if any affected server is in a lateral path
        affected_in_lateral = [s for s in br.affected_servers if s.name in lateral_servers]
        if not affected_in_lateral:
            continue

        server_names = ", ".join(s.name for s in affected_in_lateral[:3])
        results.append(
            ToxicCombination(
                pattern=ToxicPattern.LATERAL_CHAIN,
                severity="critical",
                title=f"Lateral Chain: {br.vulnerability.id} on lateral path via {server_names}",
                description=(
                    f"{br.vulnerability.id} in {br.package.name} affects server(s) on a lateral movement path. "
                    f"An attacker could exploit this to pivot across the agent ecosystem."
                ),
                components=[
                    {"type": "cve", "id": br.vulnerability.id, "label": br.vulnerability.severity.value},
                    *[{"type": "server", "id": s.name, "label": "lateral path"} for s in affected_in_lateral[:5]],
                ],
                risk_score=min(br.risk_score * 1.4, 10.0) if br.risk_score else 9.0,
                remediation=f"Patch {br.package.name}. Review lateral movement paths and isolate {server_names}.",
            )
        )
    return results


def _detect_cross_agent_poison(
    blast_radii: list[BlastRadius],
    context_graph_data: dict,
) -> list[ToxicCombination]:
    """Detect cross-agent injection: one agent can write to a shared resource read by another.

    Attack pattern: Agent A has a write-capable tool on a shared MCP server.
    Agent B has a read/retrieval tool on the same server. Agent A can poison
    the shared context that Agent B will later consume.
    """
    shared_servers = context_graph_data.get("shared_servers", [])
    if not shared_servers:
        return []

    results = []
    for server_info in shared_servers:
        server_name = server_info.get("name", "") if isinstance(server_info, dict) else str(server_info)
        agents = server_info.get("agents", []) if isinstance(server_info, dict) else []
        tools = server_info.get("tools", []) if isinstance(server_info, dict) else []

        if len(agents) < 2:
            continue

        # Check for write + read tool pair on the same shared server
        write_tools = [
            t
            for t in tools
            if any(kw in str(t).lower() for kw in ("write", "insert", "store", "save", "create", "add", "index", "upsert", "embed"))
        ]
        read_tools = [
            t
            for t in tools
            if any(kw in str(t).lower() for kw in ("read", "search", "query", "retrieve", "fetch", "get", "lookup", "similarity"))
        ]

        if not (write_tools and read_tools):
            continue

        agent_names = ", ".join(str(a) for a in agents[:4])
        write_names = ", ".join(str(t) for t in write_tools[:2])
        read_names = ", ".join(str(t) for t in read_tools[:2])

        results.append(
            ToxicCombination(
                pattern=ToxicPattern.CROSS_AGENT_POISON,
                severity="high",
                title=f"Cross-Agent Poison: shared server '{server_name}' has write+read tool pair",
                description=(
                    f"Server '{server_name}' is shared by {len(agents)} agents ({agent_names}) and "
                    f"exposes both write tools ({write_names}) and read/retrieval tools ({read_names}). "
                    f"An agent or external attacker that can invoke write tools can poison the shared "
                    f"context consumed by other agents via read tools."
                ),
                components=[
                    {"type": "server", "id": server_name, "label": "shared"},
                    *[{"type": "agent", "id": str(a), "label": "affected"} for a in agents[:4]],
                    *[{"type": "tool", "id": str(t), "label": "write"} for t in write_tools[:2]],
                    *[{"type": "tool", "id": str(t), "label": "read"} for t in read_tools[:2]],
                ],
                risk_score=8.0,
                remediation=(
                    f"Restrict write access to '{server_name}' to trusted agents only. "
                    f"Add input validation and content scanning on write tools. "
                    f"Consider separate servers per agent to eliminate the shared surface."
                ),
            )
        )
    return results


def _detect_cache_poison(
    blast_radii: list[BlastRadius],
    context_graph_data: dict,
) -> list[ToxicCombination]:
    """Detect cache poisoning: CVE in a package + vector DB / RAG retrieval tool exposure.

    When a vulnerable package backs an MCP server that exposes retrieval tools
    (similarity search, RAG query), an attacker can exploit the CVE to inject
    malicious content into the vector store, poisoning the LLM's retrieved context.
    """
    vector_servers = context_graph_data.get("vector_db_servers", [])
    vector_server_names: set[str] = {(s.get("name", "") if isinstance(s, dict) else str(s)) for s in vector_servers}

    # Also infer from tool names if vector_db_servers not populated
    results = []
    for br in blast_radii:
        if br.vulnerability.severity.value not in ("critical", "high"):
            continue

        # Check if any exposed tool looks like a vector/RAG retrieval tool
        retrieval_tools = [
            t
            for t in br.exposed_tools
            if any(
                kw in (t.name + " " + (t.description or "")).lower()
                for kw in ("similarity", "semantic", "retriev", "embedding", "vector", "rag", "context", "knowledge")
            )
        ]
        # Or check if the affected server is a known vector DB server
        vector_affected = [s for s in br.affected_servers if s.name in vector_server_names]

        if not retrieval_tools and not vector_affected:
            continue

        tool_names = ", ".join(t.name for t in retrieval_tools[:3])
        server_names = ", ".join(s.name for s in vector_affected[:2])
        target_label = tool_names or server_names

        results.append(
            ToxicCombination(
                pattern=ToxicPattern.CACHE_POISON,
                severity="critical",
                title=f"Cache Poison: {br.vulnerability.id} + RAG/vector retrieval ({target_label})",
                description=(
                    f"{br.vulnerability.id} ({br.vulnerability.severity.value}) in {br.package.name}@{br.package.version} "
                    f"backs a server with RAG/vector retrieval tools ({target_label}). "
                    f"An attacker exploiting this CVE could inject malicious instructions into the "
                    f"vector store, poisoning LLM context on every retrieval query."
                ),
                components=[
                    {"type": "cve", "id": br.vulnerability.id, "label": br.vulnerability.severity.value},
                    {"type": "package", "id": f"{br.package.name}@{br.package.version}", "label": "vector backend"},
                    *[{"type": "tool", "id": t.name, "label": "retrieval"} for t in retrieval_tools[:3]],
                    *[{"type": "server", "id": s.name, "label": "vector_db"} for s in vector_affected[:2]],
                ],
                risk_score=min(br.risk_score * 1.5, 10.0) if br.risk_score else 9.5,
                remediation=(
                    f"Patch {br.package.name} to {br.vulnerability.fixed_version or 'latest'}. "
                    f"Add content scanning on vector store writes. "
                    f"Enable authentication on vector DB endpoints. "
                    f"Implement retrieval output filtering before passing to LLM."
                ),
            )
        )
    return results


# ---------------------------------------------------------------------------
# Prioritization
# ---------------------------------------------------------------------------


def prioritize_findings(
    blast_radii: list[BlastRadius],
    toxic_combos: list[ToxicCombination],
) -> list[dict]:
    """Return priority-ordered findings combining individual vulns + toxic combos.

    Toxic combinations get a 1.5x multiplier on their risk score.
    """
    findings: list[dict] = []

    # Toxic combos as findings (boosted)
    for combo in toxic_combos:
        findings.append(
            {
                "type": "toxic_combination",
                "id": combo.title,
                "severity": combo.severity,
                "risk_score": combo.risk_score,
                "pattern": combo.pattern.value,
                "title": combo.title,
                "description": combo.description,
                "remediation": combo.remediation,
                "components": combo.components,
            }
        )

    # Individual blast radii as findings
    # Track CVEs already covered by toxic combos to avoid duplication in view
    toxic_cves: set[str] = set()
    for combo in toxic_combos:
        for comp in combo.components:
            if comp.get("type") == "cve":
                toxic_cves.add(comp["id"])

    for br in blast_radii:
        findings.append(
            {
                "type": "vulnerability",
                "id": br.vulnerability.id,
                "severity": br.vulnerability.severity.value,
                "risk_score": br.risk_score,
                "package": f"{br.package.name}@{br.package.version}",
                "ecosystem": br.package.ecosystem,
                "in_toxic_combo": br.vulnerability.id in toxic_cves,
                "agents": [a.name for a in br.affected_agents],
                "credentials_exposed": len(br.exposed_credentials),
                "tools_exposed": len(br.exposed_tools),
            }
        )

    # Sort by risk score descending, toxic combos first at same score
    findings.sort(key=lambda f: (f["risk_score"], 1 if f["type"] == "toxic_combination" else 0), reverse=True)
    return findings


def to_serializable(combos: list[ToxicCombination]) -> list[dict]:
    """Convert toxic combinations to JSON-serializable dicts."""
    return [
        {
            "pattern": c.pattern.value,
            "severity": c.severity,
            "title": c.title,
            "description": c.description,
            "components": c.components,
            "risk_score": c.risk_score,
            "remediation": c.remediation,
        }
        for c in combos
    ]
