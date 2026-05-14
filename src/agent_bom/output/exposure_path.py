"""Shared ExposurePath projection for file-based report formats."""

from __future__ import annotations

from typing import Any

from agent_bom.models import BlastRadius


def exposure_path_for_blast_radius(br: BlastRadius, *, rank: int | None = None) -> dict[str, Any]:
    """Return a bounded, report-safe ExposurePath view for a blast-radius item.

    The API graph endpoints produce richer graph-native ExposurePath payloads.
    File-based reports start from ``BlastRadius``, so this projection preserves
    the same investigation shape without claiming graph persistence or live path
    replay was involved.
    """

    vuln = br.vulnerability
    package = br.package
    package_ref = f"pkg:{package.ecosystem}:{package.name}@{package.version or 'unknown'}"
    finding_ref = f"finding:{vuln.id}"
    source_ref = _source_ref(br)
    target_ref = finding_ref
    nodes = _ordered_unique(
        [
            source_ref,
            *_server_refs(br)[:3],
            package_ref,
            target_ref,
            *_tool_refs(br)[:3],
            *_credential_refs(br)[:3],
        ]
    )
    relationships = _relationships(br, source_ref, package_ref, finding_ref)
    fix = f"Upgrade {package.name} to {vuln.fixed_version}" if vuln.fixed_version else "No upstream fix recorded; monitor advisory source"
    proof_bits = []
    if br.affected_agents:
        proof_bits.append(f"{len(br.affected_agents)} affected agent(s)")
    if br.affected_servers:
        proof_bits.append(f"{len(br.affected_servers)} affected server(s)")
    if br.exposed_tools:
        proof_bits.append(f"{len(br.exposed_tools)} reachable tool(s)")
    if br.exposed_credentials:
        proof_bits.append(f"{len(br.exposed_credentials)} exposed credential reference(s)")
    if vuln.is_kev:
        proof_bits.append("CISA KEV")
    if vuln.epss_score is not None:
        proof_bits.append(f"EPSS {vuln.epss_score:.4f}")

    path_id_parts = [vuln.id, package.ecosystem, package.name, package.version or "unknown"]
    path: dict[str, Any] = {
        "id": "blast:" + ":".join(_slug(part) for part in path_id_parts),
        "rank": rank,
        "label": f"{package.name}@{package.version or '?'} -> {vuln.id}",
        "summary": br.attack_vector_summary
        or br.ai_risk_context
        or f"{vuln.id} affects {package.name}@{package.version or '?'} with {br.reachability} reachability.",
        "riskScore": round(br.risk_score, 2),
        "severity": vuln.severity.value,
        "source": source_ref,
        "target": target_ref,
        "hops": nodes,
        "relationships": relationships,
        "nodeIds": nodes,
        "edgeIds": [rel["id"] for rel in relationships],
        "findings": [vuln.id],
        "affectedAgents": [_agent_label(agent) for agent in br.affected_agents[:10]],
        "affectedServers": [_server_label(server) for server in br.affected_servers[:10]],
        "reachableTools": [tool.name for tool in br.exposed_tools[:10]],
        "exposedCredentials": list(br.exposed_credentials[:10]),
        "dependencyContext": {
            "package": package.name,
            "version": package.version,
            "ecosystem": package.ecosystem,
            "direct": package.is_direct,
            "dependencyDepth": package.dependency_depth,
            "reachabilityEvidence": package.reachability_evidence,
        },
        "fix": fix,
        "evidence": proof_bits,
        "provenance": {"source": "blast_radius_output", "graphPersistence": False},
    }
    return {key: value for key, value in path.items() if value is not None}


def exposure_path_brief(br: BlastRadius, *, rank: int) -> dict[str, str]:
    """Return compact strings for Markdown/HTML investigation summaries."""

    path = exposure_path_for_blast_radius(br, rank=rank)
    proof = ", ".join(str(item) for item in path.get("evidence", [])) or "Package finding"
    return {
        "rank": str(rank),
        "risk": f"{br.risk_score:.1f}",
        "severity": br.vulnerability.severity.value.upper(),
        "path": str(path["label"]),
        "why": str(path["summary"]),
        "proof": proof,
        "fix": str(path["fix"]),
    }


def _agent_label(agent: Any) -> str:
    return str(getattr(agent, "name", "") or getattr(agent, "stable_id", "") or "unknown-agent")


def _server_label(server: Any) -> str:
    return str(getattr(server, "name", "") or getattr(server, "stable_id", "") or "unknown-server")


def _source_ref(br: BlastRadius) -> str:
    if br.affected_agents:
        return f"agent:{_agent_label(br.affected_agents[0])}"
    if br.affected_servers:
        return f"server:{_server_label(br.affected_servers[0])}"
    return f"pkg:{br.package.ecosystem}:{br.package.name}@{br.package.version or 'unknown'}"


def _server_refs(br: BlastRadius) -> list[str]:
    return [f"server:{_server_label(server)}" for server in br.affected_servers]


def _tool_refs(br: BlastRadius) -> list[str]:
    return [f"tool:{tool.name}" for tool in br.exposed_tools]


def _credential_refs(br: BlastRadius) -> list[str]:
    return [f"credential:{name}" for name in br.exposed_credentials]


def _relationships(br: BlastRadius, source_ref: str, package_ref: str, finding_ref: str) -> list[dict[str, str]]:
    rels: list[dict[str, str]] = []

    def add(rel_type: str, source: str, target: str) -> None:
        rels.append({"id": f"{source}->{rel_type}->{target}", "type": rel_type, "source": source, "target": target})

    for server_ref in _server_refs(br)[:3]:
        add("uses", source_ref, server_ref)
        add("depends_on", server_ref, package_ref)
    if not br.affected_servers:
        add("depends_on", source_ref, package_ref)
    add("vulnerable_to", package_ref, finding_ref)
    for tool_ref in _tool_refs(br)[:3]:
        add("provides_tool", source_ref, tool_ref)
    for credential_ref in _credential_refs(br)[:3]:
        add("exposes_credential", source_ref, credential_ref)
    return rels


def _ordered_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {".", "_", "-"} else "-" for ch in value.lower()).strip("-") or "unknown"
