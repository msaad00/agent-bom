"""Shared ExposurePath projection for file-based report formats."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.models import BlastRadius

if TYPE_CHECKING:
    from agent_bom.finding import Finding


def _display_package_name(name: str, version: str | None) -> str:
    """Return the package name without a redundant ``@<version>`` suffix.

    Some ingestion paths store ``name@version`` in ``Package.name``. Builders here
    append the version again, so without stripping the duplicate suffix a package
    named ``form-data@4.0.0`` renders as ``form-data@4.0.0@4.0.0``. The graph node
    label already guards against this via ``split("@")[0]``; this keeps the
    file-report projection consistent.
    """
    name = (name or "").strip()
    version = (version or "").strip()
    if version and name.endswith(f"@{version}"):
        return name[: -(len(version) + 1)]
    return name


def exposure_path_for_finding(
    finding: Finding,
    *,
    rank: int | None = None,
    provenance_source: str = "finding_output",
) -> dict[str, Any]:
    """Return a bounded, report-safe ExposurePath view for a unified Finding."""

    from agent_bom.output.finding_views import package_ecosystem, package_name, package_version

    pkg_name = package_name(finding)
    pkg_version = package_version(finding)
    ecosystem = package_ecosystem(finding)
    display_name = _display_package_name(pkg_name, pkg_version or None)
    package_ref = f"pkg:{ecosystem}:{display_name}@{pkg_version or 'unknown'}"
    vuln_id = finding.cve_id or finding.title or finding.asset.name
    finding_ref = f"finding:{vuln_id}"
    source_ref = _source_ref_for_finding(finding, display_name, pkg_version, ecosystem)
    target_ref = finding_ref
    server_refs = _server_refs_for_finding(finding)
    tool_refs = _tool_refs_for_finding(finding)
    credential_refs = _credential_refs_for_finding(finding)
    nodes = _ordered_unique(
        [
            source_ref,
            *server_refs[:3],
            package_ref,
            target_ref,
            *tool_refs[:3],
            *credential_refs[:3],
        ]
    )
    relationships = _relationships_for_finding(
        finding,
        source_ref,
        package_ref,
        finding_ref,
        server_refs,
        tool_refs,
        credential_refs,
    )
    fix = (
        f"Upgrade {display_name} to {finding.fixed_version}"
        if finding.fixed_version
        else "No upstream fix recorded; monitor advisory source"
    )
    proof_bits: list[str] = []
    if finding.affected_agents:
        proof_bits.append(f"{len(finding.affected_agents)} affected agent(s)")
    if finding.affected_servers:
        proof_bits.append(f"{len(finding.affected_servers)} affected server(s)")
    if finding.exposed_tools:
        proof_bits.append(f"{len(finding.exposed_tools)} reachable tool(s)")
    if finding.exposed_credentials:
        proof_bits.append(f"{len(finding.exposed_credentials)} exposed credential reference(s)")
    if finding.is_kev:
        proof_bits.append("CISA KEV")
    if finding.epss_score is not None:
        proof_bits.append(f"EPSS {finding.epss_score:.4f}")

    reachability = finding.reachability or "unknown"
    severity = str(finding.effective_severity() or finding.severity or "unknown")
    path_id_parts = [vuln_id, ecosystem, display_name, pkg_version or "unknown"]
    path: dict[str, Any] = {
        "id": "finding:" + ":".join(_slug(part) for part in path_id_parts),
        "rank": rank,
        "label": f"{display_name}@{pkg_version or '?'} -> {vuln_id}",
        "summary": finding.attack_vector_summary
        or finding.ai_risk_context
        or f"{vuln_id} affects {display_name}@{pkg_version or '?'} with {reachability} reachability.",
        "riskScore": round(float(finding.risk_score or 0.0), 2),
        "severity": severity,
        "source": source_ref,
        "target": target_ref,
        "hops": nodes,
        "relationships": relationships,
        "nodeIds": nodes,
        "edgeIds": [rel["id"] for rel in relationships],
        "findings": [vuln_id],
        "affectedAgents": list(finding.affected_agents[:10]),
        "affectedServers": list(finding.affected_servers[:10]),
        "reachableTools": list(finding.exposed_tools[:10]),
        "exposedCredentials": list(finding.exposed_credentials[:10]),
        "dependencyContext": {
            "package": display_name,
            "version": pkg_version,
            "ecosystem": ecosystem,
            "direct": finding.evidence.get("package_is_direct"),
            "dependencyDepth": finding.evidence.get("package_dependency_depth"),
            "reachabilityEvidence": finding.evidence.get("package_reachability_evidence"),
        },
        "fix": fix,
        "evidence": proof_bits,
        "provenance": {"source": provenance_source, "graphPersistence": False},
    }
    return {key: value for key, value in path.items() if value is not None}


def exposure_path_for_blast_radius(br: BlastRadius, *, rank: int | None = None) -> dict[str, Any]:
    """Return a bounded, report-safe ExposurePath view for a blast-radius item.

    Legacy adapter: projects through the unified Finding model so file-based
    formatters can converge on one canonical exposure-path builder.
    """
    from agent_bom.finding import blast_radius_to_finding

    path = exposure_path_for_finding(
        blast_radius_to_finding(br),
        rank=rank,
        provenance_source="blast_radius_output",
    )
    vuln = br.vulnerability
    package = br.package
    package_name_value = _display_package_name(package.name, package.version)
    path["id"] = "blast:" + ":".join(
        _slug(part) for part in [vuln.id, package.ecosystem, package_name_value, package.version or "unknown"]
    )
    return path


def _chain_token(hop: str) -> str:
    """Render a single hop ref (``server:database-server``) as a display token."""

    return hop.rsplit(":", 1)[-1] if ":" in hop else hop


def exposure_path_chain(path: dict[str, Any], *, include_tool: bool = True) -> str:
    """Render the primary trust spine of an ExposurePath as a one-line chain."""

    hops = [hop for hop in (path.get("hops") or []) if hop]
    if not hops:
        return ""

    def first(prefix: str) -> str | None:
        return next((hop for hop in hops if hop.startswith(prefix)), None)

    spine: list[str] = [hops[0]]
    for candidate in (first("server:"), first("pkg:"), path.get("target") or first("finding:")):
        if candidate and candidate not in spine:
            spine.append(candidate)
    if include_tool:
        tool = first("tool:")
        if tool and tool not in spine:
            spine.append(tool)
    return " → ".join(_chain_token(hop) for hop in spine)


def exposure_path_blast_summary(path: dict[str, Any]) -> str:
    """Render ``N cred(s), N tool(s) reachable`` for a single ExposurePath."""

    creds = len(path.get("exposedCredentials") or [])
    tools = len(path.get("reachableTools") or [])
    return f"{creds} cred(s), {tools} tool(s) reachable"


def exposure_path_brief_for_finding(finding: Finding, *, rank: int) -> dict[str, str]:
    """Return compact strings for Markdown/HTML investigation summaries."""

    path = exposure_path_for_finding(finding, rank=rank)
    proof = ", ".join(str(item) for item in path.get("evidence", [])) or "Package finding"
    severity = str(finding.effective_severity() or finding.severity or "unknown").upper()
    return {
        "rank": str(rank),
        "risk": f"{float(finding.risk_score or 0.0):.1f}",
        "severity": severity,
        "path": str(path["label"]),
        "why": str(path["summary"]),
        "proof": proof,
        "fix": str(path["fix"]),
    }


def exposure_path_brief(br: BlastRadius, *, rank: int) -> dict[str, str]:
    """Return compact strings for Markdown/HTML investigation summaries."""

    from agent_bom.finding import blast_radius_to_finding

    return exposure_path_brief_for_finding(blast_radius_to_finding(br), rank=rank)


def _agent_label(agent: Any) -> str:
    return str(getattr(agent, "name", "") or getattr(agent, "stable_id", "") or "unknown-agent")


def _server_label(server: Any) -> str:
    return str(getattr(server, "name", "") or getattr(server, "stable_id", "") or "unknown-server")


def _source_ref(br: BlastRadius) -> str:
    if br.affected_agents:
        return f"agent:{_agent_label(br.affected_agents[0])}"
    if br.affected_servers:
        return f"server:{_server_label(br.affected_servers[0])}"
    return f"pkg:{br.package.ecosystem}:{_display_package_name(br.package.name, br.package.version)}@{br.package.version or 'unknown'}"


def _source_ref_for_finding(
    finding: Finding,
    package_name_value: str,
    package_version_value: str,
    ecosystem: str,
) -> str:
    if finding.affected_agents:
        return f"agent:{finding.affected_agents[0]}"
    if finding.affected_servers:
        return f"server:{finding.affected_servers[0]}"
    return f"pkg:{ecosystem}:{package_name_value}@{package_version_value or 'unknown'}"


def _server_refs(br: BlastRadius) -> list[str]:
    return [f"server:{_server_label(server)}" for server in br.affected_servers]


def _server_refs_for_finding(finding: Finding) -> list[str]:
    return [f"server:{server}" for server in finding.affected_servers]


def _tool_refs(br: BlastRadius) -> list[str]:
    return [f"tool:{tool.name}" for tool in br.exposed_tools]


def _tool_refs_for_finding(finding: Finding) -> list[str]:
    return [f"tool:{tool}" for tool in finding.exposed_tools]


def _credential_refs(br: BlastRadius) -> list[str]:
    return [f"credential:{name}" for name in br.exposed_credentials]


def _credential_refs_for_finding(finding: Finding) -> list[str]:
    return [f"credential:{name}" for name in finding.exposed_credentials]


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


def _relationships_for_finding(
    finding: Finding,
    source_ref: str,
    package_ref: str,
    finding_ref: str,
    server_refs: list[str],
    tool_refs: list[str],
    credential_refs: list[str],
) -> list[dict[str, str]]:
    rels: list[dict[str, str]] = []

    def add(rel_type: str, source: str, target: str) -> None:
        rels.append({"id": f"{source}->{rel_type}->{target}", "type": rel_type, "source": source, "target": target})

    for server_ref in server_refs[:3]:
        add("uses", source_ref, server_ref)
        add("depends_on", server_ref, package_ref)
    if not finding.affected_servers:
        add("depends_on", source_ref, package_ref)
    add("vulnerable_to", package_ref, finding_ref)
    for tool_ref in tool_refs[:3]:
        add("provides_tool", source_ref, tool_ref)
    for credential_ref in credential_refs[:3]:
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
