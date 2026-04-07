"""Graph data builders for agent → server → package → CVE relationship visualization.

Produces Cytoscape.js-compatible element lists consumable by:
- The built-in HTML dashboard (``--format html``)
- Standalone graph JSON export (``--format graph``)
- External tools: Cytoscape desktop, Sigma.js, D3.js, Gephi (via conversion)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, TypedDict

from agent_bom.graph import SEVERITY_BADGE as _SEVERITY_BADGE
from agent_bom.graph import SEVERITY_RANK as _SEVERITY_RANK

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius


class _PackageVulnSummary(TypedDict):
    counts: dict[str, int]
    maxSeverity: str
    vulnCount: int
    summaryText: str
    vulnIds: list[str]


def _package_node_id(
    package_name: str,
    ecosystem: str,
    *,
    agent_name: str | None = None,
    server_name: str | None = None,
    scoped: bool = False,
) -> str:
    """Return a graph node id for a package.

    The collapsed HTML graph uses server-scoped package nodes to avoid the
    shared-package edge spaghetti that makes larger blast-radius graphs unreadable.
    """
    if scoped and agent_name and server_name:
        return f"pkg:{agent_name}:{server_name}:{package_name}:{ecosystem}"
    return f"pkg:{package_name}:{ecosystem}"


def _summarize_package_vulns(vulns: list[dict]) -> _PackageVulnSummary:
    """Aggregate vulnerability counts and labels for a package."""
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    max_severity = "unknown"
    max_rank = -1
    unique_ids: list[str] = []
    seen_ids: set[str] = set()

    for vuln in vulns:
        severity = str(vuln.get("severity") or "unknown")
        if severity not in counts:
            severity = "unknown"
        counts[severity] += 1
        rank = _SEVERITY_RANK[severity]
        if rank > max_rank:
            max_rank = rank
            max_severity = severity
        vuln_id = str(vuln.get("id") or "")
        if vuln_id and vuln_id not in seen_ids:
            seen_ids.add(vuln_id)
            unique_ids.append(vuln_id)

    badge_parts = []
    for severity in ("critical", "high", "medium", "low"):
        count = counts[severity]
        if count:
            badge_parts.append(f"{_SEVERITY_BADGE[severity]}{count}")
    if counts["unknown"]:
        badge_parts.append(f"?{counts['unknown']}")

    summary_text = " ".join(badge_parts) if badge_parts else "No CVEs"
    return {
        "counts": counts,
        "maxSeverity": max_severity,
        "vulnCount": len(unique_ids),
        "summaryText": summary_text,
        "vulnIds": unique_ids,
    }


def build_graph_elements(
    report: "AIBOMReport",
    blast_radii: list["BlastRadius"],
    include_cve_nodes: bool = True,
    *,
    collapse_cves: bool = False,
) -> list[dict]:
    """Build a Cytoscape.js-compatible element list with provider, agent, server, package, and CVE nodes.

    Node types:
      - ``provider``    — cloud source grouping (AWS, Azure, Databricks, local, etc.)
      - ``agent``       — AI agent
      - ``server_vuln`` — MCP server with vulnerable packages
      - ``server_cred`` — MCP server with exposed credentials
      - ``server_clean``— MCP server, no issues
      - ``pkg_vuln``    — vulnerable package summary
      - ``cve``         — individual CVE/advisory

    Edge types (in ``data.type``):
      - ``hosts``       — provider → agent
      - ``uses``        — agent → server
      - ``depends_on``  — server → package
      - ``affects``     — package → CVE
    """
    elements: list[dict] = []
    vuln_pkg_keys: set[tuple[str, str]] = {(br.package.name, br.package.ecosystem) for br in blast_radii}

    # Track which provider nodes we've already created
    providers_seen: set[str] = set()

    cve_nodes_seen: set[str] = set()

    # Build a lookup: (pkg_name, ecosystem) → list of vulnerability IDs
    pkg_to_vulns: dict[tuple[str, str], list[dict]] = {}
    for br in blast_radii:
        key = (br.package.name, br.package.ecosystem)
        if key not in pkg_to_vulns:
            pkg_to_vulns[key] = []
        pkg_to_vulns[key].append(
            {
                "id": br.vulnerability.id,
                "severity": br.vulnerability.severity.value,
                "summary": br.vulnerability.summary[:100] if br.vulnerability.summary else "",
                "risk_score": br.risk_score,
                "cvss_score": br.vulnerability.cvss_score or 0,
                "fix_version": br.vulnerability.fixed_version or "",
                "owasp_tags": list(br.owasp_tags),
                "atlas_tags": list(br.atlas_tags),
                "attack_tags": list(getattr(br, "attack_tags", [])),
                "nist_ai_rmf_tags": list(br.nist_ai_rmf_tags),
                "owasp_mcp_tags": list(br.owasp_mcp_tags),
                "owasp_agentic_tags": list(br.owasp_agentic_tags),
                "eu_ai_act_tags": list(br.eu_ai_act_tags),
            }
        )

    for agent in report.agents:
        # ── Provider node ─────────────────────────────────────────────
        source = agent.source or "local"
        if source not in providers_seen:
            providers_seen.add(source)
            elements.append(
                {
                    "data": {
                        "id": f"provider:{source}",
                        "label": _provider_label(source),
                        "type": "provider",
                        "tip": f"Source: {source}",
                    }
                }
            )

        # ── Agent node ────────────────────────────────────────────────
        aid = f"a:{agent.name}"
        elements.append(
            {
                "data": {
                    "id": aid,
                    "label": agent.name,
                    "type": "agent",
                    "tip": (f"Agent: {agent.name}\nType: {agent.agent_type.value}\nSource: {source}\nServers: {len(agent.mcp_servers)}"),
                    "agentType": agent.agent_type.value,
                    "configPath": agent.config_path or "",
                    "source": source,
                    "serverCount": len(agent.mcp_servers),
                    "packageCount": agent.total_packages,
                    "vulnCount": agent.total_vulnerabilities,
                }
            }
        )
        # Edge: provider → agent
        elements.append(
            {
                "data": {
                    "source": f"provider:{source}",
                    "target": aid,
                    "type": "hosts",
                }
            }
        )

        # ── Server nodes ──────────────────────────────────────────────
        for srv in agent.mcp_servers:
            sid = f"s:{agent.name}:{srv.name}"
            vuln_count = sum(1 for p in srv.packages if (p.name, p.ecosystem) in vuln_pkg_keys)
            has_vuln = vuln_count > 0
            has_cred = srv.has_credentials
            stype = "server_vuln" if has_vuln else ("server_cred" if has_cred else "server_clean")

            vulnerable_pkg_count = sum(1 for p in srv.packages if (p.name, p.ecosystem) in vuln_pkg_keys)
            total_pkg_vulns = 0
            critical_pkg_vulns = 0
            for pkg in srv.packages:
                summary = _summarize_package_vulns(pkg_to_vulns.get((pkg.name, pkg.ecosystem), []))
                total_pkg_vulns += int(summary["vulnCount"])
                critical_pkg_vulns += int(summary["counts"]["critical"])  # type: ignore[index]

            pkg_note = f"\nPackages: {len(srv.packages)}"
            if vuln_count:
                pkg_note += f"\nVulnerable packages: {vulnerable_pkg_count}"
                pkg_note += f"\nTotal CVEs: {total_pkg_vulns}"
                if critical_pkg_vulns:
                    pkg_note += f"\nCritical CVEs: {critical_pkg_vulns}"
            cinfo = f"\nCredentials: {', '.join(srv.credential_names)}" if has_cred else ""
            pkg_badge = f"{len(srv.packages)} pkg"
            if total_pkg_vulns:
                pkg_badge += f" • {total_pkg_vulns} CVEs"
            server_label = f"{srv.name}\n{pkg_badge}"
            if has_cred:
                server_label = "KEY " + server_label
            elif has_vuln:
                server_label = "RISK " + server_label

            elements.append(
                {
                    "data": {
                        "id": sid,
                        "label": server_label,
                        "type": stype,
                        "tip": f"MCP Server: {srv.name}{pkg_note}{cinfo}",
                        "command": ((srv.command or "") + " " + " ".join((srv.args or [])[:3]))[:80].strip(),
                        "packageCount": len(srv.packages),
                        "vulnPackageCount": vulnerable_pkg_count,
                        "vulnCount": total_pkg_vulns,
                        "criticalCount": critical_pkg_vulns,
                        "hasCredentials": has_cred,
                        "credentials": json.dumps(srv.credential_names) if srv.credential_names else "[]",
                        "toolNames": json.dumps([t.name for t in srv.tools[:10]]) if srv.tools else "[]",
                    }
                }
            )
            # Edge: agent → server
            elements.append(
                {
                    "data": {
                        "source": aid,
                        "target": sid,
                        "type": "uses",
                        "credentialEdge": 1 if has_cred else 0,
                    }
                }
            )

            # ── Package nodes (vulnerable only) ───────────────────────
            seen_pkg_ids: set[str] = set()
            for pkg in srv.packages:
                pkg_key = (pkg.name, pkg.ecosystem)
                if pkg_key not in vuln_pkg_keys:
                    continue

                pid = _package_node_id(
                    pkg.name,
                    pkg.ecosystem,
                    agent_name=agent.name,
                    server_name=srv.name,
                    scoped=collapse_cves,
                )
                if pid in seen_pkg_ids:
                    # Just add another edge for shared package
                    elements.append(
                        {
                            "data": {
                                "source": sid,
                                "target": pid,
                                "type": "depends_on",
                            }
                        }
                    )
                    continue
                seen_pkg_ids.add(pid)

                package_vulns = pkg_to_vulns.get(pkg_key, [])
                vuln_summary = _summarize_package_vulns(package_vulns)
                vc = int(vuln_summary["vulnCount"])
                vuln_ids = list(vuln_summary["vulnIds"])
                max_severity = str(vuln_summary["maxSeverity"])
                summary_label = f"{pkg.name}\n{pkg.version}"
                if collapse_cves and vc:
                    summary_label = f"{pkg.name}@{pkg.version}\n{vuln_summary['summaryText']} • {vc} CVEs"
                elements.append(
                    {
                        "data": {
                            "id": pid,
                            "label": summary_label,
                            "type": "pkg_vuln",
                            "tip": (
                                f"Package: {pkg.name}\n"
                                f"Version: {pkg.version}\n"
                                f"Ecosystem: {pkg.ecosystem}\n"
                                f"Vulnerabilities: {vc if vc else '(via blast radius)'}\n"
                                f"Highest severity: {max_severity}"
                            ),
                            "ecosystem": pkg.ecosystem,
                            "version": pkg.version,
                            "vulnIds": json.dumps(vuln_ids),
                            "vulnCount": vc,
                            "maxSeverity": max_severity,
                            "criticalCount": vuln_summary["counts"]["critical"],
                            "highCount": vuln_summary["counts"]["high"],
                            "mediumCount": vuln_summary["counts"]["medium"],
                            "lowCount": vuln_summary["counts"]["low"],
                            "unknownCount": vuln_summary["counts"]["unknown"],
                            "collapsedCves": collapse_cves,
                            "cveList": json.dumps(package_vulns),
                            "searchText": " ".join([pkg.name, pkg.version, pkg.ecosystem, *vuln_ids]).lower(),
                        }
                    }
                )
                # Edge: server → package
                elements.append(
                    {
                        "data": {
                            "source": sid,
                            "target": pid,
                            "type": "depends_on",
                            "maxSeverity": max_severity,
                            "vulnCount": vc,
                        }
                    }
                )

                # ── CVE nodes ─────────────────────────────────────────
                if include_cve_nodes and not collapse_cves and pkg_key in pkg_to_vulns:
                    for vuln_info in package_vulns:
                        cve_id = f"cve:{vuln_info['id']}"
                        if cve_id not in cve_nodes_seen:
                            cve_nodes_seen.add(cve_id)
                            sev = vuln_info["severity"]
                            severity_weight = _SEVERITY_RANK.get(sev, 1)
                            elements.append(
                                {
                                    "data": {
                                        "id": cve_id,
                                        "label": f"{vuln_info['id']}\n{sev.upper()}",
                                        "type": f"cve_{sev}",
                                        "tip": (f"{vuln_info['id']}\nSeverity: {sev}\n{vuln_info['summary']}"),
                                        "severity": sev,
                                        "severityWeight": severity_weight,
                                        "cvssScore": vuln_info.get("cvss_score", 0),
                                        "summary": vuln_info.get("summary", ""),
                                        "fixVersion": vuln_info.get("fix_version", ""),
                                        "owaspTags": vuln_info.get("owasp_tags", []),
                                        "atlasTags": vuln_info.get("atlas_tags", []),
                                        "nistAiRmfTags": vuln_info.get("nist_ai_rmf_tags", []),
                                        "owaspMcpTags": vuln_info.get("owasp_mcp_tags", []),
                                        "owaspAgenticTags": vuln_info.get("owasp_agentic_tags", []),
                                        "euAiActTags": vuln_info.get("eu_ai_act_tags", []),
                                    }
                                }
                            )
                        # Edge: package → CVE
                        elements.append(
                            {
                                "data": {
                                    "source": pid,
                                    "target": cve_id,
                                    "type": "affects",
                                }
                            }
                        )

    return elements


def _provider_label(source: str) -> str:
    """Human-readable label for a provider source string."""
    labels = {
        "local": "Local",
        "aws-bedrock": "AWS Bedrock",
        "aws-ecs": "AWS ECS",
        "aws-sagemaker": "AWS SageMaker",
        "azure-container-apps": "Azure Container Apps",
        "azure-ai-foundry": "Azure AI Foundry",
        "gcp-vertex-ai": "GCP Vertex AI",
        "gcp-cloud-run": "GCP Cloud Run",
        "databricks": "Databricks",
        "snowflake-cortex": "Snowflake Cortex",
        "snowflake-streamlit": "Snowflake Streamlit",
        "snowflake": "Snowflake",
        "mcp-registry": "MCP Registry",
        "smithery": "Smithery",
        "snyk": "Snyk",
        "huggingface": "Hugging Face",
        "openai": "OpenAI",
        "mlflow": "MLflow",
        "wandb": "W&B",
        "nebius": "Nebius",
    }
    return labels.get(source, source.upper())


def build_attack_flow_elements(
    blast_radii: list["BlastRadius"],
) -> list[dict]:
    """Build a CVE-centric attack flow graph showing how vulns compromise assets.

    Flow direction (left-to-right):
      CVE → Package → MCP Server → Credentials / Tools / Agents

    This is the *reverse* of the supply chain graph — it shows blast radius
    propagation from vulnerability to impacted assets.

    Node types:
      - ``cve_*``      — CVE/advisory (severity-colored diamond)
      - ``pkg_vuln``   — vulnerable package
      - ``server``     — MCP server affected
      - ``credential`` — exposed credential (key icon)
      - ``tool``       — reachable MCP tool
      - ``agent``      — affected agent

    Edge types:
      - ``exploits``   — CVE → package
      - ``runs_on``    — package → server
      - ``exposes``    — server → credential
      - ``reaches``    — server → tool
      - ``compromises``— server → agent
    """
    if not blast_radii:
        return []

    elements: list[dict] = []
    seen_nodes: set[str] = set()

    def _add_node(node_id: str, **data: object) -> None:
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            elements.append({"data": {"id": node_id, **data}})

    seen_edges: set[tuple[str, str, str]] = set()

    def _add_edge(source: str, target: str, edge_type: str) -> None:
        key = (source, target, edge_type)
        if key not in seen_edges:
            seen_edges.add(key)
            elements.append({"data": {"source": source, "target": target, "type": edge_type}})

    for br in blast_radii:
        v = br.vulnerability
        sev = v.severity.value

        # CVE node
        cve_id = f"cve:{v.id}"
        score_text = f"\nCVSS: {v.cvss_score:.1f}" if v.cvss_score else ""
        fix_text = f"\nFix: {v.fixed_version}" if v.fixed_version else "\nNo fix available"
        _add_node(
            cve_id, label=v.id, type=f"cve_{sev}", tip=f"{v.id}\nSeverity: {sev}{score_text}\nBlast score: {br.risk_score:.1f}{fix_text}"
        )

        # Package node
        pkg_id = f"pkg:{br.package.name}"
        _add_node(
            pkg_id,
            label=f"{br.package.name}\n@{br.package.version}",
            type="pkg_vuln",
            tip=f"Package: {br.package.name}\nVersion: {br.package.version}\nEcosystem: {br.package.ecosystem}",
        )
        _add_edge(cve_id, pkg_id, "exploits")

        # Servers that use this package
        for agent in br.affected_agents:
            for srv in agent.mcp_servers:
                pkg_match = any(p.name == br.package.name and p.ecosystem == br.package.ecosystem for p in srv.packages)
                if not pkg_match:
                    continue

                srv_id = f"srv:{agent.name}:{srv.name}"
                _add_node(
                    srv_id, label=srv.name, type="server", tip=f"MCP Server: {srv.name}\nAgent: {agent.name}\nPackages: {len(srv.packages)}"
                )
                _add_edge(pkg_id, srv_id, "runs_on")

                # Exposed credentials
                for cred in srv.credential_names:
                    cred_id = f"cred:{cred}"
                    _add_node(cred_id, label=cred, type="credential", tip=f"Credential: {cred}\nExposed via: {srv.name}")
                    _add_edge(srv_id, cred_id, "exposes")

                # Reachable tools (from introspection data if available)
                tools = getattr(srv, "tool_names", []) or []
                for tool_name in tools[:8]:  # cap at 8 to avoid graph explosion
                    tool_id = f"tool:{srv.name}:{tool_name}"
                    _add_node(tool_id, label=tool_name, type="tool", tip=f"MCP Tool: {tool_name}\nServer: {srv.name}")
                    _add_edge(srv_id, tool_id, "reaches")

                # Affected agent
                agent_id = f"agent:{agent.name}"
                _add_node(agent_id, label=agent.name, type="agent", tip=f"Agent: {agent.name}\nType: {agent.agent_type.value}")
                _add_edge(srv_id, agent_id, "compromises")

    return elements


def _graph_priority_summary(blast_radii: list["BlastRadius"], *, collapse_cves: bool = False) -> list[dict]:
    """Summarize the highest-value blast-radius paths for the HTML graph.

    The standalone graph needs an operator-facing starting point, not just raw
    nodes. These summaries drive the top-risk sidebar and focus behavior.
    """
    priorities: list[dict] = []
    for br in sorted(blast_radii, key=lambda item: item.risk_score, reverse=True)[:8]:
        node_id = f"cve:{br.vulnerability.id}"
        if collapse_cves and br.affected_agents and br.affected_servers:
            node_id = _package_node_id(
                br.package.name,
                br.package.ecosystem,
                agent_name=br.affected_agents[0].name,
                server_name=br.affected_servers[0].name,
                scoped=True,
            )
        priorities.append(
            {
                "nodeId": node_id,
                "vulnerabilityId": br.vulnerability.id,
                "packageName": br.package.name,
                "packageVersion": br.package.version,
                "packageEcosystem": br.package.ecosystem,
                "severity": br.vulnerability.severity.value,
                "riskScore": round(br.risk_score, 1),
                "agentCount": len(br.affected_agents),
                "serverCount": len(br.affected_servers),
                "credentialCount": len(br.exposed_credentials),
                "toolCount": len(br.exposed_tools),
                "fixVersion": br.vulnerability.fixed_version or "",
                "reachability": br.reachability,
                "summary": br.vulnerability.summary or "",
                "agents": [agent.name for agent in br.affected_agents[:6]],
                "servers": [server.name for server in br.affected_servers[:6]],
                "credentials": list(br.exposed_credentials)[:8],
                "tools": [tool.name for tool in br.exposed_tools[:10]],
                "owaspTags": list(br.owasp_tags),
                "atlasTags": list(br.atlas_tags),
                "owaspMcpTags": list(br.owasp_mcp_tags),
                "owaspAgenticTags": list(br.owasp_agentic_tags),
            }
        )
    return priorities


def _graph_overview(blast_radii: list["BlastRadius"]) -> dict[str, int]:
    """Aggregate the key counts operators need before drilling into a path."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    exposed_credentials: set[str] = set()
    exposed_tools: set[str] = set()
    affected_servers: set[str] = set()
    affected_agents: set[str] = set()

    for br in blast_radii:
        severity = br.vulnerability.severity.value
        if severity in counts:
            counts[severity] += 1
        exposed_credentials.update(br.exposed_credentials)
        exposed_tools.update(tool.name for tool in br.exposed_tools)
        affected_servers.update(server.name for server in br.affected_servers)
        affected_agents.update(agent.name for agent in br.affected_agents)

    return {
        **counts,
        "credentialCount": len(exposed_credentials),
        "toolCount": len(exposed_tools),
        "affectedServerCount": len(affected_servers),
        "affectedAgentCount": len(affected_agents),
    }


def export_graph_html(
    report: "AIBOMReport",
    blast_radii: list["BlastRadius"],
    output_path: str,
) -> None:
    """Export an interactive standalone HTML file with Cytoscape.js supply chain graph.

    Self-contained: loads Cytoscape + dagre from CDN, embeds data inline.
    Supports zoom, pan, click-to-inspect, legend, and PNG export.
    """
    from pathlib import Path

    elements = build_graph_elements(report, blast_radii, include_cve_nodes=False, collapse_cves=True)
    elements_json = json.dumps(elements, indent=2)

    total_agents = len(report.agents)
    total_servers = sum(len(a.mcp_servers) for a in report.agents)
    total_pkgs = sum(a.total_packages for a in report.agents)
    total_vulns = len(blast_radii)
    top_risks_json = json.dumps(_graph_priority_summary(blast_radii, collapse_cves=True), indent=2)
    overview_json = json.dumps(_graph_overview(blast_radii), indent=2)

    html_content = _GRAPH_HTML_TEMPLATE.format(
        elements_json=elements_json,
        top_risks_json=top_risks_json,
        overview_json=overview_json,
        total_agents=total_agents,
        total_servers=total_servers,
        total_pkgs=total_pkgs,
        total_vulns=total_vulns,
    )
    Path(output_path).write_text(html_content, encoding="utf-8")


_GRAPH_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-bom Supply Chain Graph</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; background: #0f1419; color: #e7e9ea; }}
  #header {{ padding: 16px 24px; display: flex; align-items: flex-start; justify-content: space-between;
    border-bottom: 1px solid #2f3336; gap: 16px; }}
  #header h1 {{ font-size: 20px; font-weight: 700; }}
  #header p {{ font-size: 13px; color: #9ba1a6; margin-top: 6px; max-width: 780px; }}
  #stats {{ font-size: 13px; color: #71767b; white-space: nowrap; padding-top: 4px; }}
  #stats span {{ margin: 0 8px; }}
  #cy {{ width: 100%; height: calc(100vh - 176px); }}
  #toolbar {{ padding: 10px 24px; display: flex; align-items: center; justify-content: space-between;
    gap: 16px; border-bottom: 1px solid #2f3336; background: #10151b; }}
  #toolbar .left, #toolbar .right {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .chip {{ border: 1px solid #2f3336; background: #151b22; color: #e7e9ea; font-size: 12px; font-weight: 600;
    border-radius: 999px; padding: 7px 10px; cursor: pointer; }}
  .chip:hover {{ background: #1b2330; }}
  .chip.active {{ border-color: #4a9eff; background: #15202b; color: #d9ecff; }}
  .chip.count {{ cursor: default; }}
  .chip.critical {{ border-color: #b42318; color: #ffb4ae; }}
  .chip.high {{ border-color: #c56b1f; color: #ffd1a5; }}
  .chip.medium {{ border-color: #9d7d13; color: #ffe28a; }}
  .chip.low {{ border-color: #6e7681; color: #c6ccd3; }}
  #search {{
    width: 230px; max-width: 100%; border: 1px solid #2f3336; background: #0f1419; color: #e7e9ea;
    border-radius: 10px; padding: 8px 12px; font-size: 12px;
  }}
  .panel {{ position: fixed; z-index: 10; background: rgba(26, 31, 37, 0.96); border: 1px solid #2f3336;
    border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,.28); backdrop-filter: blur(10px); }}
  #riskpanel {{ top: 138px; left: 16px; width: 360px; max-height: calc(100vh - 270px); overflow: auto; }}
  #riskpanel h2, #detail h2 {{ font-size: 14px; font-weight: 700; margin-bottom: 10px; }}
  #riskpanel .inner, #detail .inner {{ padding: 14px; }}
  #riskpanel .hint {{ font-size: 12px; color: #9ba1a6; line-height: 1.45; margin-bottom: 10px; }}
  .risk-item {{ width: 100%; display: block; text-align: left; border: 1px solid #2f3336; background: #11161c;
    color: #e7e9ea; border-radius: 10px; padding: 12px; margin-bottom: 10px; cursor: pointer; }}
  .risk-item:hover, .risk-item.active {{ border-color: #4a9eff; background: #15202b; }}
  .risk-head {{ display: flex; justify-content: space-between; gap: 10px; align-items: baseline; margin-bottom: 6px; }}
  .risk-title {{ font-size: 12px; font-weight: 700; line-height: 1.35; }}
  .risk-score {{ font-size: 12px; font-weight: 700; color: #ffd33d; }}
  .risk-meta {{ font-size: 11px; color: #9ba1a6; line-height: 1.45; }}
  .risk-summary {{ font-size: 12px; line-height: 1.45; color: #c6ccd3; margin-top: 8px; }}
  .pill {{ display: inline-block; font-size: 10px; padding: 2px 6px; border-radius: 999px;
    background: #2f3336; color: #e7e9ea; margin-right: 6px; }}
  .pill.critical {{ background: #5b1f24; color: #ffb3b8; }}
  .pill.high {{ background: #5b341f; color: #ffd1a5; }}
  .pill.medium {{ background: #4b3d18; color: #ffe28a; }}
  .pill.low {{ background: #30363d; color: #e7e9ea; }}
  #legend {{ bottom: 16px; left: 16px; padding: 12px; font-size: 11px; width: 220px; }}
  #legend div {{ display: flex; align-items: center; gap: 6px; margin: 4px 0; }}
  .dot {{ width: 12px; height: 12px; border-radius: 3px; display: inline-block; }}
  #detail {{ top: 138px; right: 16px; width: 360px; max-height: calc(100vh - 270px); overflow: auto; display: none; }}
  #detail .subtle {{ color: #9ba1a6; font-size: 12px; line-height: 1.45; margin-bottom: 12px; }}
  #detail .section {{ margin-top: 12px; }}
  #detail .section h3 {{ font-size: 12px; font-weight: 700; margin-bottom: 8px; color: #d9ecff;
    text-transform: uppercase; letter-spacing: .04em; }}
  #detail ul {{ padding-left: 18px; color: #c6ccd3; font-size: 12px; line-height: 1.5; }}
  #detail code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #11161c; padding: 1px 4px; border-radius: 4px; }}
  #controls {{ position: fixed; bottom: 16px; right: 16px; z-index: 10; display: flex; gap: 8px; }}
  #controls button {{ padding: 8px 12px; border: 1px solid #2f3336; background: rgba(26, 31, 37, 0.96);
    color: #e7e9ea; border-radius: 8px; cursor: pointer; font-size: 12px; }}
  #controls button:hover {{ background: #2f3336; }}
</style>
</head>
<body>
<div id="header">
  <div>
    <h1>agent-bom Supply Chain Graph</h1>
    <p>Open on the highest-risk blast-radius path first, then inspect the full
    agent → server → package → vulnerability chain. Click a risk card or node to
    focus the relevant path.</p>
  </div>
  <div id="stats">
    <span>{total_agents} agents</span> | <span>{total_servers} servers</span> |
    <span>{total_pkgs} packages</span> | <span>{total_vulns} CVEs</span>
  </div>
</div>
<div id="toolbar">
  <div class="left">
    <button class="chip active" id="sev-all" onclick="setSeverityFilter('all')">All severities</button>
    <button class="chip critical" id="sev-critical" onclick="setSeverityFilter('critical')">Critical</button>
    <button class="chip high" id="sev-high" onclick="setSeverityFilter('high')">High</button>
    <button class="chip medium" id="sev-medium" onclick="setSeverityFilter('medium')">Medium</button>
    <button class="chip low" id="sev-low" onclick="setSeverityFilter('low')">Low</button>
    <button class="chip" id="chip-credentials" onclick="toggleCredentialFilter()">Credential exposure</button>
    <button class="chip" id="chip-focus" onclick="toggleFocusedOnly()">Focused path only</button>
  </div>
  <div class="right">
    <span class="chip count critical" id="count-critical"></span>
    <span class="chip count high" id="count-high"></span>
    <span class="chip count" id="count-credentials"></span>
    <span class="chip count" id="count-agents"></span>
    <input id="search" type="search" placeholder="Search CVE, package, server, agent" oninput="searchNodes(this.value)">
  </div>
</div>
<div id="cy"></div>
<div id="riskpanel" class="panel">
  <div class="inner">
    <h2>Top risky paths</h2>
    <div class="hint">Start here. These are the blast-radius paths with the highest risk score in this report.</div>
    <div id="riskList"></div>
  </div>
</div>
<div id="legend" class="panel">
  <div><span class="dot" style="background:#4a9eff"></span> Provider</div>
  <div><span class="dot" style="background:#2ea043"></span> Agent</div>
  <div><span class="dot" style="background:#6e7681"></span> Server (clean)</div>
  <div><span class="dot" style="background:#f85149"></span> Server (vulnerable)</div>
  <div><span class="dot" style="background:#d29922"></span> Server (credentials)</div>
  <div><span class="dot" style="background:#da3633"></span> CVE critical</div>
  <div><span class="dot" style="background:#db6d28"></span> CVE high</div>
  <div><span class="dot" style="background:#d29922"></span> CVE medium</div>
</div>
<div id="detail" class="panel">
  <div class="inner">
    <h2 id="dt"></h2>
    <div id="db"></div>
  </div>
</div>
<div id="controls">
  <button onclick="focusTopRisk()">Top risk</button>
  <button onclick="fitAll()">Fit all</button>
  <button onclick="cy.zoom(cy.zoom()*1.2);cy.center()">+</button>
  <button onclick="cy.zoom(cy.zoom()/1.2);cy.center()">-</button>
  <button onclick="dlPng()">PNG</button>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/dagre@0.8.5/dist/dagre.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.js"></script>
<script>
const els={elements_json};
const topRisks={top_risks_json};
const overview={overview_json};
let activeRiskNodeId=null;
let focusedPathOnly=true;
let credentialsOnly=false;
let activeSeverity='all';
const expandedPackages = new Map();
cytoscape.use(cytoscapeDagre);
const cy=cytoscape({{
  container:document.getElementById('cy'),elements:els,
  layout:{{name:'dagre',rankDir:'LR',align:'DL',nodeSep:90,edgeSep:20,rankSep:240,padding:56,ranker:'network-simplex',acyclicer:'greedy'}},
  style:[
    {{selector:'node',style:{{'label':'data(label)','text-wrap':'wrap','text-max-width':180,
      'font-size':14,'font-weight':700,'min-zoomed-font-size':6,'text-valign':'center','color':'#e7e9ea','width':160,'height':46,
      'shape':'roundrectangle','background-color':'#2f3336','border-width':1.2,'border-color':'#444',
      'text-outline-width':2,'text-outline-color':'#0f1419'}}}},
    {{selector:'node[type="provider"]',style:{{'background-color':'#1a3a5c','border-color':'#4a9eff','width':132,'height':38,'font-size':11}}}},
    {{selector:'node[type="agent"]',style:{{'background-color':'#1a3520','border-color':'#2ea043','shape':'barrel','width':200,'height':56}}}},
    {{selector:'node[type="server_clean"]',style:{{
      'background-color':'#21262d','border-color':'#6e7681','border-width':3,
      'width':'mapData(packageCount, 1, 12, 190, 250)','height':56,'opacity':0.78
    }}}},
    {{selector:'node[type="server_vuln"]',style:{{
      'background-color':'#451f24','border-color':'#ff5d5d','border-width':3,
      'width':'mapData(vulnCount, 1, 40, 200, 300)','height':56
    }}}},
    {{selector:'node[type="server_cred"]',style:{{
      'background-color':'#4c3411','border-color':'#f2b84b','border-width':3,
      'width':'mapData(vulnCount, 0, 40, 200, 300)','height':56
    }}}},
    {{selector:'node[type="pkg_vuln"]',style:{{
      'background-color':'#3b1a1a','border-color':'#da3633',
      'width':'mapData(vulnCount, 1, 15, 180, 280)','height':58,'text-max-width':220
    }}}},
    {{selector:'node[type^="cve_critical"]',style:{{'background-color':'#ff3b30','color':'#fff',
      'shape':'diamond','width':160,'height':70}}}},
    {{selector:'node[type^="cve_high"]',style:{{'background-color':'#ff8a24','color':'#fff',
      'shape':'diamond','width':140,'height':60}}}},
    {{selector:'node[type^="cve_medium"]',style:{{'background-color':'#ffd33d','color':'#000',
      'shape':'diamond','width':120,'height':52}}}},
    {{selector:'node[type^="cve_low"]',style:{{'background-color':'#6e7681','color':'#fff',
      'shape':'diamond','width':100,'height':44}}}},
    {{selector:'node[type^="cve_unknown"]',style:{{'background-color':'#4b5563','color':'#d1d5db',
      'shape':'roundrectangle','width':90,'height':40,'opacity':0.66}}}},
    {{selector:'edge',style:{{'width':1.5,'line-color':'#444','target-arrow-color':'#444',
      'target-arrow-shape':'triangle','curve-style':'bezier','arrow-scale':0.8,'opacity':0.7}}}},
    {{selector:'edge[type="hosts"]',style:{{'line-color':'#4a9eff','target-arrow-color':'#4a9eff','width':2}}}},
    {{selector:'edge[type="uses"]',style:{{'line-color':'#2ea043','target-arrow-color':'#2ea043','width':2}}}},
    {{selector:'edge[type="uses"][credentialEdge = 1]',style:{{'line-color':'#f2b84b','target-arrow-color':'#f2b84b','width':3}}}},
    {{selector:'edge[type="depends_on"]',style:{{'line-color':'#8b949e','target-arrow-color':'#8b949e','width':1.5}}}},
    {{selector:'edge[type="depends_on"][maxSeverity = "critical"]',style:{{
      'line-color':'#ff5d5d','target-arrow-color':'#ff5d5d','width':2.5
    }}}},
    {{selector:'edge[type="depends_on"][maxSeverity = "high"]',style:{{'line-color':'#ff8a24','target-arrow-color':'#ff8a24','width':2}}}},
    {{selector:'edge[type="affects"]',style:{{'line-style':'dashed','line-color':'#ff5d5d','target-arrow-color':'#ff5d5d','width':1.8}}}},
    {{selector:'.faded',style:{{'opacity':0.08}}}},
    {{selector:'.focus',style:{{'opacity':1,'border-width':4,'border-color':'#58a6ff','z-index':9999}}}},
    {{selector:'edge.focus',style:{{'opacity':1,'line-color':'#58a6ff','target-arrow-color':'#58a6ff','width':2.4}}}},
    {{selector:'.filtered',style:{{'display':'none'}}}},
  ],wheelSensitivity:0.3
}});

const riskByNodeId = new Map(topRisks.map((risk)=>[risk.nodeId, risk]));

function runGraphLayout(){{
  cy.layout({{
    name:'dagre',
    rankDir:'LR',
    align:'DL',
    nodeSep:90,
    edgeSep:20,
    rankSep:240,
    padding:56,
    ranker:'network-simplex',
    acyclicer:'greedy',
    animate:false,
    fit:false,
  }}).run();
}}

function severityClass(sev){{
  if(sev === 'critical' || sev === 'high' || sev === 'medium' || sev === 'low') return sev;
  return '';
}}

function escapeHtml(value){{
  return String(value || '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}}

function listHtml(items){{
  if(!items || !items.length) return '<div class="subtle">None in this path.</div>';
  return `<ul>${{items.map((item)=>`<li><code>${{escapeHtml(item)}}</code></li>`).join('')}}</ul>`;
}}

function recommendationHtml(risk){{
  const steps = [];
  if(risk.fixVersion) {{
    steps.push(`Upgrade <code>${{escapeHtml(risk.packageName)}}</code> to <code>${{escapeHtml(risk.fixVersion)}}</code>.`);
  }} else {{
    steps.push('No fixed version is advertised yet; isolate or contain the affected server path first.');
  }}
  if(risk.credentialCount) {{
    steps.push('Rotate or scope down exposed credentials on affected servers before wider rollout.');
  }}
  if(risk.toolCount) {{
    steps.push('Review reachable MCP tools to reduce post-exploitation blast radius.');
  }}
  if(risk.reachability && risk.reachability !== 'unknown') {{
    steps.push(`Reachability is reported as <code>${{escapeHtml(risk.reachability)}}</code>; prioritize live paths first.`);
  }}
  return `<ul>${{steps.map((item)=>`<li>${{item}}</li>`).join('')}}</ul>`;
}}

function setDetail(title, bodyHtml){{
  document.getElementById('detail').style.display='block';
  document.getElementById('dt').textContent=title;
  document.getElementById('db').innerHTML=bodyHtml;
}}

function setRiskDetail(risk){{
  const tags = [
    ...(risk.owaspTags || []),
    ...(risk.atlasTags || []),
    ...(risk.owaspMcpTags || []),
    ...(risk.owaspAgenticTags || []),
  ].slice(0, 8);
  const tagHtml = tags.length
    ? `<div class="section"><h3>Mapped controls</h3><div>${{
        tags.map((tag)=>`<span class="pill">${{escapeHtml(tag)}}</span>`).join('')
      }}</div></div>`
    : '';
  setDetail(
    risk.vulnerabilityId,
    `
      <div class="subtle">${{escapeHtml(risk.summary || 'No summary was available for this vulnerability.')}}</div>
      <div><span class="pill ${{severityClass(risk.severity)}}">${{escapeHtml(risk.severity.toUpperCase())}}</span>
        <span class="pill">risk ${{escapeHtml(risk.riskScore)}}</span>
        <span class="pill">${{escapeHtml(risk.reachability)}}</span></div>
      <div class="section"><h3>Package</h3>
        <div><code>${{escapeHtml(risk.packageName)}}</code> @
          <code>${{escapeHtml(risk.packageVersion)}}</code>
          (${{escapeHtml(risk.packageEcosystem)}})</div>
        <div class="subtle">${{
          risk.fixVersion
            ? `Recommended fix: <code>${{escapeHtml(risk.fixVersion)}}</code>`
            : 'No fixed version reported yet.'
        }}</div>
      </div>
      <div class="section"><h3>Impact</h3>
        <ul>
          <li>${{escapeHtml(risk.agentCount)}} agent(s) affected</li>
          <li>${{escapeHtml(risk.serverCount)}} server(s) affected</li>
          <li>${{escapeHtml(risk.credentialCount)}} credential(s) exposed</li>
          <li>${{escapeHtml(risk.toolCount)}} tool(s) reachable</li>
        </ul>
      </div>
      <div class="section"><h3>Affected agents</h3>${{listHtml(risk.agents)}}</div>
      <div class="section"><h3>Affected servers</h3>${{listHtml(risk.servers)}}</div>
      <div class="section"><h3>Credentials</h3>${{listHtml(risk.credentials)}}</div>
      <div class="section"><h3>Reachable tools</h3>${{listHtml(risk.tools)}}</div>
      ${{tagHtml}}
      <div class="section"><h3>Operator actions</h3>${{recommendationHtml(risk)}}</div>
    `,
  );
}}

function clearFocus(){{
  cy.elements().removeClass('focus faded');
  document.querySelectorAll('.risk-item').forEach((el)=>el.classList.remove('active'));
  activeRiskNodeId=null;
}}

function updateOverview(){{
  document.getElementById('count-critical').textContent=`${{overview.critical}} critical`;
  document.getElementById('count-high').textContent=`${{overview.high}} high`;
  document.getElementById('count-credentials').textContent=`${{overview.credentialCount}} exposed creds`;
  document.getElementById('count-agents').textContent=`${{overview.affectedAgentCount}} impacted agents`;
}}

function setSeverityFilter(level){{
  activeSeverity=level;
  ['all','critical','high','medium','low'].forEach((item)=>{{
    const el=document.getElementById(`sev-${{item}}`);
    if(el) el.classList.toggle('active', item===level);
  }});
  applyFilters();
}}

function toggleCredentialFilter(){{
  credentialsOnly=!credentialsOnly;
  document.getElementById('chip-credentials').classList.toggle('active', credentialsOnly);
  applyFilters();
}}

function toggleFocusedOnly(){{
  focusedPathOnly=!focusedPathOnly;
  document.getElementById('chip-focus').classList.toggle('active', focusedPathOnly);
  applyFilters();
}}

function matchingSeverityNodes(){{
  return cy.nodes().filter((node)=>{{
    const severity = node.data('severity');
    if(!severity) return false;
    return activeSeverity === 'all' ? true : severity === activeSeverity;
  }});
}}

function nodesForCredentialExposure(){{
  const servers = cy.nodes().filter((node)=>Boolean(node.data('hasCredentials')));
  let result = cy.collection();
  servers.forEach((node)=>{{
    result = result.union(node).union(node.predecessors()).union(node.successors());
  }});
  return result;
}}

function nodesForSearch(query){{
  const trimmed = (query || '').trim().toLowerCase();
  if(!trimmed) return null;
  const matches = cy.nodes().filter((node)=>{{
    const searchText = String(node.data('searchText') || node.data('label') || '').toLowerCase();
    return searchText.includes(trimmed);
  }});
  if(matches.empty()) return cy.collection();
  let result = cy.collection();
  matches.forEach((node)=>{{
    result = result.union(node).union(node.predecessors()).union(node.successors());
  }});
  return result;
}}

function expandedCveNodeId(packageNodeId, vulnId){{
  return `${{packageNodeId}}::${{vulnId}}`;
}}

function packageExpansionElements(node){{
  const rawList = node.data('cveList');
  if(!rawList) return [];
  let cveList = [];
  try {{
    cveList = JSON.parse(rawList);
  }} catch (_error) {{
    return [];
  }}

  const created = [];
  cveList.forEach((vulnInfo)=>{{
    const vulnId = String(vulnInfo.id || '');
    if(!vulnId) return;
    const severity = String(vulnInfo.severity || 'unknown');
    const cveId = expandedCveNodeId(node.id(), vulnId);
    if(cy.getElementById(cveId).length) return;
    created.push(
      {{
        data: {{
          id: cveId,
          label: `${{vulnId}}\\n${{severity.toUpperCase()}}`,
          type: `cve_${{severity}}`,
          severity,
          severityWeight: 1,
          summary: vulnInfo.summary || '',
          fixVersion: vulnInfo.fix_version || '',
          tip: `${{vulnId}}\\nSeverity: ${{severity}}\\n${{vulnInfo.summary || ''}}`,
          searchText: `${{vulnId}} ${{severity}} ${{vulnInfo.summary || ''}}`.toLowerCase(),
        }},
      }},
      {{
        data: {{
          source: node.id(),
          target: cveId,
          type: 'affects',
        }},
      }},
    );
  }});
  return created;
}}

function togglePackageExpansion(node){{
  if(!node.data('collapsedCves')) return false;
  const expanded = Boolean(expandedPackages.get(node.id()));
  if(expanded) {{
    let related = cy.collection();
    cy.elements().forEach((ele)=>{{
      const id = String(ele.data('id') || '');
      const source = String(ele.data('source') || '');
      const target = String(ele.data('target') || '');
      if(
        id.startsWith(`${{node.id()}}::`) ||
        (source === node.id() && target.startsWith(`${{node.id()}}::`))
      ) {{
        related = related.union(ele);
      }}
    }});
    cy.remove(related);
    expandedPackages.delete(node.id());
  }} else {{
    const created = packageExpansionElements(node);
    if(created.length) {{
      cy.add(created);
      expandedPackages.set(node.id(), true);
    }}
  }}
  runGraphLayout();
  applyFilters();
  return true;
}}

function focusedSubgraph(){{
  if(!activeRiskNodeId) return null;
  const node = cy.getElementById(activeRiskNodeId);
  if(!node || node.empty()) return null;
  return node.union(node.predecessors()).union(node.successors());
}}

function applyFilters(){{
  cy.elements().removeClass('filtered');
  let visible = cy.elements();

  const severityNodes = matchingSeverityNodes();
  if(!severityNodes.empty()) {{
    let severityGraph = cy.collection();
    severityNodes.forEach((node)=>{{
      severityGraph = severityGraph.union(node).union(node.predecessors());
    }});
    visible = visible.intersection(severityGraph.union(severityGraph.connectedEdges()));
  }}

  if(credentialsOnly) {{
    const credGraph = nodesForCredentialExposure();
    visible = visible.intersection(credGraph.union(credGraph.connectedEdges()));
  }}

  const searchGraph = nodesForSearch(document.getElementById('search').value);
  if(searchGraph !== null) {{
    visible = visible.intersection(searchGraph.union(searchGraph.connectedEdges()));
  }}

  const focusedGraph = focusedSubgraph();
  if(focusedPathOnly && focusedGraph) {{
    visible = visible.intersection(focusedGraph.union(focusedGraph.connectedEdges()));
  }}

  cy.elements().difference(visible).addClass('filtered');
}}

function fitAll(){{
  clearFocus();
  document.getElementById('detail').style.display='none';
  focusedPathOnly=false;
  document.getElementById('chip-focus').classList.remove('active');
  applyFilters();
  cy.fit(cy.elements(), 60);
}}

function focusNode(nodeId, opts){{
  const node = cy.getElementById(nodeId);
  if(!node || node.empty()) return;
  const focus = node.union(node.predecessors()).union(node.successors());
  cy.elements().addClass('faded');
  focus.removeClass('faded');
  focus.addClass('focus');
  cy.animate({{ fit: {{ eles: focus, padding: 90 }}, duration: 350 }});
  activeRiskNodeId=nodeId;
  if(!(opts && opts.silent)){{
    const risk = riskByNodeId.get(nodeId);
    if(risk){{
      setRiskDetail(risk);
    }} else {{
      const d=node.data();
      setDetail(d.label||d.id, `<div class="subtle">${{escapeHtml(d.tip || '')}}</div>`);
    }}
  }}
  applyFilters();
}}

function focusTopRisk(){{
  if(topRisks.length){{
    focusRisk(topRisks[0].nodeId);
  }} else {{
    fitAll();
  }}
}}

function focusRisk(nodeId){{
  clearFocus();
  focusNode(nodeId);
  const active=document.querySelector('[data-node-id=\"'+nodeId+'\"]');
  if(active) active.classList.add('active');
}}

function renderRiskList(){{
  const list=document.getElementById('riskList');
  if(!topRisks.length){{
    list.innerHTML='<div class=\"hint\">No vulnerable blast-radius paths were present in this report.</div>';
    return;
  }}
  list.innerHTML=topRisks.map((risk, index)=>`
    <button class="risk-item${{index===0 ? ' active' : ''}}" data-node-id="${{risk.nodeId}}" onclick="focusRisk('${{risk.nodeId}}')">
      <div class="risk-head">
        <div class="risk-title">${{risk.vulnerabilityId}} in ${{risk.packageName}}</div>
        <div class="risk-score">risk ${{risk.riskScore}}</div>
      </div>
      <div class="risk-meta">
        <span class="pill ${{severityClass(risk.severity)}}">${{risk.severity.toUpperCase()}}</span>
        <span class="pill">${{risk.reachability}}</span><br>
        ${{risk.agentCount}} agent(s) · ${{risk.serverCount}} server(s) ·
        ${{risk.credentialCount}} credential(s) · ${{risk.toolCount}} tool(s)
        ${{risk.fixVersion ? '<br>Fix: '+risk.fixVersion : ''}}
      </div>
      <div class="risk-summary">${{risk.summary ? risk.summary.slice(0, 130) : 'No summary available.'}}</div>
    </button>
  `).join('');
}}

cy.on('tap','node',function(e){{
  const node = e.target;
  if(togglePackageExpansion(node)){{
    clearFocus();
    focusNode(node.id(), {{ silent: false }});
    return;
  }}
  clearFocus();
  focusNode(node.id(), {{ silent: false }});
}});
cy.on('tap',function(e){{ if(e.target===cy) fitAll(); }});

function searchNodes(query){{
  const trimmed = (query || '').trim();
  applyFilters();
  if(!trimmed) return;
  const match = cy
    .nodes(':visible')
    .filter((node)=>String(node.data('label') || '').toLowerCase().includes(trimmed.toLowerCase()))
    .first();
  if(match && !match.empty()){{
    cy.animate({{ fit: {{ eles: match.closedNeighborhood(), padding: 120 }}, duration: 250 }});
  }}
}}

function dlPng(){{
  const a=document.createElement('a');
  a.href=cy.png({{scale:2,bg:'#0f1419'}});
  a.download='agent-bom-graph.png';
  a.click();
}}

renderRiskList();
updateOverview();
document.getElementById('chip-focus').classList.add('active');
cy.ready(function(){{
  setTimeout(function(){{ focusTopRisk(); }}, 120);
}});
</script>
</body>
</html>"""
