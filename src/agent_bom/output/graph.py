"""Graph data builders for agent → server → package → CVE relationship visualization.

Produces Cytoscape.js-compatible element lists consumable by:
- The built-in HTML dashboard (``--format html``)
- Standalone graph JSON export (``--format graph``)
- External tools: Cytoscape desktop, Sigma.js, D3.js, Gephi (via conversion)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius


def build_graph_elements(
    report: "AIBOMReport",
    blast_radii: list["BlastRadius"],
    include_cve_nodes: bool = True,
) -> list[dict]:
    """Build a Cytoscape.js-compatible element list with provider, agent, server, package, and CVE nodes.

    Node types:
      - ``provider``    — cloud source grouping (AWS, Azure, Databricks, local, etc.)
      - ``agent``       — AI agent
      - ``server_vuln`` — MCP server with vulnerable packages
      - ``server_cred`` — MCP server with exposed credentials
      - ``server_clean``— MCP server, no issues
      - ``pkg_vuln``    — vulnerable package
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

    # Map (pkg_name, ecosystem) → set of CVE IDs already added as nodes
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

            pkg_note = f"\nPackages: {len(srv.packages)}"
            if vuln_count:
                pkg_note += f"\nVulnerable: {vuln_count}"
            cinfo = f"\nCredentials: {', '.join(srv.credential_names)}" if has_cred else ""
            pkg_badge = f" ({len(srv.packages)})"
            server_label = srv.name + pkg_badge
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
                        "vulnCount": vuln_count,
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
                    }
                }
            )

            # ── Package nodes (vulnerable only) ───────────────────────
            seen_pkg_ids: set[str] = set()
            for pkg in srv.packages:
                pkg_key = (pkg.name, pkg.ecosystem)
                if pkg_key not in vuln_pkg_keys:
                    continue

                pid = f"pkg:{pkg.name}:{pkg.ecosystem}"
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

                vc = len(pkg.vulnerabilities)
                vuln_ids = [vi["id"] for vi in pkg_to_vulns.get(pkg_key, [])]
                elements.append(
                    {
                        "data": {
                            "id": pid,
                            "label": f"{pkg.name}\n{pkg.version}",
                            "type": "pkg_vuln",
                            "tip": (
                                f"Package: {pkg.name}\n"
                                f"Version: {pkg.version}\n"
                                f"Ecosystem: {pkg.ecosystem}\n"
                                f"Vulnerabilities: {vc if vc else '(via blast radius)'}"
                            ),
                            "ecosystem": pkg.ecosystem,
                            "version": pkg.version,
                            "vulnIds": json.dumps(vuln_ids),
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
                        }
                    }
                )

                # ── CVE nodes ─────────────────────────────────────────
                if include_cve_nodes and pkg_key in pkg_to_vulns:
                    for vuln_info in pkg_to_vulns[pkg_key]:
                        cve_id = f"cve:{vuln_info['id']}"
                        if cve_id not in cve_nodes_seen:
                            cve_nodes_seen.add(cve_id)
                            sev = vuln_info["severity"]
                            severity_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev, 1)
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


def _graph_priority_summary(blast_radii: list["BlastRadius"]) -> list[dict]:
    """Summarize the highest-value blast-radius paths for the HTML graph.

    The standalone graph needs an operator-facing starting point, not just raw
    nodes. These summaries drive the top-risk sidebar and focus behavior.
    """
    priorities: list[dict] = []
    for br in sorted(blast_radii, key=lambda item: item.risk_score, reverse=True)[:8]:
        priorities.append(
            {
                "nodeId": f"cve:{br.vulnerability.id}",
                "vulnerabilityId": br.vulnerability.id,
                "packageName": br.package.name,
                "severity": br.vulnerability.severity.value,
                "riskScore": round(br.risk_score, 1),
                "agentCount": len(br.affected_agents),
                "serverCount": len(br.affected_servers),
                "credentialCount": len(br.exposed_credentials),
                "toolCount": len(br.exposed_tools),
                "fixVersion": br.vulnerability.fixed_version or "",
                "reachability": br.reachability,
            }
        )
    return priorities


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

    elements = build_graph_elements(report, blast_radii)
    elements_json = json.dumps(elements, indent=2)

    total_agents = len(report.agents)
    total_servers = sum(len(a.mcp_servers) for a in report.agents)
    total_pkgs = sum(a.total_packages for a in report.agents)
    total_vulns = len(blast_radii)
    top_risks_json = json.dumps(_graph_priority_summary(blast_radii), indent=2)

    html_content = _GRAPH_HTML_TEMPLATE.format(
        elements_json=elements_json,
        top_risks_json=top_risks_json,
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
  #cy {{ width: 100%; height: calc(100vh - 120px); }}
  .panel {{ position: fixed; z-index: 10; background: rgba(26, 31, 37, 0.96); border: 1px solid #2f3336;
    border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,.28); backdrop-filter: blur(10px); }}
  #riskpanel {{ top: 88px; left: 16px; width: 320px; max-height: calc(100vh - 220px); overflow: auto; }}
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
  .pill {{ display: inline-block; font-size: 10px; padding: 2px 6px; border-radius: 999px;
    background: #2f3336; color: #e7e9ea; margin-right: 6px; }}
  .pill.critical {{ background: #5b1f24; color: #ffb3b8; }}
  .pill.high {{ background: #5b341f; color: #ffd1a5; }}
  .pill.medium {{ background: #4b3d18; color: #ffe28a; }}
  #legend {{ bottom: 16px; left: 16px; padding: 12px; font-size: 11px; width: 220px; }}
  #legend div {{ display: flex; align-items: center; gap: 6px; margin: 4px 0; }}
  .dot {{ width: 12px; height: 12px; border-radius: 3px; display: inline-block; }}
  #detail {{ top: 88px; right: 16px; width: 320px; max-height: calc(100vh - 220px); overflow: auto; display: none; }}
  #detail pre {{ white-space: pre-wrap; color: #9ba1a6; font-size: 11px; line-height: 1.45; }}
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
    <pre id="db"></pre>
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
let activeRiskNodeId=null;
cytoscape.use(cytoscapeDagre);
const cy=cytoscape({{
  container:document.getElementById('cy'),elements:els,
  layout:{{name:'dagre',rankDir:'LR',nodeSep:72,rankSep:190,padding:48,ranker:'network-simplex',acyclicer:'greedy'}},
  style:[
    {{selector:'node',style:{{'label':'data(label)','text-wrap':'wrap','text-max-width':180,
      'font-size':12,'font-weight':600,'text-valign':'center','color':'#e7e9ea','width':160,'height':46,
      'shape':'roundrectangle','background-color':'#2f3336','border-width':1.2,'border-color':'#444',
      'text-outline-width':0}}}},
    {{selector:'node[type="provider"]',style:{{'background-color':'#1a3a5c','border-color':'#4a9eff','width':126,'height':36,'font-size':10}}}},
    {{selector:'node[type="agent"]',style:{{'background-color':'#1a3520','border-color':'#2ea043','width':168,'height':50}}}},
    {{selector:'node[type="server_clean"]',style:{{'background-color':'#21262d','border-color':'#6e7681','opacity':0.72}}}},
    {{selector:'node[type="server_vuln"]',style:{{'background-color':'#451f24','border-color':'#ff5d5d','width':176,'height':52}}}},
    {{selector:'node[type="server_cred"]',style:{{'background-color':'#4c3411','border-color':'#f2b84b','width':176,'height':52}}}},
    {{selector:'node[type="pkg_vuln"]',style:{{'background-color':'#3b1a1a','border-color':'#da3633','width':170,'height':50}}}},
    {{selector:'node[type^="cve_critical"]',style:{{'background-color':'#ff3b30','color':'#fff',
      'shape':'diamond','width':'mapData(severityWeight, 1, 4, 118, 154)',
      'height':'mapData(severityWeight, 1, 4, 48, 64)'}}}},
    {{selector:'node[type^="cve_high"]',style:{{'background-color':'#ff8a24','color':'#fff',
      'shape':'diamond','width':'mapData(severityWeight, 1, 4, 118, 154)',
      'height':'mapData(severityWeight, 1, 4, 48, 64)'}}}},
    {{selector:'node[type^="cve_medium"]',style:{{'background-color':'#ffd33d','color':'#000',
      'shape':'diamond','width':'mapData(severityWeight, 1, 4, 118, 154)',
      'height':'mapData(severityWeight, 1, 4, 48, 64)'}}}},
    {{selector:'node[type^="cve_low"]',style:{{'background-color':'#6e7681','color':'#fff',
      'shape':'diamond','width':'mapData(severityWeight, 1, 4, 118, 154)',
      'height':'mapData(severityWeight, 1, 4, 48, 64)'}}}},
    {{selector:'edge',style:{{'width':1.5,'line-color':'#444','target-arrow-color':'#444',
      'target-arrow-shape':'triangle','curve-style':'bezier','arrow-scale':0.8,'opacity':0.7}}}},
    {{selector:'edge[type="affects"]',style:{{'line-color':'#ff5d5d','target-arrow-color':'#ff5d5d','width':1.8}}}},
    {{selector:'.faded',style:{{'opacity':0.14}}}},
    {{selector:'.focus',style:{{'opacity':1,'border-width':2.5,'border-color':'#58a6ff','z-index':9999}}}},
    {{selector:'edge.focus',style:{{'opacity':1,'line-color':'#58a6ff','target-arrow-color':'#58a6ff','width':2.4}}}},
  ],wheelSensitivity:0.3
}});

function setDetail(title, body){{
  document.getElementById('detail').style.display='block';
  document.getElementById('dt').textContent=title;
  document.getElementById('db').textContent=body;
}}

function clearFocus(){{
  cy.elements().removeClass('focus faded');
  document.querySelectorAll('.risk-item').forEach((el)=>el.classList.remove('active'));
  activeRiskNodeId=null;
}}

function fitAll(){{
  clearFocus();
  document.getElementById('detail').style.display='none';
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
    const d=node.data();
    setDetail(d.label||d.id, d.tip||JSON.stringify(d,null,2));
  }}
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

function severityClass(sev){{
  if(sev === 'critical' || sev === 'high' || sev === 'medium') return sev;
  return '';
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
    </button>
  `).join('');
}}

cy.on('tap','node',function(e){{
  clearFocus();
  focusNode(e.target.id(), {{ silent: false }});
}});
cy.on('tap',function(e){{ if(e.target===cy) fitAll(); }});

function dlPng(){{
  const a=document.createElement('a');
  a.href=cy.png({{scale:2,bg:'#0f1419'}});
  a.download='agent-bom-graph.png';
  a.click();
}}

renderRiskList();
cy.ready(function(){{
  setTimeout(function(){{ focusTopRisk(); }}, 120);
}});
</script>
</body>
</html>"""
