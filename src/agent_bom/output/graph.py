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

            elements.append(
                {
                    "data": {
                        "id": sid,
                        "label": srv.name + pkg_badge,
                        "type": stype,
                        "tip": f"MCP Server: {srv.name}{pkg_note}{cinfo}",
                        "command": ((srv.command or "") + " " + " ".join((srv.args or [])[:3]))[:80].strip(),
                        "packageCount": len(srv.packages),
                        "vulnCount": vuln_count,
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
                            elements.append(
                                {
                                    "data": {
                                        "id": cve_id,
                                        "label": vuln_info["id"],
                                        "type": f"cve_{sev}",
                                        "tip": (f"{vuln_info['id']}\nSeverity: {sev}\n{vuln_info['summary']}"),
                                        "severity": sev,
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

    html_content = _GRAPH_HTML_TEMPLATE.format(
        elements_json=elements_json,
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
  #header {{ padding: 16px 24px; display: flex; align-items: center; justify-content: space-between;
    border-bottom: 1px solid #2f3336; }}
  #header h1 {{ font-size: 18px; font-weight: 600; }}
  #stats {{ font-size: 13px; color: #71767b; }}
  #stats span {{ margin: 0 8px; }}
  #cy {{ width: 100%; height: calc(100vh - 120px); }}
  #legend {{ position: fixed; bottom: 16px; left: 16px; background: #1a1f25; border: 1px solid #2f3336;
    border-radius: 8px; padding: 12px; font-size: 11px; z-index: 10; }}
  #legend div {{ display: flex; align-items: center; gap: 6px; margin: 4px 0; }}
  .dot {{ width: 12px; height: 12px; border-radius: 3px; display: inline-block; }}
  #detail {{ position: fixed; top: 60px; right: 16px; background: #1a1f25; border: 1px solid #2f3336;
    border-radius: 8px; padding: 16px; width: 280px; font-size: 12px; z-index: 10; display: none; }}
  #detail h3 {{ font-size: 14px; margin-bottom: 8px; }}
  #detail pre {{ white-space: pre-wrap; color: #71767b; font-size: 11px; }}
  #controls {{ position: fixed; bottom: 16px; right: 16px; z-index: 10; display: flex; gap: 6px; }}
  #controls button {{ padding: 6px 12px; border: 1px solid #2f3336; background: #1a1f25;
    color: #e7e9ea; border-radius: 6px; cursor: pointer; font-size: 12px; }}
  #controls button:hover {{ background: #2f3336; }}
</style>
</head>
<body>
<div id="header">
  <h1>agent-bom Supply Chain Graph</h1>
  <div id="stats">
    <span>{total_agents} agents</span> | <span>{total_servers} servers</span> |
    <span>{total_pkgs} packages</span> | <span>{total_vulns} CVEs</span>
  </div>
</div>
<div id="cy"></div>
<div id="legend">
  <div><span class="dot" style="background:#4a9eff"></span> Provider</div>
  <div><span class="dot" style="background:#2ea043"></span> Agent</div>
  <div><span class="dot" style="background:#6e7681"></span> Server (clean)</div>
  <div><span class="dot" style="background:#f85149"></span> Server (vulnerable)</div>
  <div><span class="dot" style="background:#d29922"></span> Server (credentials)</div>
  <div><span class="dot" style="background:#da3633"></span> CVE critical</div>
  <div><span class="dot" style="background:#db6d28"></span> CVE high</div>
  <div><span class="dot" style="background:#d29922"></span> CVE medium</div>
</div>
<div id="detail"><h3 id="dt"></h3><pre id="db"></pre></div>
<div id="controls">
  <button onclick="cy.fit(50)">Fit</button>
  <button onclick="cy.zoom(cy.zoom()*1.3);cy.center()">+</button>
  <button onclick="cy.zoom(cy.zoom()/1.3);cy.center()">-</button>
  <button onclick="dlPng()">PNG</button>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/dagre@0.8.5/dist/dagre.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.js"></script>
<script>
const els={elements_json};
cytoscape.use(cytoscapeDagre);
const cy=cytoscape({{
  container:document.getElementById('cy'),elements:els,
  layout:{{name:'dagre',rankDir:'LR',nodeSep:40,rankSep:120,padding:30}},
  style:[
    {{selector:'node',style:{{'label':'data(label)','text-wrap':'wrap','text-max-width':140,
      'font-size':10,'text-valign':'center','color':'#e7e9ea','width':140,'height':40,
      'shape':'roundrectangle','background-color':'#2f3336','border-width':1,'border-color':'#444'}}}},
    {{selector:'node[type="provider"]',style:{{'background-color':'#1a3a5c','border-color':'#4a9eff'}}}},
    {{selector:'node[type="agent"]',style:{{'background-color':'#1a3520','border-color':'#2ea043'}}}},
    {{selector:'node[type="server_clean"]',style:{{'background-color':'#21262d','border-color':'#6e7681'}}}},
    {{selector:'node[type="server_vuln"]',style:{{'background-color':'#3b1a1a','border-color':'#f85149'}}}},
    {{selector:'node[type="server_cred"]',style:{{'background-color':'#3b2a0a','border-color':'#d29922'}}}},
    {{selector:'node[type="pkg_vuln"]',style:{{'background-color':'#3b1a1a','border-color':'#da3633'}}}},
    {{selector:'node[type^="cve_critical"]',style:{{'background-color':'#da3633','color':'#fff','shape':'diamond','width':100,'height':40}}}},
    {{selector:'node[type^="cve_high"]',style:{{'background-color':'#db6d28','color':'#fff','shape':'diamond','width':100,'height':40}}}},
    {{selector:'node[type^="cve_medium"]',style:{{'background-color':'#d29922','color':'#000','shape':'diamond','width':100,'height':40}}}},
    {{selector:'node[type^="cve_low"]',style:{{'background-color':'#6e7681','color':'#fff','shape':'diamond','width':100,'height':40}}}},
    {{selector:'edge',style:{{'width':1.5,'line-color':'#444','target-arrow-color':'#444',
      'target-arrow-shape':'triangle','curve-style':'bezier','arrow-scale':0.8}}}},
    {{selector:'edge[type="affects"]',style:{{'line-color':'#da3633','target-arrow-color':'#da3633'}}}},
  ],wheelSensitivity:0.3
}});
cy.on('tap','node',function(e){{
  const d=e.target.data();
  document.getElementById('detail').style.display='block';
  document.getElementById('dt').textContent=d.label||d.id;
  document.getElementById('db').textContent=d.tip||JSON.stringify(d,null,2);
}});
cy.on('tap',function(e){{if(e.target===cy)document.getElementById('detail').style.display='none';}});
function dlPng(){{const a=document.createElement('a');a.href=cy.png({{scale:2,bg:'#0f1419'}});
  a.download='agent-bom-graph.png';a.click();}}
</script>
</body>
</html>"""
