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
    vuln_pkg_keys: set[tuple[str, str]] = {
        (br.package.name, br.package.ecosystem) for br in blast_radii
    }

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
        pkg_to_vulns[key].append({
            "id": br.vulnerability.id,
            "severity": br.vulnerability.severity.value,
            "summary": br.vulnerability.summary[:100] if br.vulnerability.summary else "",
            "risk_score": br.risk_score,
            "cvss_score": br.vulnerability.cvss_score or 0,
            "fix_version": br.vulnerability.fixed_version or "",
        })

    for agent in report.agents:
        # ── Provider node ─────────────────────────────────────────────
        source = agent.source or "local"
        if source not in providers_seen:
            providers_seen.add(source)
            elements.append({"data": {
                "id": f"provider:{source}",
                "label": _provider_label(source),
                "type": "provider",
                "tip": f"Source: {source}",
            }})

        # ── Agent node ────────────────────────────────────────────────
        aid = f"a:{agent.name}"
        elements.append({"data": {
            "id": aid,
            "label": agent.name,
            "type": "agent",
            "tip": (
                f"Agent: {agent.name}\n"
                f"Type: {agent.agent_type.value}\n"
                f"Source: {source}\n"
                f"Servers: {len(agent.mcp_servers)}"
            ),
            "agentType": agent.agent_type.value,
            "configPath": agent.config_path or "",
            "source": source,
            "serverCount": len(agent.mcp_servers),
            "packageCount": agent.total_packages,
            "vulnCount": agent.total_vulnerabilities,
        }})
        # Edge: provider → agent
        elements.append({"data": {
            "source": f"provider:{source}",
            "target": aid,
            "type": "hosts",
        }})

        # ── Server nodes ──────────────────────────────────────────────
        for srv in agent.mcp_servers:
            sid = f"s:{agent.name}:{srv.name}"
            vuln_count = sum(
                1 for p in srv.packages
                if (p.name, p.ecosystem) in vuln_pkg_keys
            )
            has_vuln = vuln_count > 0
            has_cred = srv.has_credentials
            stype = "server_vuln" if has_vuln else ("server_cred" if has_cred else "server_clean")

            pkg_note = f"\nPackages: {len(srv.packages)}"
            if vuln_count:
                pkg_note += f"\nVulnerable: {vuln_count}"
            cinfo = f"\nCredentials: {', '.join(srv.credential_names)}" if has_cred else ""
            pkg_badge = f" ({len(srv.packages)})"

            elements.append({"data": {
                "id": sid,
                "label": srv.name + pkg_badge,
                "type": stype,
                "tip": f"MCP Server: {srv.name}{pkg_note}{cinfo}",
                "command": ((srv.command or "") + " " + " ".join((srv.args or [])[:3]))[:80].strip(),
                "packageCount": len(srv.packages),
                "vulnCount": vuln_count,
                "credentials": json.dumps(srv.credential_names) if srv.credential_names else "[]",
                "toolNames": json.dumps([t.name for t in srv.tools[:10]]) if srv.tools else "[]",
            }})
            # Edge: agent → server
            elements.append({"data": {
                "source": aid,
                "target": sid,
                "type": "uses",
            }})

            # ── Package nodes (vulnerable only) ───────────────────────
            seen_pkg_ids: set[str] = set()
            for pkg in srv.packages:
                pkg_key = (pkg.name, pkg.ecosystem)
                if pkg_key not in vuln_pkg_keys:
                    continue

                pid = f"pkg:{pkg.name}:{pkg.ecosystem}"
                if pid in seen_pkg_ids:
                    # Just add another edge for shared package
                    elements.append({"data": {
                        "source": sid,
                        "target": pid,
                        "type": "depends_on",
                    }})
                    continue
                seen_pkg_ids.add(pid)

                vc = len(pkg.vulnerabilities)
                vuln_ids = [vi["id"] for vi in pkg_to_vulns.get(pkg_key, [])]
                elements.append({"data": {
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
                }})
                # Edge: server → package
                elements.append({"data": {
                    "source": sid,
                    "target": pid,
                    "type": "depends_on",
                }})

                # ── CVE nodes ─────────────────────────────────────────
                if include_cve_nodes and pkg_key in pkg_to_vulns:
                    for vuln_info in pkg_to_vulns[pkg_key]:
                        cve_id = f"cve:{vuln_info['id']}"
                        if cve_id not in cve_nodes_seen:
                            cve_nodes_seen.add(cve_id)
                            sev = vuln_info["severity"]
                            elements.append({"data": {
                                "id": cve_id,
                                "label": vuln_info["id"],
                                "type": f"cve_{sev}",
                                "tip": (
                                    f"{vuln_info['id']}\n"
                                    f"Severity: {sev}\n"
                                    f"{vuln_info['summary']}"
                                ),
                                "severity": sev,
                                "cvssScore": vuln_info.get("cvss_score", 0),
                                "summary": vuln_info.get("summary", ""),
                                "fixVersion": vuln_info.get("fix_version", ""),
                            }})
                        # Edge: package → CVE
                        elements.append({"data": {
                            "source": pid,
                            "target": cve_id,
                            "type": "affects",
                        }})

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
        _add_node(cve_id,
                  label=v.id,
                  type=f"cve_{sev}",
                  tip=f"{v.id}\nSeverity: {sev}{score_text}\nBlast score: {br.risk_score:.1f}{fix_text}")

        # Package node
        pkg_id = f"pkg:{br.package.name}"
        _add_node(pkg_id,
                  label=f"{br.package.name}\n@{br.package.version}",
                  type="pkg_vuln",
                  tip=f"Package: {br.package.name}\nVersion: {br.package.version}\nEcosystem: {br.package.ecosystem}")
        _add_edge(cve_id, pkg_id, "exploits")

        # Servers that use this package
        for agent in br.affected_agents:
            for srv in agent.mcp_servers:
                pkg_match = any(
                    p.name == br.package.name and p.ecosystem == br.package.ecosystem
                    for p in srv.packages
                )
                if not pkg_match:
                    continue

                srv_id = f"srv:{agent.name}:{srv.name}"
                _add_node(srv_id,
                          label=srv.name,
                          type="server",
                          tip=f"MCP Server: {srv.name}\nAgent: {agent.name}\nPackages: {len(srv.packages)}")
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
                _add_node(agent_id,
                          label=agent.name,
                          type="agent",
                          tip=f"Agent: {agent.name}\nType: {agent.agent_type.value}")
                _add_edge(srv_id, agent_id, "compromises")

    return elements
