"""Top-level HTML document assembler and file exporter."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from agent_bom.output.finding_views import cve_findings, severity_value, topology_package_key
from agent_bom.output.html._common import _esc
from agent_bom.output.html.scripts import (
    SCALE_REPORT_SCRIPT,
    _apply_offline_assets_mode,
    render_graph_script,
)
from agent_bom.output.html.sections import (
    _ai_inventory_section,
    _attack_flow_elements,
    _attack_flow_section,
    _blast_table,
    _chart_data,
    _cis_benchmark_section,
    _compliance_section,
    _cytoscape_elements,
    _delta_banner,
    _enforcement_section,
    _exposure_path_section,
    _inventory_cards,
    _non_cve_findings,
    _policy_findings_section,
    _remediation_list,
    _skill_audit_section,
    _summary_cards,
    _trust_assessment_section,
    _vuln_table,
    _warn_gate_banner,
)
from agent_bom.output.html.styles import render_styles
from agent_bom.output.html.tabs import _apply_tabs

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius


def to_html(
    report: "AIBOMReport",
    blast_radii: list["BlastRadius"] | None = None,
    *,
    offline_assets: bool = False,
) -> str:
    blast_radii = blast_radii or []
    findings = cve_findings(report, blast_radii)
    policy_findings = _non_cve_findings(report)
    generated = report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    elements_json = _cytoscape_elements(report, blast_radii)
    attack_flow_json = _attack_flow_elements(report, blast_radii)
    chart_data_json = _chart_data(findings)
    crit = sum(1 for finding in findings if severity_value(finding) == "critical")
    policy_crit = sum(1 for finding in policy_findings if str(finding.severity).lower() == "critical")
    policy_high = sum(1 for finding in policy_findings if str(finding.severity).lower() == "high")
    total_vulns = len(findings)

    if crit or policy_crit:
        status_color, status_label = "#dc2626", "CRITICAL FINDINGS"
    elif total_vulns or policy_high or policy_findings:
        status_color, status_label = "#d97706", "SECURITY FINDINGS"
    else:
        status_color, status_label = "#16a34a", "CLEAN"

    # Sections
    vuln_sections = ""
    if findings:
        vuln_sections = (
            f'<section id="vulns">'
            f'<div class="sec-title">&#x26a0;&#xfe0f; Vulnerabilities'
            f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{len(findings)}</sup>'
            f"</div>"
            f'<div class="panel">{_vuln_table(report, blast_radii)}</div>'
            f"</section>"
            f'<section id="exposure-paths">'
            f'<div class="sec-title">&#x1f9ed; Exposure Paths'
            f'<sup style="font-size:.65rem;color:#475569;margin-left:6px;font-weight:400">'
            f"ranked investigation briefs from blast-radius evidence"
            f"</sup></div>"
            f'<div class="panel exposure-paths">{_exposure_path_section(report, blast_radii)}</div>'
            f"</section>"
            f'<section id="blast">'
            f'<div class="sec-title">&#x1f4a5; Blast Radius'
            f'<sup style="font-size:.65rem;color:#475569;margin-left:6px;font-weight:400">'
            f"risk = CVSS + agents + creds + tools + KEV/EPSS boosts (max 10)"
            f"</sup></div>"
            f'<div class="panel">{_blast_table(report, blast_radii)}</div>'
            f"</section>"
            f'<section id="remediation">'
            f'<div class="sec-title">&#x1f527; Remediation Plan</div>'
            f'<div class="panel">{_remediation_list(findings)}</div>'
            f"</section>"
        )
    policy_section = _policy_findings_section(policy_findings)

    # Compliance section
    compliance_html = _compliance_section(findings)

    # AI inventory section
    ai_inv_section = _ai_inventory_section(report)

    # Skill audit section
    skill_section = _skill_audit_section(report)

    # Trust assessment section
    trust_section = _trust_assessment_section(report)

    # Enforcement section
    enforce_section = _enforcement_section(report)

    # CIS benchmark posture (issue #665 — structured remediation)
    cis_bench_section = _cis_benchmark_section(report)

    # Determine node counts for graph subtitle
    vuln_node_count = len({topology_package_key(finding) for finding in findings})
    graph_note = (
        f"agents + servers + {vuln_node_count} vulnerable pkg(s) only — {report.total_packages - vuln_node_count} clean packages hidden"
        if report.total_packages > vuln_node_count
        else "agents + servers + packages"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>agent-bom AI-BOM &mdash; {_esc(generated)}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
  <script src="https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"></script>
  <script src="https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"></script>
  <script src="https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js"></script>
  <script src="https://unpkg.com/cytoscape-popper@2.0.0/cytoscape-popper.js"></script>
{render_styles(status_color)}
</head>
<body>

<!-- Mobile sidebar toggle -->
<button class="sidebar-toggle" id="sidebarToggle" onclick="document.getElementById('mainSidebar').classList.toggle('mobile-open');this.innerHTML=this.innerHTML==='&#9776;'?'&times;':'&#9776;'">&#9776;</button>

<!-- Sidebar Navigation -->
<div class="sidebar" id="mainSidebar">
  <div class="sidebar-brand">
    <div class="brand-icon">&#x1f6e1;&#xfe0f;</div>
    <div>
      <div class="brand-text">agent-bom</div>
      <div class="brand-sub">Open security scanner for AI infrastructure</div>
    </div>
  </div>
  <div class="sidebar-status">
    <span class="status-badge">{status_label}</span>
    <span class="scan-time">v{_esc(report.tool_version)}</span>
  </div>

  <div class="sidebar-group">
    <div class="sidebar-group-label">Overview</div>
    <a href="#summary" class="sidebar-link active"><span class="link-icon">&#x1f4ca;</span> Summary</a>
    <a href="#charts" class="sidebar-link"><span class="link-icon">&#x1f4c8;</span> Risk Charts</a>
  </div>

  <div class="sidebar-group">
    <div class="sidebar-group-label">Analysis</div>
    <a href="#riskmap" class="sidebar-link"><span class="link-icon">&#x1f5fa;&#xfe0f;</span> Supply Chain Graph</a>
    <a href="#inventory" class="sidebar-link"><span class="link-icon">&#x1f4e6;</span> Agent Inventory</a>
    {'<a href="#aiinventory" class="sidebar-link"><span class="link-icon">&#x1f916;</span> AI Inventory</a>' if ai_inv_section else ""}
  </div>

  <div class="sidebar-group">
    <div class="sidebar-group-label">Security</div>
    {'<a href="#attackflow" class="sidebar-link"><span class="link-icon">&#x26a1;</span> Attack Flow</a>' if findings else ""}
    {f'<a href="#vulns" class="sidebar-link"><span class="link-icon">&#x1f41b;</span> Vulnerabilities <span class="link-badge" style="background:#7f1d1d;color:#fca5a5">{len(findings)}</span></a>' if findings else ""}
    {f'<a href="#policyfindings" class="sidebar-link"><span class="link-icon">&#x1f6e1;&#xfe0f;</span> Policy Findings <span class="link-badge" style="background:#78350f;color:#fcd34d">{len(policy_findings)}</span></a>' if policy_findings else ""}
    {'<a href="#exposure-paths" class="sidebar-link"><span class="link-icon">&#x1f9ed;</span> Exposure Paths</a>' if findings else ""}
    {'<a href="#blast" class="sidebar-link"><span class="link-icon">&#x1f4a5;</span> Blast Radius</a>' if findings else ""}
    {'<a href="#remediation" class="sidebar-link"><span class="link-icon">&#x1f527;</span> Remediation</a>' if findings else ""}
  </div>

  <div class="sidebar-group">
    <div class="sidebar-group-label">Governance</div>
    {'<a href="#compliance" class="sidebar-link"><span class="link-icon">&#x2705;</span> Compliance</a>' if compliance_html else ""}
    {'<a href="#skillaudit" class="sidebar-link"><span class="link-icon">&#x1f50d;</span> Skill Audit</a>' if skill_section else ""}
    {'<a href="#trust" class="sidebar-link"><span class="link-icon">&#x1f91d;</span> Trust</a>' if trust_section else ""}
    {'<a href="#enforcement" class="sidebar-link"><span class="link-icon">&#x1f512;</span> Enforcement</a>' if enforce_section else ""}
    {'<a href="#cisbenchmarks" class="sidebar-link"><span class="link-icon">&#x1f6e1;&#xfe0f;</span> CIS Benchmarks</a>' if cis_bench_section else ""}
  </div>

  <div class="sidebar-spacer"></div>

  <div class="sidebar-footer">
    <div class="scan-time">{_esc(generated)}</div>
    <button class="print-btn" onclick="window.print()">&#x1f5b6;&#xfe0f; Print / Export PDF</button>
  </div>
</div>

<div id="tip"></div>

<div id="nodeDetailSidebar" class="node-sidebar" style="display:none">
  <div class="sidebar-header">
    <span id="sidebarNodeType" class="sidebar-type"></span>
    <button id="sidebarClose" class="sidebar-close">&times;</button>
  </div>
  <h3 id="sidebarNodeName" class="sidebar-name"></h3>
  <div id="sidebarMeta" class="sidebar-meta"></div>
  <div id="sidebarConnected" class="sidebar-section"></div>
  <div id="sidebarCredentials" class="sidebar-section"></div>
  <div id="sidebarCves" class="sidebar-section"></div>
  <div id="sidebarRemediation" class="sidebar-section"></div>
</div>

<div class="container">

  <!-- Delta / warn-gate banners (only rendered when applicable) -->
  {_delta_banner(report)}
  {_warn_gate_banner(report)}

  <!-- Summary stat cards -->
  <section id="summary">
    <div class="sec-title">Summary</div>
    {_summary_cards(report, findings, policy_findings)}
  </section>

  <!-- Charts row -->
  <section id="charts">
    <div class="sec-title">Risk Overview</div>
    <div class="charts-row">
      <div class="chart-panel">
        <div class="chart-title">Severity Distribution</div>
        <div class="donut-wrap">
          <canvas id="sevChart" height="240"></canvas>
        </div>
      </div>
      <div class="chart-panel">
        <div class="chart-title">Top Blast Radius Scores</div>
        <div class="chart-wrap">
          <canvas id="blastChart" height="240"></canvas>
        </div>
      </div>
    </div>
  </section>

  <!-- Risk map graph -->
  <section id="riskmap">
    <div class="sec-title">
      Supply Chain Graph
      <span style="font-size:.68rem;font-weight:400;opacity:.5;margin-left:8px">
        {_esc(graph_note)}
      </span>
    </div>
    <div class="graph-container">
      <div id="cy"></div>
      <div class="graph-filter-bar" style="position:absolute;top:12px;left:12px;display:flex;gap:8px;align-items:center;z-index:10;background:rgba(15,23,42,.92);padding:8px 12px;border-radius:8px;border:1px solid #334155;backdrop-filter:blur(8px)">
        <label style="display:flex;align-items:center;gap:3px;font-size:.72rem;color:#fca5a5;cursor:pointer"><input type="checkbox" class="graph-sev-filter" value="critical" checked> Crit</label>
        <label style="display:flex;align-items:center;gap:3px;font-size:.72rem;color:#fb923c;cursor:pointer"><input type="checkbox" class="graph-sev-filter" value="high" checked> High</label>
        <label style="display:flex;align-items:center;gap:3px;font-size:.72rem;color:#fbbf24;cursor:pointer"><input type="checkbox" class="graph-sev-filter" value="medium" checked> Med</label>
        <label style="display:flex;align-items:center;gap:3px;font-size:.72rem;color:#94a3b8;cursor:pointer"><input type="checkbox" class="graph-sev-filter" value="low" checked> Low</label>
        <span style="width:1px;height:16px;background:#334155"></span>
        <input type="text" id="graphSearch" placeholder="Search nodes&hellip;" style="padding:4px 8px;background:#0f172a;border:1px solid #334155;border-radius:4px;color:#e2e8f0;font-size:.72rem;width:120px;outline:none">
      </div>
      <div class="graph-controls">
        <button class="graph-btn" id="zoomIn" title="Zoom in">+</button>
        <button class="graph-btn" id="zoomOut" title="Zoom out">&minus;</button>
        <button class="graph-btn" id="fitBtn" title="Fit to view">&#x2922;</button>
        <button class="graph-btn" id="fullscreenBtn" title="Fullscreen">&#x26F6;</button>
      </div>
    </div>
    <div class="legend">
      <span><i style="background:#818cf8"></i>Provider</span>
      <span><i style="background:#3b82f6"></i>Agent</span>
      <span><i style="background:#10b981"></i>Server (clean)</span>
      <span><i style="background:#f59e0b"></i>Server (credentials)</span>
      <span><i style="background:#ef4444"></i>Server (vulnerable)</span>
      <span><i style="background:#dc2626"></i>Vulnerable package</span>
      <span><i class="diamond" style="background:#f87171"></i>CVE</span>
    </div>
  </section>

  <!-- Agent inventory (collapsible) -->
  <section id="inventory">
    <div class="sec-title">Agent Inventory</div>
    <input type="text" class="inv-search" id="invSearch" placeholder="Search agents, servers, packages&hellip;">
    {_inventory_cards(report)}
  </section>

  <!-- AI component inventory -->
  {ai_inv_section}

  <!-- Skill audit -->
  {skill_section}

  <!-- Trust assessment -->
  {trust_section}

  <!-- Enforcement -->
  {enforce_section}

  <!-- CIS benchmark posture (issue #665) -->
  {cis_bench_section}

  <!-- Attack flow graph (only when vulns exist) -->
  {_attack_flow_section(findings)}

  <!-- Vuln / Blast / Remediation -->
  {policy_section}
  {vuln_sections}

  <!-- Compliance posture -->
  {compliance_html}

</div>

<footer>
  Generated by <strong style="color:#475569">agent-bom</strong> v{_esc(report.tool_version)} &middot;
  <a href="https://github.com/msaad00/agent-bom">github.com/msaad00/agent-bom</a> &middot;
  Vulnerability data: OSV.dev &middot; NVD &middot; CISA KEV &middot; EPSS
</footer>

{SCALE_REPORT_SCRIPT}

{render_graph_script(chart_data_json, elements_json, attack_flow_json)}

</body>
</html>"""
    if offline_assets:
        # Offline mode strips the interactive script layer, so keep the report a
        # single scrollable page (no tab bar to click into a dead end).
        return _apply_offline_assets_mode(html)
    tab_counts = {
        "findings": total_vulns + len(policy_findings),
        "agents": len(report.agents),
    }
    return _apply_tabs(html, tab_counts)


def export_html(
    report: "AIBOMReport",
    output_path: str,
    blast_radii: list["BlastRadius"] | None = None,
    *,
    offline_assets: bool = False,
) -> None:
    """Write the HTML report to a file."""
    Path(output_path).write_text(to_html(report, blast_radii or [], offline_assets=offline_assets), encoding="utf-8")
