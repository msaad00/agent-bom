"""Self-contained HTML report generator for AI-BOM scans.

Produces a single ``report.html`` file with:
- Summary cards (agents / servers / packages / vulns)
- Interactive Mermaid.js dependency graph: agent → server → package → CVE
- Sortable vulnerability table with severity colour-coding
- Blast radius table with affected agents and exposed credentials
- Remediation plan ordered by blast radius score
- Credential exposure summary

No server required — open the file in any browser.
All JS/CSS is either inline or loaded from a CDN (Mermaid, Bootstrap).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius


# ─── Severity helpers ──────────────────────────────────────────────────────────

_SEV_BADGE = {
    "critical": ("danger", "CRITICAL"),
    "high": ("warning text-dark", "HIGH"),
    "medium": ("warning text-dark", "MEDIUM"),
    "low": ("secondary", "LOW"),
    "none": ("success", "NONE"),
}

_SEV_COLOR = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#6c757d",
    "none": "#198754",
}

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _badge(severity: str) -> str:
    cls, label = _SEV_BADGE.get(severity.lower(), ("secondary", severity.upper()))
    return f'<span class="badge bg-{cls}">{label}</span>'


def _esc(s: str) -> str:
    """Minimal HTML escaping."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ─── Mermaid graph ─────────────────────────────────────────────────────────────


def _mermaid_graph(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    """Generate a Mermaid flowchart definition for the agent trust chain."""
    lines = ["flowchart LR"]
    vuln_pkg_names: set[str] = {br.package.name for br in blast_radii}
    used_ids: dict[str, str] = {}

    def node_id(prefix: str, name: str) -> str:
        key = f"{prefix}:{name}"
        if key not in used_ids:
            safe = "".join(c if c.isalnum() else "_" for c in name)
            used_ids[key] = f"{prefix}_{safe}_{len(used_ids)}"
        return used_ids[key]

    for agent in report.agents:
        aid = node_id("A", agent.name)
        lines.append(f'    {aid}(["🤖 {_esc(agent.name)}"])')
        lines.append(f'    style {aid} fill:#4e73df,color:#fff,stroke:#2e59d9')

        for server in agent.mcp_servers:
            sid = node_id("S", f"{agent.name}:{server.name}")
            cred_icon = " 🔑" if server.has_credentials else ""
            lines.append(f'    {sid}["{_esc(server.name)}{cred_icon}"]')
            lines.append(f'    {aid} --> {sid}')

            if server.has_credentials:
                lines.append(f'    style {sid} fill:#e8a838,color:#000,stroke:#d49a2e')
            else:
                lines.append(f'    style {sid} fill:#1cc88a,color:#fff,stroke:#17a673')

            for pkg in server.packages:
                pid = node_id("P", f"{server.name}:{pkg.name}")
                is_vuln = pkg.name in vuln_pkg_names or pkg.has_vulnerabilities
                label = f"{_esc(pkg.name)}@{_esc(pkg.version)}"
                if is_vuln:
                    lines.append(f'    {pid}["{label} ⚠"]')
                    lines.append(f'    style {pid} fill:#e74a3b,color:#fff,stroke:#c0392b')
                else:
                    lines.append(f'    {pid}["{label}"]')
                    lines.append(f'    style {pid} fill:#36b9cc,color:#fff,stroke:#258391')
                lines.append(f'    {sid} --> {pid}')

    return "\n".join(lines)


# ─── Sections ──────────────────────────────────────────────────────────────────


def _summary_cards(report: "AIBOMReport") -> str:
    crit = len(report.critical_vulns)
    total_vulns = report.total_vulnerabilities
    cred_count = sum(
        1 for a in report.agents for s in a.mcp_servers if s.has_credentials
    )
    cards = [
        ("🤖", str(report.total_agents), "Agents", "#4e73df"),
        ("⚙️", str(report.total_servers), "MCP Servers", "#1cc88a"),
        ("📦", str(report.total_packages), "Packages", "#36b9cc"),
        ("⚠️", str(total_vulns), "Vulnerabilities", "#e74a3b" if total_vulns else "#1cc88a"),
        ("🔑", str(cred_count), "Servers with Credentials", "#e8a838" if cred_count else "#1cc88a"),
        ("🚨", str(crit), "Critical Findings", "#e74a3b" if crit else "#1cc88a"),
    ]
    cols = []
    for icon, value, label, color in cards:
        cols.append(f"""
      <div class="col-sm-6 col-md-4 col-lg-2 mb-4">
        <div class="card shadow-sm h-100 text-center">
          <div class="card-body" style="border-top:4px solid {color}">
            <div style="font-size:2rem">{icon}</div>
            <div style="font-size:2rem;font-weight:700;color:{color}">{_esc(value)}</div>
            <div class="text-muted small">{_esc(label)}</div>
          </div>
        </div>
      </div>""")
    return '<div class="row">' + "".join(cols) + "</div>"


def _vuln_table(blast_radii: list["BlastRadius"]) -> str:
    if not blast_radii:
        return '<div class="alert alert-success">✅ No vulnerabilities found.</div>'

    sorted_brs = sorted(blast_radii, key=lambda br: _SEV_ORDER.get(br.vulnerability.severity.value.lower(), 0), reverse=True)
    rows = []
    for br in sorted_brs:
        v = br.vulnerability
        sev = v.severity.value.lower()
        fix = _esc(v.fixed_version) if v.fixed_version else '<span class="text-muted">No fix yet</span>'
        cvss = f"{v.cvss_score:.1f}" if v.cvss_score else "—"
        epss = f"{v.epss_score:.1%}" if v.epss_score else "—"
        kev = '<span class="badge bg-danger">KEV</span>' if v.is_kev else "—"
        agents_html = ", ".join(_esc(a.name) for a in br.affected_agents) or "—"
        creds_html = ", ".join(_esc(c) for c in br.exposed_credentials) if br.exposed_credentials else "—"
        rows.append(f"""
      <tr>
        <td><code>{_esc(v.id)}</code></td>
        <td>{_badge(sev)}</td>
        <td><strong>{_esc(br.package.name)}</strong>@{_esc(br.package.version)}</td>
        <td>{cvss}</td>
        <td>{epss}</td>
        <td>{kev}</td>
        <td>{fix}</td>
        <td class="small">{agents_html}</td>
        <td class="small text-warning">{creds_html}</td>
      </tr>""")

    return f"""
  <table id="vulnTable" class="table table-hover table-sm align-middle" style="font-size:.875rem">
    <thead class="table-dark">
      <tr>
        <th>Vuln ID</th><th>Severity</th><th>Package</th>
        <th title="CVSS 3.x base score">CVSS</th>
        <th title="EPSS exploit probability">EPSS</th>
        <th title="CISA Known Exploited Vulnerability">KEV</th>
        <th>Fix</th><th>Affected Agents</th><th>Exposed Credentials</th>
      </tr>
    </thead>
    <tbody>{"".join(rows)}</tbody>
  </table>"""


def _blast_radius_section(blast_radii: list["BlastRadius"]) -> str:
    if not blast_radii:
        return ""
    sorted_brs = sorted(blast_radii, key=lambda br: br.risk_score, reverse=True)
    rows = []
    for br in sorted_brs:
        v = br.vulnerability
        sev = v.severity.value.lower()
        color = _SEV_COLOR.get(sev, "#6c757d")
        score = f"{br.risk_score:.2f}"
        ai_flag = '<span class="badge bg-info text-dark">AI Framework</span>' if br.ai_risk_context else ""
        rows.append(f"""
      <tr>
        <td><code>{_esc(v.id)}</code></td>
        <td>{_badge(sev)}</td>
        <td><strong style="color:{color}">{_esc(score)}</strong></td>
        <td>{len(br.affected_agents)}</td>
        <td>{len(br.exposed_credentials)}</td>
        <td>{len(br.exposed_tools)}</td>
        <td>{ai_flag}</td>
        <td class="small">{_esc(v.fixed_version or "—")}</td>
      </tr>""")
    return f"""
  <table class="table table-hover table-sm align-middle" style="font-size:.875rem">
    <thead class="table-dark">
      <tr>
        <th>Vuln ID</th><th>Severity</th><th>Blast Score</th>
        <th title="Number of agents affected">Agents Hit</th>
        <th title="Number of credentials exposed">Creds</th>
        <th title="Number of reachable MCP tools">Tools</th>
        <th>Flags</th><th>Fix</th>
      </tr>
    </thead>
    <tbody>{"".join(rows)}</tbody>
  </table>"""


def _remediation_section(blast_radii: list["BlastRadius"]) -> str:
    if not blast_radii:
        return '<div class="alert alert-success">✅ Nothing to remediate.</div>'
    with_fix = [br for br in blast_radii if br.vulnerability.fixed_version]
    no_fix = [br for br in blast_radii if not br.vulnerability.fixed_version]
    sorted_fix = sorted(with_fix, key=lambda br: br.risk_score, reverse=True)
    items = []
    for br in sorted_fix:
        v = br.vulnerability
        sev = v.severity.value.lower()
        items.append(f"""
    <li class="list-group-item">
      {_badge(sev)}
      <strong>{_esc(br.package.name)}</strong>@{_esc(br.package.version)}
      → upgrade to <code>{_esc(v.fixed_version)}</code>
      &nbsp;<span class="text-muted small">({len(br.affected_agents)} agent(s) protected, {len(br.exposed_credentials)} credential(s) freed)</span>
      <div class="text-muted small"><code>{_esc(v.id)}</code></div>
    </li>""")
    no_fix_html = ""
    if no_fix:
        nf_items = "".join(
            f'<li class="list-group-item"><code>{_esc(br.vulnerability.id)}</code> — '
            f'<strong>{_esc(br.package.name)}</strong>@{_esc(br.package.version)} '
            f'— {_badge(br.vulnerability.severity.value.lower())} — no fix yet, monitor upstream</li>'
            for br in no_fix
        )
        no_fix_html = f"""
    <h6 class="mt-4 text-muted">No fix available yet — monitor upstream</h6>
    <ul class="list-group list-group-flush">{nf_items}</ul>"""
    return f"""
    <ul class="list-group list-group-flush">{"".join(items)}</ul>
    {no_fix_html}"""


def _dep_tree_section(report: "AIBOMReport") -> str:
    agents_html = []
    for agent in report.agents:
        servers_html = []
        for server in agent.mcp_servers:
            pkgs_html = "".join(
                f'<li class="list-group-item py-1 border-0">'
                f'<span class="badge bg-{"danger" if p.has_vulnerabilities else "info"} me-1">'
                f'{"⚠" if p.has_vulnerabilities else "📦"}</span>'
                f'<code>{_esc(p.ecosystem)}:{_esc(p.name)}@{_esc(p.version)}</code>'
                f'{"<span class=text-danger ms-1>"+str(len(p.vulnerabilities))+" vuln(s)</span>" if p.has_vulnerabilities else ""}'
                f'</li>'
                for p in server.packages
            )
            creds_html = "".join(
                f'<li class="list-group-item py-1 border-0 text-warning">'
                f'🔑 <code>{_esc(c)}</code></li>'
                for c in server.credential_names
            )
            cmd = f"{_esc(server.command)} {' '.join(_esc(a) for a in server.args[:3])}" if server.command else ""
            servers_html.append(f"""
        <div class="card mb-2 border-0 bg-light">
          <div class="card-body py-2">
            <strong>⚙️ {_esc(server.name)}</strong>
            {"<span class='badge bg-warning text-dark ms-2'>🔑 Credentials</span>" if server.has_credentials else ""}
            {"<span class='badge bg-danger ms-2'>⚠ Vulns</span>" if any(p.has_vulnerabilities for p in server.packages) else ""}
            <div class="text-muted small mt-1"><code>{cmd}</code></div>
            <ul class="list-group list-group-flush mt-1">{pkgs_html}{creds_html}</ul>
          </div>
        </div>""")
        agents_html.append(f"""
      <div class="col-md-6 mb-4">
        <div class="card shadow-sm">
          <div class="card-header bg-primary text-white">
            🤖 <strong>{_esc(agent.name)}</strong>
            <span class="badge bg-light text-dark ms-2">{agent.agent_type.value}</span>
            <div class="small text-white-50 mt-1">{_esc(agent.config_path or "")}</div>
          </div>
          <div class="card-body">{"".join(servers_html) or "<p class=text-muted>No MCP servers.</p>"}</div>
        </div>
      </div>""")
    return '<div class="row">' + "".join(agents_html) + "</div>"


# ─── Main HTML builder ─────────────────────────────────────────────────────────


def to_html(report: "AIBOMReport", blast_radii: list["BlastRadius"] | None = None) -> str:
    """Generate a self-contained HTML report string."""
    blast_radii = blast_radii or []
    generated = report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    graph = _mermaid_graph(report, blast_radii)

    # Embed scan data as JSON for potential future JS use
    report_json_str = json.dumps({
        "generated_at": report.generated_at.isoformat(),
        "tool_version": report.tool_version,
        "summary": {
            "total_agents": report.total_agents,
            "total_servers": report.total_servers,
            "total_packages": report.total_packages,
            "total_vulnerabilities": report.total_vulnerabilities,
            "critical_findings": len(report.critical_vulns),
        },
    }, indent=2)

    status_color = "#dc3545" if len(report.critical_vulns) else ("#ffc107" if report.total_vulnerabilities else "#198754")
    status_label = "CRITICAL FINDINGS" if len(report.critical_vulns) else ("VULNERABILITIES FOUND" if report.total_vulnerabilities else "CLEAN")

    vuln_nav = "" if not blast_radii else """
      <li class="nav-item"><a class="nav-link" href="#vulns">Vulnerabilities</a></li>
      <li class="nav-item"><a class="nav-link" href="#blast">Blast Radius</a></li>
      <li class="nav-item"><a class="nav-link" href="#remediation">Remediation</a></li>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>agent-bom AI-BOM Report — {_esc(generated)}</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #f8f9fc; }}
    .navbar-brand {{ font-weight: 700; letter-spacing: .04em; }}
    .mermaid {{ background: #fff; border-radius: 8px; padding: 1rem; overflow-x: auto; }}
    .section-heading {{ border-left: 4px solid #4e73df; padding-left: .75rem; margin: 2rem 0 1rem; }}
    .status-pill {{
      display: inline-block; padding: .25rem .75rem; border-radius: 999px;
      font-weight: 600; font-size: .85rem; color: #fff;
      background: {status_color};
    }}
    code {{ color: #d63384; }}
    th {{ white-space: nowrap; }}
    #vulnTable td {{ vertical-align: middle; }}
  </style>
</head>
<body>

<nav class="navbar navbar-dark" style="background:#4e73df">
  <div class="container-fluid">
    <span class="navbar-brand">🛡️ agent-bom AI-BOM Report</span>
    <span class="status-pill">{status_label}</span>
  </div>
</nav>

<div class="container-fluid py-4">

  <!-- Meta -->
  <div class="row mb-2 align-items-center">
    <div class="col">
      <span class="text-muted">Generated: <strong>{_esc(generated)}</strong>
      &nbsp;·&nbsp; agent-bom v{_esc(report.tool_version)}</span>
    </div>
  </div>

  <!-- Nav pills -->
  <ul class="nav nav-pills mb-4">
    <li class="nav-item"><a class="nav-link active" href="#summary">Summary</a></li>
    <li class="nav-item"><a class="nav-link" href="#graph">Dependency Graph</a></li>
    <li class="nav-item"><a class="nav-link" href="#inventory">Inventory</a></li>
    {vuln_nav}
  </ul>

  <!-- Summary cards -->
  <h2 class="section-heading" id="summary">Summary</h2>
  {_summary_cards(report)}

  <!-- Dependency graph -->
  <h2 class="section-heading" id="graph">Dependency Graph</h2>
  <div class="card shadow-sm mb-4">
    <div class="card-body">
      <p class="text-muted small mb-2">
        🤖 Agent → ⚙️ MCP Server → 📦 Package.
        <span style="color:#e74a3b">⚠ Red = vulnerable</span> ·
        <span style="color:#e8a838">🟡 Orange = has credentials</span> ·
        <span style="color:#1cc88a">🟢 Green = clean</span>
      </p>
      <div class="mermaid">
{graph}
      </div>
    </div>
  </div>

  <!-- Inventory tree -->
  <h2 class="section-heading" id="inventory">Agent Inventory</h2>
  {_dep_tree_section(report)}

  <!-- Vulnerabilities -->
  {"" if not blast_radii else f'''
  <h2 class="section-heading" id="vulns">Vulnerabilities</h2>
  <div class="card shadow-sm mb-4">
    <div class="card-body table-responsive">
      {_vuln_table(blast_radii)}
    </div>
  </div>

  <!-- Blast radius -->
  <h2 class="section-heading" id="blast">Blast Radius Analysis</h2>
  <p class="text-muted small">Score boosted by KEV (+1.0), high EPSS (+0.5), AI framework (+0.5). Higher = fix first.</p>
  <div class="card shadow-sm mb-4">
    <div class="card-body table-responsive">
      {_blast_radius_section(blast_radii)}
    </div>
  </div>

  <!-- Remediation -->
  <h2 class="section-heading" id="remediation">Remediation Plan</h2>
  <div class="card shadow-sm mb-4">
    <div class="card-body">
      {_remediation_section(blast_radii)}
    </div>
  </div>
  '''}

  <!-- Footer -->
  <footer class="text-center text-muted small py-4 mt-4 border-top">
    Generated by <strong>agent-bom</strong> v{_esc(report.tool_version)} ·
    <a href="https://github.com/agent-bom/agent-bom" target="_blank">github.com/agent-bom/agent-bom</a>
  </footer>

</div>

<script>
  mermaid.initialize({{ startOnLoad: true, theme: 'default', flowchart: {{ curve: 'basis' }} }});
  // Smooth scroll for nav links
  document.querySelectorAll('a[href^="#"]').forEach(a => {{
    a.addEventListener('click', e => {{
      e.preventDefault();
      document.querySelector(a.getAttribute('href'))?.scrollIntoView({{ behavior: 'smooth' }});
    }});
  }});
</script>

<!-- Embedded scan data (JSON) -->
<script type="application/json" id="agentBomData">
{report_json_str}
</script>

</body>
</html>"""


def export_html(report: "AIBOMReport", output_path: str, blast_radii: list["BlastRadius"] | None = None) -> None:
    """Write the HTML report to a file."""
    Path(output_path).write_text(to_html(report, blast_radii or []), encoding="utf-8")
