"""Self-contained HTML report generator for AI-BOM scans.

Produces a single ``report.html`` file with:
- Professional dark-theme dashboard (no bright cartoon colors)
- Interactive Cytoscape.js dependency graph (drag, zoom, hover tooltips, click-to-highlight)
  agent → MCP server → package, coloured by vulnerability/credential status
- Enrichment hint when CVSS/description data is missing (run with --enrich)
- Sortable vulnerability table with severity pill, CVSS bar, EPSS, KEV badge
- Blast radius table with visual score bar ordered by risk score
- Remediation plan ordered by impact: agents protected × credentials freed

No server required — open the file in any browser.
Cytoscape.js loaded from unpkg CDN; everything else is inline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius


_SEV_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#6b7280",
    "none": "#16a34a",
}
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _sev_badge(sev: str) -> str:
    color = _SEV_COLOR.get(sev.lower(), "#6b7280")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;'
        f'font-size:.72rem;font-weight:700;letter-spacing:.04em">{sev.upper()}</span>'
    )


def _esc(s: object) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ─── Cytoscape elements ───────────────────────────────────────────────────────


def _cytoscape_elements(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    elements: list[dict] = []
    vuln_pkg_names = {br.package.name for br in blast_radii}
    seen_pkg_ids: set[str] = set()

    for agent in report.agents:
        aid = f"a{id(agent)}"
        elements.append({"data": {
            "id": aid, "label": agent.name, "type": "agent",
            "tip": f"Agent: {agent.name}\nType: {agent.agent_type.value}\nServers: {len(agent.mcp_servers)}",
        }})
        for srv in agent.mcp_servers:
            sid = f"s{id(srv)}"
            has_vuln = any(p.has_vulnerabilities or p.name in vuln_pkg_names for p in srv.packages)
            stype = "server_vuln" if has_vuln else ("server_cred" if srv.has_credentials else "server_clean")
            cinfo = f"\nCredentials: {', '.join(srv.credential_names)}" if srv.has_credentials else ""
            elements.append({"data": {
                "id": sid,
                "label": srv.name + (" 🔑" if srv.has_credentials else ""),
                "type": stype,
                "tip": f"MCP Server: {srv.name}\nPackages: {len(srv.packages)}{cinfo}",
            }})
            elements.append({"data": {"source": aid, "target": sid}})
            for pkg in srv.packages:
                pid = f"p{pkg.name}{pkg.ecosystem}"
                is_vuln = pkg.has_vulnerabilities or pkg.name in vuln_pkg_names
                ptype = "pkg_vuln" if is_vuln else "pkg_clean"
                if pid not in seen_pkg_ids:
                    seen_pkg_ids.add(pid)
                    vc = len(pkg.vulnerabilities)
                    elements.append({"data": {
                        "id": pid,
                        "label": f"{pkg.name}\n{pkg.version}",
                        "type": ptype,
                        "tip": f"Package: {pkg.name}\nVersion: {pkg.version}\nEcosystem: {pkg.ecosystem}"
                               + (f"\nVulnerabilities: {vc}" if vc else ""),
                    }})
                elements.append({"data": {"source": sid, "target": pid}})
    return json.dumps(elements)


# ─── HTML sections ────────────────────────────────────────────────────────────


def _summary_cards(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    crit = len(report.critical_vulns)
    total_vulns = report.total_vulnerabilities
    cred_count = sum(1 for a in report.agents for s in a.mcp_servers if s.has_credentials)

    def card(icon: str, value: str, label: str, accent: str) -> str:
        return (
            f'<div style="background:#1e293b;border-radius:8px;padding:20px 24px;'
            f'border-left:4px solid {accent};min-width:130px">'
            f'<div style="font-size:1.5rem">{icon}</div>'
            f'<div style="font-size:1.9rem;font-weight:700;color:{accent};line-height:1.1">{_esc(value)}</div>'
            f'<div style="font-size:.7rem;color:#64748b;margin-top:4px;letter-spacing:.04em;text-transform:uppercase">{label}</div>'
            f'</div>'
        )

    return '<div style="display:flex;gap:14px;flex-wrap:wrap">' + "".join([
        card("🤖", str(report.total_agents),   "Agents",          "#60a5fa"),
        card("⚙️",  str(report.total_servers),  "MCP Servers",     "#34d399"),
        card("📦", str(report.total_packages), "Packages",        "#38bdf8"),
        card("⚠️",  str(total_vulns),           "Vulnerabilities", "#f87171" if total_vulns else "#34d399"),
        card("🔑", str(cred_count),            "With Credentials","#fbbf24" if cred_count else "#34d399"),
        card("🚨", str(crit),                  "Critical",        "#ef4444" if crit else "#34d399"),
    ]) + "</div>"


def _vuln_table(blast_radii: list["BlastRadius"]) -> str:
    if not blast_radii:
        return (
            '<div style="background:#052e1620;border:1px solid #16a34a40;border-radius:8px;'
            'padding:20px;color:#4ade80;text-align:center;font-size:.9rem">'
            '✅ No vulnerabilities found in scanned packages.</div>'
        )

    has_missing = any(not br.vulnerability.cvss_score or not br.vulnerability.summary for br in blast_radii)
    hint = ""
    if has_missing:
        hint = (
            '<div style="background:#1e3a5f;border:1px solid #3b82f660;border-radius:6px;'
            'padding:12px 16px;margin-bottom:16px;font-size:.82rem;color:#93c5fd">'
            '💡 <strong>Some entries are missing CVSS scores or descriptions.</strong> '
            'Run with <code style="background:#0f172a;padding:1px 5px;border-radius:3px">--enrich</code> '
            'to fetch full NVD metadata, CVSS 3.x vectors, EPSS exploit probability, and CISA KEV status.'
            '</div>'
        )

    th = "padding:9px 12px;font-size:.68rem;letter-spacing:.06em;color:#64748b;font-weight:700;text-transform:uppercase;border-bottom:1px solid #334155;white-space:nowrap"
    td = "padding:9px 12px;border-bottom:1px solid #1e293b;vertical-align:middle"

    sorted_brs = sorted(blast_radii, key=lambda b: _SEV_ORDER.get(b.vulnerability.severity.value.lower(), 0), reverse=True)
    rows = []
    for br in sorted_brs:
        v = br.vulnerability
        sev = v.severity.value.lower()
        cvss = f'<strong style="color:{_SEV_COLOR.get(sev,"#6b7280")}">{v.cvss_score:.1f}</strong>' if v.cvss_score else '<span style="color:#334155">—</span>'
        epss = f'{v.epss_score:.1%}' if v.epss_score else '<span style="color:#334155">—</span>'
        kev = ('<span style="background:#7f1d1d;color:#fca5a5;padding:1px 6px;border-radius:3px;'
               'font-size:.68rem;font-weight:700">KEV</span>') if v.is_kev else '<span style="color:#334155">—</span>'
        fix = (f'<code style="color:#4ade80">{_esc(v.fixed_version)}</code>' if v.fixed_version
               else '<span style="color:#475569">No fix yet</span>')
        summary = _esc((v.summary or "")[:90]) or '<span style="color:#475569;font-style:italic">Run --enrich for details</span>'
        agents_s = ", ".join(_esc(a.name) for a in br.affected_agents) or "<span style='color:#334155'>—</span>"
        creds_s = ", ".join(f'<code style="color:#fbbf24">{_esc(c)}</code>' for c in br.exposed_credentials) or "<span style='color:#334155'>—</span>"
        rows.append(
            f'<tr>'
            f'<td style="{td}"><code style="color:#93c5fd;font-size:.78rem">{_esc(v.id)}</code></td>'
            f'<td style="{td}">{_sev_badge(sev)}</td>'
            f'<td style="{td}"><strong style="color:#e2e8f0">{_esc(br.package.name)}</strong>'
            f'<span style="color:#475569">@{_esc(br.package.version)}</span></td>'
            f'<td style="{td};text-align:center">{cvss}</td>'
            f'<td style="{td};text-align:center;color:#94a3b8;font-size:.82rem">{epss}</td>'
            f'<td style="{td};text-align:center">{kev}</td>'
            f'<td style="{td}">{fix}</td>'
            f'<td style="{td};font-size:.78rem;color:#94a3b8">{agents_s}</td>'
            f'<td style="{td};font-size:.78rem">{creds_s}</td>'
            f'<td style="{td};font-size:.75rem;color:#64748b;max-width:200px">{summary}</td>'
            f'</tr>'
        )

    return (
        hint
        + '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.83rem">'
        + '<thead style="background:#0f172a"><tr>'
        + "".join(f'<th style="{th}">{h}</th>' for h in [
            "Vuln ID", "Severity", "Package", "CVSS", "EPSS", "KEV", "Fix",
            "Affected Agents", "Exposed Creds", "Summary"])
        + "</tr></thead>"
        + f'<tbody>{"".join(rows)}</tbody></table></div>'
    )


def _blast_table(blast_radii: list["BlastRadius"]) -> str:
    if not blast_radii:
        return ""
    th = "padding:9px 12px;font-size:.68rem;letter-spacing:.06em;color:#64748b;font-weight:700;text-transform:uppercase;border-bottom:1px solid #334155;white-space:nowrap"
    td = "padding:9px 12px;border-bottom:1px solid #1e293b;vertical-align:middle"
    sorted_brs = sorted(blast_radii, key=lambda b: b.risk_score, reverse=True)
    rows = []
    for i, br in enumerate(sorted_brs, 1):
        v = br.vulnerability
        sev = v.severity.value.lower()
        color = _SEV_COLOR.get(sev, "#6b7280")
        bar = int(br.risk_score * 8)
        ai = ('<span style="background:#1d4ed8;color:#bfdbfe;padding:2px 6px;border-radius:3px;'
              'font-size:.68rem;font-weight:700">AI</span>') if br.ai_risk_context else ""
        fix = (f'<code style="color:#4ade80;font-size:.8rem">{_esc(v.fixed_version)}</code>'
               if v.fixed_version else '<span style="color:#475569">—</span>')
        rows.append(
            f'<tr><td style="{td};color:#475569;font-weight:600">#{i}</td>'
            f'<td style="{td}"><code style="color:#93c5fd;font-size:.78rem">{_esc(v.id)}</code></td>'
            f'<td style="{td}">{_sev_badge(sev)}</td>'
            f'<td style="{td}">'
            f'<div style="display:flex;align-items:center;gap:8px">'
            f'<div style="background:#0f172a;border-radius:3px;height:5px;width:80px">'
            f'<div style="background:{color};border-radius:3px;height:5px;width:{bar}px"></div></div>'
            f'<strong style="color:{color};font-size:.9rem">{br.risk_score:.1f}</strong></div></td>'
            f'<td style="{td};text-align:center;color:#e2e8f0">{len(br.affected_agents)}</td>'
            f'<td style="{td};text-align:center;color:#fbbf24">{len(br.exposed_credentials)}</td>'
            f'<td style="{td};text-align:center;color:#94a3b8">{len(br.exposed_tools)}</td>'
            f'<td style="{td}">{ai}</td>'
            f'<td style="{td}">{fix}</td></tr>'
        )
    return (
        '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.83rem">'
        + '<thead style="background:#0f172a"><tr>'
        + "".join(f'<th style="{th}">{h}</th>' for h in [
            "#", "Vuln ID", "Severity", "Blast Score (0–10)",
            "Agents Hit", "Creds Exposed", "Tools Reachable", "Flags", "Fix"])
        + f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
    )


def _remediation_list(blast_radii: list["BlastRadius"]) -> str:
    if not blast_radii:
        return '<p style="color:#4ade80">✅ Nothing to remediate.</p>'
    with_fix = sorted([b for b in blast_radii if b.vulnerability.fixed_version], key=lambda b: b.risk_score, reverse=True)
    no_fix = [b for b in blast_radii if not b.vulnerability.fixed_version]
    items = []
    for br in with_fix:
        v = br.vulnerability
        items.append(
            f'<div style="display:flex;align-items:flex-start;gap:14px;padding:14px 0;border-bottom:1px solid #1e293b">'
            f'<div style="flex-shrink:0;padding-top:1px">{_sev_badge(v.severity.value.lower())}</div>'
            f'<div style="flex:1">'
            f'<div style="color:#e2e8f0;font-weight:600">{_esc(br.package.name)}'
            f'<span style="color:#475569;font-weight:400">@{_esc(br.package.version)}</span></div>'
            f'<div style="font-size:.8rem;color:#64748b;margin-top:3px">'
            f'<code style="color:#93c5fd">{_esc(v.id)}</code> · upgrade to '
            f'<code style="color:#4ade80">{_esc(v.fixed_version)}</code>'
            f' · protects {len(br.affected_agents)} agent(s)'
            + (f' · frees {len(br.exposed_credentials)} credential(s)' if br.exposed_credentials else "")
            + f'</div></div>'
            f'<div style="flex-shrink:0;color:#475569;font-size:.78rem;padding-top:3px">score&nbsp;{br.risk_score:.1f}</div>'
            f'</div>'
        )
    nf_html = ""
    if no_fix:
        nf_rows = "".join(
            f'<div style="padding:9px 0;border-bottom:1px solid #1e293b;font-size:.82rem">'
            f'{_sev_badge(b.vulnerability.severity.value.lower())} '
            f'<code style="color:#93c5fd">{_esc(b.vulnerability.id)}</code> — '
            f'<strong style="color:#e2e8f0">{_esc(b.package.name)}</strong>@{_esc(b.package.version)} '
            f'— <span style="color:#475569">no fix available yet — monitor upstream</span></div>'
            for b in no_fix
        )
        nf_html = (
            '<div style="margin-top:20px">'
            '<div style="font-size:.7rem;letter-spacing:.07em;text-transform:uppercase;color:#64748b;margin-bottom:8px">No Fix Available</div>'
            + nf_rows + '</div>'
        )
    return "".join(items) + nf_html


def _inventory_cards(report: "AIBOMReport") -> str:
    cards = []
    for agent in report.agents:
        servers = []
        for srv in agent.mcp_servers:
            vuln_pkgs = [p for p in srv.packages if p.has_vulnerabilities]
            pkgs_html = "".join(
                f'<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #0f172a;font-size:.78rem">'
                f'<span><code style="color:{"#f87171" if p.has_vulnerabilities else "#38bdf8"};font-size:.75rem">{_esc(p.ecosystem)}</code>'
                f' <span style="color:#e2e8f0">{_esc(p.name)}</span></span>'
                f'<span style="color:#64748b">{_esc(p.version)}'
                f'{"&nbsp;⚠" if p.has_vulnerabilities else ""}</span></div>'
                for p in srv.packages
            )
            creds_html = "".join(
                f'<div style="font-size:.74rem;color:#fbbf24;padding:3px 0">🔑 <code>{_esc(c)}</code></div>'
                for c in srv.credential_names
            )
            accent = "#ef4444" if vuln_pkgs else ("#f59e0b" if srv.has_credentials else "#334155")
            cmd = f"{_esc(srv.command)} {_esc(' '.join(srv.args[:3]))}" if srv.command else ""
            servers.append(
                f'<div style="background:#0f172a;border-radius:6px;padding:12px;margin-bottom:8px;border-left:3px solid {accent}">'
                f'<div style="font-weight:600;color:#e2e8f0;margin-bottom:5px;font-size:.9rem">⚙️ {_esc(srv.name)}'
                + ('&nbsp;<span style="background:#7f1d1d;color:#fca5a5;font-size:.65rem;padding:1px 5px;border-radius:3px;font-weight:700">VULN</span>' if vuln_pkgs else "")
                + ('&nbsp;<span style="background:#78350f;color:#fde68a;font-size:.65rem;padding:1px 5px;border-radius:3px;font-weight:700">CREDS</span>' if srv.has_credentials else "")
                + f'</div>'
                f'<div style="font-size:.72rem;color:#475569;font-family:monospace;margin-bottom:7px">{cmd}</div>'
                f'{pkgs_html}{creds_html}</div>'
            )
        cards.append(
            f'<div style="background:#1e293b;border-radius:10px;padding:20px;margin-bottom:14px">'
            f'<div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:12px">'
            f'<div><div style="font-weight:700;font-size:1rem;color:#f1f5f9">🤖 {_esc(agent.name)}</div>'
            f'<div style="font-size:.72rem;color:#475569;margin-top:2px">{_esc(agent.agent_type.value)} · {_esc(agent.config_path or "")}</div></div>'
            f'<div style="font-size:.72rem;color:#334155">{len(agent.mcp_servers)} server(s)</div></div>'
            + ("".join(servers) if servers else '<p style="color:#334155;font-size:.85rem">No MCP servers.</p>')
            + '</div>'
        )
    return "".join(cards)


# ─── Main assembler ───────────────────────────────────────────────────────────


def to_html(report: "AIBOMReport", blast_radii: list["BlastRadius"] | None = None) -> str:
    blast_radii = blast_radii or []
    generated = report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    elements_json = _cytoscape_elements(report, blast_radii)
    crit = len(report.critical_vulns)
    total_vulns = report.total_vulnerabilities

    if crit:
        status_color, status_label = "#dc2626", "CRITICAL FINDINGS"
    elif total_vulns:
        status_color, status_label = "#d97706", "VULNERABILITIES FOUND"
    else:
        status_color, status_label = "#16a34a", "CLEAN"

    vuln_nav = ("" if not blast_radii else
                "<a href='#vulns'>Vulnerabilities</a>"
                "<a href='#blast'>Blast Radius</a>"
                "<a href='#remediation'>Remediation</a>")

    vuln_sections = ""
    if blast_radii:
        def sec(anchor: str, title: str, content: str) -> str:
            return (
                f'<section id="{anchor}" style="margin-bottom:48px">'
                f'<div class="sec-title">{title}</div>'
                f'<div style="background:#1e293b;border-radius:10px;padding:20px">{content}</div>'
                f'</section>'
            )
        vuln_sections = (
            sec("vulns", f"⚠️ Vulnerabilities &nbsp;<sup style='font-size:.7rem;color:#475569'>{len(blast_radii)}</sup>", _vuln_table(blast_radii))
            + sec("blast",
                  "💥 Blast Radius &nbsp;<sup style='font-size:.7rem;color:#475569'>risk = CVSS + agents + creds + tools + KEV/EPSS/AI boosts (max 10)</sup>",
                  _blast_table(blast_radii))
            + sec("remediation", "🔧 Remediation Plan", _remediation_list(blast_radii))
        )

    meta_json = json.dumps({
        "generated_at": report.generated_at.isoformat(),
        "tool_version": report.tool_version,
        "summary": {
            "total_agents": report.total_agents,
            "total_servers": report.total_servers,
            "total_packages": report.total_packages,
            "total_vulnerabilities": total_vulns,
            "critical_findings": crit,
        },
    }, indent=2)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>agent-bom AI-BOM — {_esc(generated)}</title>
  <script src="https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"></script>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#cbd5e1;line-height:1.5;font-size:14px}}
    a{{color:#60a5fa;text-decoration:none}}a:hover{{text-decoration:underline}}
    code{{font-family:"SF Mono","Cascadia Code",Consolas,monospace;font-size:.9em}}
    nav{{background:#0f172a;border-bottom:1px solid #1e293b;padding:0 28px;display:flex;align-items:center;gap:20px;height:52px;position:sticky;top:0;z-index:100}}
    .brand{{font-weight:700;font-size:.95rem;color:#f1f5f9;letter-spacing:-.01em}}
    .status{{padding:3px 10px;border-radius:4px;font-size:.7rem;font-weight:700;letter-spacing:.05em;background:{status_color}18;color:{status_color};border:1px solid {status_color}35}}
    .navlinks{{display:flex;gap:2px;margin-left:auto}}
    .navlinks a{{color:#475569;font-size:.8rem;padding:4px 9px;border-radius:4px}}
    .navlinks a:hover{{background:#1e293b;color:#e2e8f0;text-decoration:none}}
    .container{{max-width:1400px;margin:0 auto;padding:28px 28px 72px}}
    .sec-title{{font-size:.82rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#64748b;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #1e293b}}
    section{{margin-bottom:44px}}
    #cy{{width:100%;height:460px;background:#1e293b;border-radius:10px}}
    .legend{{display:flex;gap:18px;flex-wrap:wrap;font-size:.75rem;color:#64748b;margin-top:10px}}
    .legend span{{display:flex;align-items:center;gap:5px}}
    .legend i{{display:inline-block;width:9px;height:9px;border-radius:50%}}
    #tip{{position:fixed;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 11px;font-size:.75rem;color:#e2e8f0;pointer-events:none;white-space:pre-line;max-width:240px;z-index:9999;display:none;line-height:1.45}}
    footer{{border-top:1px solid #1e293b;padding:20px 28px;text-align:center;font-size:.75rem;color:#334155}}
  </style>
</head>
<body>

<nav>
  <span class="brand">🛡️ agent-bom</span>
  <span class="status">{status_label}</span>
  <span style="color:#334155;font-size:.75rem">{_esc(generated)} · v{_esc(report.tool_version)}</span>
  <div class="navlinks">
    <a href="#summary">Summary</a>
    <a href="#graph">Graph</a>
    <a href="#inventory">Inventory</a>
    {vuln_nav}
  </div>
</nav>

<div id="tip"></div>

<div class="container">

  <section id="summary" style="margin-bottom:44px">
    <div class="sec-title">Summary</div>
    {_summary_cards(report, blast_radii)}
    {"" if blast_radii else '<div style="margin-top:18px;background:#052e1618;border:1px solid #16a34a30;border-radius:8px;padding:14px;color:#4ade80;font-size:.85rem">✅ No vulnerabilities found. All scanned packages are clean.</div>'}
  </section>

  <section id="graph" style="margin-bottom:44px">
    <div class="sec-title">Dependency Graph &nbsp;<span style="font-size:.68rem;font-weight:400;opacity:.5">drag · scroll to zoom · hover for details · click to highlight</span></div>
    <div id="cy"></div>
    <div class="legend">
      <span><i style="background:#3b82f6"></i>Agent</span>
      <span><i style="background:#10b981"></i>Server (clean)</span>
      <span><i style="background:#f59e0b"></i>Server (credentials)</span>
      <span><i style="background:#ef4444"></i>Vulnerable</span>
      <span><i style="background:#0ea5e9"></i>Package (clean)</span>
    </div>
  </section>

  <section id="inventory" style="margin-bottom:44px">
    <div class="sec-title">Agent Inventory</div>
    {_inventory_cards(report)}
  </section>

  {vuln_sections}

</div>

<footer>
  Generated by <strong style="color:#475569">agent-bom</strong> v{_esc(report.tool_version)} ·
  <a href="https://github.com/agent-bom/agent-bom">github.com/agent-bom/agent-bom</a> ·
  <span>Vulnerability data: OSV.dev · NVD · CISA KEV · EPSS</span>
</footer>

<script type="application/json" id="agentBomData">{meta_json}</script>
<script>
(function(){{
  var cy=cytoscape({{
    container:document.getElementById('cy'),
    elements:{elements_json},
    style:[
      {{selector:'node[type="agent"]',style:{{'background-color':'#1e3a8a','border-color':'#3b82f6','border-width':2,'label':'data(label)','color':'#bfdbfe','font-size':'11px','font-weight':'600','text-valign':'center','text-halign':'center','width':88,'height':34,'shape':'round-rectangle','text-wrap':'wrap','text-max-width':'78px'}}}},
      {{selector:'node[type="server_clean"]',style:{{'background-color':'#052e16','border-color':'#10b981','border-width':2,'label':'data(label)','color':'#6ee7b7','font-size':'10px','text-valign':'center','text-halign':'center','width':78,'height':30,'shape':'round-rectangle','text-wrap':'wrap','text-max-width':'70px'}}}},
      {{selector:'node[type="server_cred"]',style:{{'background-color':'#431407','border-color':'#f59e0b','border-width':2,'label':'data(label)','color':'#fde68a','font-size':'10px','text-valign':'center','text-halign':'center','width':78,'height':30,'shape':'round-rectangle','text-wrap':'wrap','text-max-width':'70px'}}}},
      {{selector:'node[type="server_vuln"]',style:{{'background-color':'#450a0a','border-color':'#ef4444','border-width':2,'label':'data(label)','color':'#fca5a5','font-size':'10px','text-valign':'center','text-halign':'center','width':78,'height':30,'shape':'round-rectangle','text-wrap':'wrap','text-max-width':'70px'}}}},
      {{selector:'node[type="pkg_clean"]',style:{{'background-color':'#082f49','border-color':'#0ea5e9','border-width':1,'label':'data(label)','color':'#bae6fd','font-size':'9px','text-valign':'center','text-halign':'center','width':96,'height':32,'shape':'round-rectangle','text-wrap':'wrap','text-max-width':'88px'}}}},
      {{selector:'node[type="pkg_vuln"]',style:{{'background-color':'#450a0a','border-color':'#dc2626','border-width':2,'label':'data(label)','color':'#fca5a5','font-size':'9px','font-weight':'700','text-valign':'center','text-halign':'center','width':96,'height':32,'shape':'round-rectangle','text-wrap':'wrap','text-max-width':'88px'}}}},
      {{selector:'edge',style:{{'width':1,'line-color':'#1e293b','target-arrow-color':'#334155','target-arrow-shape':'triangle','curve-style':'bezier','arrow-scale':0.7}}}},
      {{selector:'.faded',style:{{'opacity':0.12}}}},
    ],
    layout:{{name:'breadthfirst',directed:true,padding:20,spacingFactor:1.3}},
    minZoom:0.25,maxZoom:4,
  }});
  cy.ready(function(){{cy.fit(cy.elements(),20);}});

  var tip=document.getElementById('tip');
  cy.on('mouseover','node',function(e){{var t=e.target.data('tip');if(t){{tip.textContent=t;tip.style.display='block';}}}});
  cy.on('mousemove',function(e){{if(tip.style.display==='block'){{tip.style.left=(e.originalEvent.clientX+12)+'px';tip.style.top=(e.originalEvent.clientY+12)+'px';}}}});
  cy.on('mouseout','node',function(){{tip.style.display='none';}});
  cy.on('tap','node',function(e){{
    cy.elements().removeClass('faded');
    var nb=e.target.closedNeighborhood();
    cy.elements().not(nb).addClass('faded');
  }});
  cy.on('tap',function(e){{if(e.target===cy)cy.elements().removeClass('faded');}});
  document.querySelectorAll('a[href^="#"]').forEach(function(a){{
    a.addEventListener('click',function(e){{e.preventDefault();var el=document.querySelector(a.getAttribute('href'));if(el)el.scrollIntoView({{behavior:'smooth',block:'start'}});}});
  }});
}})();
</script>
</body>
</html>"""


def export_html(
    report: "AIBOMReport",
    output_path: str,
    blast_radii: list["BlastRadius"] | None = None,
) -> None:
    """Write the HTML report to a file."""
    Path(output_path).write_text(to_html(report, blast_radii or []), encoding="utf-8")
