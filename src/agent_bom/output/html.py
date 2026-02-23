"""Self-contained HTML report generator for AI-BOM scans.

Produces a single ``report.html`` file with:
- Enterprise dashboard: stat cards, severity donut, blast radius bar chart
- Hierarchical Cytoscape.js risk map (dagre layout: Provider → Agent → Server → Package → CVE)
  with zoom controls, fullscreen toggle, and node highlighting
- Collapsible agent inventory panels with search and truncated package lists
- Sortable vulnerability table with severity pill, CVSS bar, EPSS, KEV badge
- Blast radius table ordered by risk score with visual bar
- Remediation plan ordered by impact
- Skill audit findings section (when skill scan data is present)
- Print-friendly stylesheet for PDF export

No server required — open the file in any browser.
Chart.js + Cytoscape.js + dagre loaded from CDN; everything else is inline.
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

# Max packages shown per server before collapsing
_PKG_PREVIEW = 15


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


# ─── Data builders ────────────────────────────────────────────────────────────


def _chart_data(blast_radii: list["BlastRadius"]) -> str:
    """Build Chart.js dataset JSON for severity donut + blast radius bar chart."""
    from agent_bom.models import Severity

    sev_counts: dict[str, int] = {s.value: 0 for s in Severity if s != Severity.NONE}
    for br in blast_radii:
        sev = br.vulnerability.severity.value
        if sev in sev_counts:
            sev_counts[sev] += 1

    top10 = sorted(blast_radii, key=lambda b: b.risk_score, reverse=True)[:10]
    blast_labels = [f"{br.vulnerability.id[:16]}/{br.package.name[:14]}" for br in top10]
    blast_scores = [round(br.risk_score, 2) for br in top10]
    blast_colors = [_SEV_COLOR.get(br.vulnerability.severity.value.lower(), "#6b7280") for br in top10]

    return json.dumps({
        "sev": {
            "labels": [k.capitalize() for k in sev_counts],
            "data": list(sev_counts.values()),
            "colors": [_SEV_COLOR[k] for k in sev_counts],
        },
        "blast": {
            "labels": blast_labels,
            "scores": blast_scores,
            "colors": blast_colors,
        },
    })


def _cytoscape_elements(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    """Build Cytoscape element list using the shared graph builder."""
    from agent_bom.output.graph import build_graph_elements

    elements = build_graph_elements(report, blast_radii, include_cve_nodes=True)
    return json.dumps(elements)


def _attack_flow_elements(blast_radii: list["BlastRadius"]) -> str:
    """Build attack flow element list showing CVE → impact propagation."""
    from agent_bom.output.graph import build_attack_flow_elements

    elements = build_attack_flow_elements(blast_radii)
    return json.dumps(elements)


# ─── HTML sections ────────────────────────────────────────────────────────────


def _summary_cards(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    crit = sum(1 for br in blast_radii if br.vulnerability.severity.value == "critical")
    total_vulns = len(blast_radii)
    cred_servers = sum(1 for a in report.agents for s in a.mcp_servers if s.has_credentials)
    kev_count = sum(1 for br in blast_radii if br.vulnerability.is_kev)

    def card(icon: str, value: str, label: str, accent: str, sub: str = "") -> str:
        sub_html = f'<div style="font-size:.68rem;color:#475569;margin-top:2px">{sub}</div>' if sub else ""
        return (
            f'<div class="stat-card" style="border-left-color:{accent}">'
            f'<div class="stat-icon">{icon}</div>'
            f'<div class="stat-value" style="color:{accent}">{_esc(value)}</div>'
            f'<div class="stat-label">{label}</div>'
            f'{sub_html}'
            f'</div>'
        )

    return '<div class="stat-grid">' + "".join([
        card("&#x1f916;", str(report.total_agents),   "Agents",          "#60a5fa",
             f"{report.total_servers} servers"),
        card("&#x1f4e6;", str(report.total_packages), "Packages",        "#38bdf8",
             "direct + transitive"),
        card("&#x26a0;&#xfe0f;",  str(total_vulns),           "Vulnerabilities", "#f87171" if total_vulns else "#34d399",
             "across all agents"),
        card("&#x1f511;", str(cred_servers),          "Servers w/ Creds", "#fbbf24" if cred_servers else "#34d399",
             "credential exposure"),
        card("&#x1f6a8;", str(crit),                  "Critical",        "#ef4444" if crit else "#34d399",
             "needs immediate fix"),
        card("&#x1f9a0;", str(kev_count),             "CISA KEV",        "#a855f7" if kev_count else "#34d399",
             "actively exploited"),
    ]) + "</div>"


def _vuln_table(blast_radii: list["BlastRadius"]) -> str:
    if not blast_radii:
        return (
            '<div class="empty-state">&#x2705; No vulnerabilities found in scanned packages.</div>'
        )

    has_missing = any(
        not br.vulnerability.cvss_score or not br.vulnerability.summary
        for br in blast_radii
    )
    hint = ""
    if has_missing:
        hint = (
            '<div class="hint-box">'
            '&#x1f4a1; <strong>Some entries are missing CVSS scores or descriptions.</strong> '
            'Run with <code>--enrich</code> to fetch full NVD metadata, CVSS 3.x vectors, EPSS, and CISA KEV status.'
            '</div>'
        )

    sorted_brs = sorted(
        blast_radii,
        key=lambda b: _SEV_ORDER.get(b.vulnerability.severity.value.lower(), 0),
        reverse=True,
    )
    rows = []
    for br in sorted_brs:
        v = br.vulnerability
        sev = v.severity.value.lower()
        color = _SEV_COLOR.get(sev, "#6b7280")
        cvss_bar = ""
        if v.cvss_score:
            pct = int(v.cvss_score * 10)
            cvss_bar = (
                f'<div style="display:flex;align-items:center;gap:6px">'
                f'<div style="background:#0f172a;border-radius:3px;height:4px;width:52px;flex-shrink:0">'
                f'<div style="background:{color};border-radius:3px;height:4px;width:{pct}%"></div></div>'
                f'<strong style="color:{color}">{v.cvss_score:.1f}</strong></div>'
            )
        else:
            cvss_bar = '<span style="color:#334155">&mdash;</span>'
        epss = f'{v.epss_score:.1%}' if v.epss_score else '<span style="color:#334155">&mdash;</span>'
        kev = (
            '<span class="badge-kev">KEV</span>'
            if v.is_kev else '<span style="color:#334155">&mdash;</span>'
        )
        fix = (
            f'<code style="color:#4ade80">{_esc(v.fixed_version)}</code>'
            if v.fixed_version else '<span style="color:#475569">No fix</span>'
        )
        summary_text = (v.summary or "")[:90]
        summary = _esc(summary_text) if summary_text else '<span style="color:#475569;font-style:italic">Run --enrich</span>'
        agents_s = ", ".join(_esc(a.name) for a in br.affected_agents) or "<span style='color:#334155'>&mdash;</span>"
        creds_s = (
            " ".join(f'<code style="color:#fbbf24">{_esc(c)}</code>' for c in br.exposed_credentials)
            or "<span style='color:#334155'>&mdash;</span>"
        )
        rows.append(
            f'<tr data-severity="{sev}" data-kev="{"1" if v.is_kev else "0"}" '
            f'data-cvss="{v.cvss_score if v.cvss_score else 0}">'
            f'<td><code class="vuln-id">{_esc(v.id)}</code></td>'
            f'<td>{_sev_badge(sev)}</td>'
            f'<td><strong style="color:#e2e8f0">{_esc(br.package.name)}</strong>'
            f'<span style="color:#475569;font-size:.78rem">@{_esc(br.package.version)}</span></td>'
            f'<td>{cvss_bar}</td>'
            f'<td style="text-align:center;font-size:.82rem;color:#94a3b8">{epss}</td>'
            f'<td style="text-align:center">{kev}</td>'
            f'<td>{fix}</td>'
            f'<td style="font-size:.78rem;color:#94a3b8">{agents_s}</td>'
            f'<td style="font-size:.78rem">{creds_s}</td>'
            f'<td style="font-size:.75rem;color:#64748b;max-width:180px">{summary}</td>'
            f'</tr>'
        )

    headers = ["Vuln ID", "Severity", "Package", "CVSS", "EPSS", "KEV", "Fix",
               "Affected Agents", "Exposed Creds", "Summary"]

    filter_bar = (
        '<div class="vuln-filter-bar" style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;'
        'margin-bottom:14px;padding:12px 16px;background:#0f172a;border-radius:8px;border:1px solid #1e293b">'
        '<span style="font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em;font-weight:700">Filter:</span>'
        '<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:#fca5a5;cursor:pointer">'
        '<input type="checkbox" class="vuln-sev-filter" value="critical" checked> Critical</label>'
        '<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:#fb923c;cursor:pointer">'
        '<input type="checkbox" class="vuln-sev-filter" value="high" checked> High</label>'
        '<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:#fbbf24;cursor:pointer">'
        '<input type="checkbox" class="vuln-sev-filter" value="medium" checked> Medium</label>'
        '<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:#94a3b8;cursor:pointer">'
        '<input type="checkbox" class="vuln-sev-filter" value="low" checked> Low</label>'
        '<span style="width:1px;height:18px;background:#334155"></span>'
        '<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:#fca5a5;cursor:pointer">'
        '<input type="checkbox" id="kevToggle"> KEV only</label>'
        '<span style="width:1px;height:18px;background:#334155"></span>'
        '<input type="text" id="vulnSearch" placeholder="Search vulns&hellip;" '
        'style="padding:6px 10px;background:#1e293b;border:1px solid #334155;border-radius:6px;'
        'color:#e2e8f0;font-size:.78rem;width:160px;outline:none">'
        '</div>'
    )

    return (
        hint
        + filter_bar
        + '<div class="table-wrap"><table class="data-table sortable" id="vulnTable">'
        + '<thead><tr>'
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + '</tr></thead>'
        + f'<tbody>{"".join(rows)}</tbody></table></div>'
    )


def _blast_table(blast_radii: list["BlastRadius"]) -> str:
    if not blast_radii:
        return ""
    sorted_brs = sorted(blast_radii, key=lambda b: b.risk_score, reverse=True)
    rows = []
    for i, br in enumerate(sorted_brs, 1):
        v = br.vulnerability
        sev = v.severity.value.lower()
        color = _SEV_COLOR.get(sev, "#6b7280")
        bar_w = int(br.risk_score * 9)
        ai_badge = (
            '<span class="badge-ai">AI</span>' if br.ai_risk_context else ""
        )
        kev_badge = (
            '<span class="badge-kev">KEV</span>' if v.is_kev else ""
        )
        fix = (
            f'<code style="color:#4ade80;font-size:.8rem">{_esc(v.fixed_version)}</code>'
            if v.fixed_version else '<span style="color:#475569">&mdash;</span>'
        )
        rows.append(
            f'<tr>'
            f'<td style="color:#475569;font-weight:600">#{i}</td>'
            f'<td><code class="vuln-id">{_esc(v.id)}</code></td>'
            f'<td>{_sev_badge(sev)}</td>'
            f'<td>'
            f'<div style="display:flex;align-items:center;gap:8px">'
            f'<div style="background:#0f172a;border-radius:3px;height:5px;width:90px">'
            f'<div style="background:{color};border-radius:3px;height:5px;width:{bar_w}px"></div></div>'
            f'<strong style="color:{color}">{br.risk_score:.1f}</strong></div>'
            f'</td>'
            f'<td style="text-align:center;color:#e2e8f0">{len(br.affected_agents)}</td>'
            f'<td style="text-align:center;color:#fbbf24">{len(br.exposed_credentials)}</td>'
            f'<td style="text-align:center;color:#94a3b8">{len(br.exposed_tools)}</td>'
            f'<td>{ai_badge}{kev_badge}</td>'
            f'<td>{fix}</td>'
            f'</tr>'
        )
    headers = ["#", "Vuln ID", "Severity", "Blast Score (0&ndash;10)",
               "Agents Hit", "Creds Exposed", "Tools Reachable", "Flags", "Fix"]
    return (
        '<div class="table-wrap"><table class="data-table sortable">'
        + '<thead><tr>'
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
    )


def _remediation_list(blast_radii: list["BlastRadius"]) -> str:
    if not blast_radii:
        return '<p style="color:#4ade80">&#x2705; Nothing to remediate.</p>'
    with_fix = sorted(
        [b for b in blast_radii if b.vulnerability.fixed_version],
        key=lambda b: b.risk_score,
        reverse=True,
    )
    no_fix = [b for b in blast_radii if not b.vulnerability.fixed_version]
    items = []
    for br in with_fix:
        v = br.vulnerability
        creds_note = (
            f' &middot; frees <strong style="color:#fbbf24">{len(br.exposed_credentials)}</strong> credential(s)'
            if br.exposed_credentials else ""
        )
        items.append(
            f'<div class="remediation-item">'
            f'<div style="flex-shrink:0;padding-top:1px">{_sev_badge(v.severity.value.lower())}</div>'
            f'<div style="flex:1">'
            f'<div style="color:#e2e8f0;font-weight:600">{_esc(br.package.name)}'
            f'<span style="color:#475569;font-weight:400">@{_esc(br.package.version)}</span></div>'
            f'<div style="font-size:.8rem;color:#64748b;margin-top:3px">'
            f'<code class="vuln-id">{_esc(v.id)}</code>'
            f' &middot; upgrade to <code style="color:#4ade80">{_esc(v.fixed_version)}</code>'
            f' &middot; protects <strong>{len(br.affected_agents)}</strong> agent(s)'
            f'{creds_note}'
            f'</div></div>'
            f'<div style="flex-shrink:0;color:#475569;font-size:.78rem;padding-top:3px">score&nbsp;{br.risk_score:.1f}</div>'
            f'</div>'
        )
    nf_html = ""
    if no_fix:
        nf_rows = "".join(
            f'<div style="padding:9px 0;border-bottom:1px solid #1e293b;font-size:.82rem">'
            f'{_sev_badge(b.vulnerability.severity.value.lower())} '
            f'<code class="vuln-id">{_esc(b.vulnerability.id)}</code> &mdash; '
            f'<strong style="color:#e2e8f0">{_esc(b.package.name)}</strong>@{_esc(b.package.version)}'
            f' &mdash; <span style="color:#475569">no fix available &mdash; monitor upstream</span></div>'
            for b in no_fix
        )
        nf_html = (
            '<div style="margin-top:20px">'
            '<div class="subsection-label">No Fix Available</div>'
            + nf_rows + '</div>'
        )
    return "".join(items) + nf_html


def _skill_audit_section(report: "AIBOMReport") -> str:
    """Build the skill audit findings section if data is available."""
    data = getattr(report, "skill_audit_data", None)
    if not data:
        return ""

    findings = data.get("findings", [])
    passed = data.get("passed", True)
    pkgs_checked = data.get("packages_checked", 0)
    servers_checked = data.get("servers_checked", 0)
    creds_checked = data.get("credentials_checked", 0)
    ai_summary = data.get("ai_skill_summary", "")
    ai_risk = data.get("ai_overall_risk_level", "")

    status_color = "#16a34a" if passed else "#dc2626"
    status_text = "PASSED" if passed else "FAILED"

    summary_html = ""
    if ai_summary:
        summary_html = (
            f'<div class="hint-box" style="border-color:#818cf840;background:#1e1b4b40">'
            f'<strong style="color:#c7d2fe">AI Analysis:</strong> {_esc(ai_summary)}'
            f'</div>'
        )

    stats_html = (
        f'<div style="display:flex;gap:24px;margin-bottom:16px;font-size:.82rem;color:#94a3b8">'
        f'<span>Status: <strong style="color:{status_color}">{status_text}</strong></span>'
        f'<span>Packages checked: <strong>{pkgs_checked}</strong></span>'
        f'<span>Servers checked: <strong>{servers_checked}</strong></span>'
        f'<span>Credentials checked: <strong>{creds_checked}</strong></span>'
        + (f'<span>AI risk level: <strong style="color:{_SEV_COLOR.get(ai_risk, "#64748b")}">{_esc(ai_risk).upper()}</strong></span>' if ai_risk else "")
        + '</div>'
    )

    if not findings:
        return (
            f'<section id="skillaudit">'
            f'<div class="sec-title">&#x1f6e1;&#xfe0f; Skill File Audit</div>'
            f'<div class="panel">{stats_html}{summary_html}'
            f'<div class="empty-state">&#x2705; No security findings in skill files.</div>'
            f'</div></section>'
        )

    rows = []
    for f in findings:
        sev = f.get("severity", "low")
        rows.append(
            f'<tr>'
            f'<td>{_sev_badge(sev)}</td>'
            f'<td style="color:#e2e8f0;font-weight:600;font-size:.85rem">{_esc(f.get("title", ""))}</td>'
            f'<td><code style="color:#94a3b8;font-size:.75rem">{_esc(f.get("category", ""))}</code></td>'
            f'<td style="font-size:.78rem;color:#94a3b8;max-width:300px">{_esc(f.get("detail", ""))}</td>'
            f'<td style="font-size:.75rem;color:#64748b">{_esc(f.get("source_file", ""))}</td>'
            f'<td style="font-size:.75rem;color:#4ade80">{_esc(f.get("recommendation", ""))}</td>'
            f'</tr>'
        )

    headers = ["Severity", "Finding", "Category", "Detail", "Source", "Recommendation"]
    table_html = (
        '<div class="table-wrap"><table class="data-table sortable">'
        + '<thead><tr>'
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + '</tr></thead>'
        + f'<tbody>{"".join(rows)}</tbody></table></div>'
    )

    return (
        f'<section id="skillaudit">'
        f'<div class="sec-title">&#x1f6e1;&#xfe0f; Skill File Audit'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{len(findings)}</sup></div>'
        f'<div class="panel">{stats_html}{summary_html}{table_html}</div>'
        f'</section>'
    )


def _attack_flow_section(blast_radii: list["BlastRadius"]) -> str:
    """Build the CVE attack flow graph section (only when vulns exist)."""
    if not blast_radii:
        return ""

    total_creds = len({c for br in blast_radii for c in br.exposed_credentials})
    total_tools = len({t for br in blast_radii for t in br.exposed_tools})
    total_agents = len({a.name for br in blast_radii for a in br.affected_agents})

    return (
        '<section id="attackflow">'
        '<div class="sec-title">&#x1f525; CVE Attack Flow'
        '<span style="font-size:.68rem;font-weight:400;opacity:.5;margin-left:8px">'
        f'{len(blast_radii)} CVEs &#x2192; {total_agents} agents &#x2192; '
        f'{total_creds} credentials &#x2192; {total_tools} tools at risk'
        '</span></div>'
        '<div class="graph-container">'
        '<div id="cyAttack" class="d3-graph"></div>'
        '<div class="graph-controls" style="top:12px;right:12px">'
        '<button class="graph-btn" id="afZoomIn" title="Zoom in">+</button>'
        '<button class="graph-btn" id="afZoomOut" title="Zoom out">&minus;</button>'
        '<button class="graph-btn" id="afFitBtn" title="Fit to view">&#x2922;</button>'
        '</div>'
        '</div>'
        '<div class="legend">'
        '<span><i class="diamond" style="background:#f87171"></i>CVE</span>'
        '<span><i style="background:#dc2626"></i>Vulnerable Package</span>'
        '<span><i style="background:#475569"></i>MCP Server</span>'
        '<span><i style="background:#fbbf24"></i>Credential</span>'
        '<span><i style="background:#818cf8"></i>Tool</span>'
        '<span><i style="background:#3b82f6"></i>Agent</span>'
        '</div>'
        '</section>'
    )


def _inventory_cards(report: "AIBOMReport") -> str:
    cards = []
    for agent in report.agents:
        total_vulns = agent.total_vulnerabilities
        total_creds = sum(len(s.credential_names) for s in agent.mcp_servers)
        agent_badges = []
        if total_vulns:
            agent_badges.append(
                f'<span class="badge-vuln">{total_vulns} vuln{"s" if total_vulns != 1 else ""}</span>'
            )
        if total_creds:
            agent_badges.append(
                f'<span class="badge-cred">{total_creds} credential{"s" if total_creds != 1 else ""}</span>'
            )
        badges_html = " ".join(agent_badges)

        servers_html = []
        for srv in agent.mcp_servers:
            vuln_pkgs = [p for p in srv.packages if p.has_vulnerabilities]
            accent = "#ef4444" if vuln_pkgs else ("#f59e0b" if srv.has_credentials else "#334155")
            srv_badges = []
            if vuln_pkgs:
                srv_badges.append('<span class="badge-vuln">VULN</span>')
            if srv.has_credentials:
                srv_badges.append('<span class="badge-cred">CREDS</span>')

            cmd = ""
            if srv.command:
                cmd_parts = [srv.command] + srv.args[:3]
                cmd = _esc(" ".join(cmd_parts))
                if srv.args and len(srv.args) > 3:
                    cmd += f' <span style="color:#334155">&hellip;+{len(srv.args)-3} args</span>'

            # Credentials section
            creds_html = ""
            if srv.credential_names:
                creds_html = (
                    '<div style="margin-top:8px">'
                    + "".join(
                        f'<div style="font-size:.74rem;color:#fbbf24;padding:2px 0">'
                        f'&#x1f511; <code>{_esc(c)}</code></div>'
                        for c in srv.credential_names
                    )
                    + "</div>"
                )

            # Packages — preview first N, collapse rest
            pkgs = srv.packages
            pkg_count = len(pkgs)
            preview = pkgs[:_PKG_PREVIEW]
            rest = pkgs[_PKG_PREVIEW:]

            def pkg_row(p: object) -> str:
                from agent_bom.models import Package
                if not isinstance(p, Package):
                    return ""
                color = "#f87171" if p.has_vulnerabilities else "#38bdf8"
                vuln_mark = " &#x26a0;" if p.has_vulnerabilities else ""
                return (
                    f'<div class="pkg-row">'
                    f'<span><code style="color:{color};font-size:.72rem">{_esc(p.ecosystem)}</code>'
                    f' <span class="pkg-name">{_esc(p.name)}</span></span>'
                    f'<span class="pkg-ver">{_esc(p.version)}{vuln_mark}</span>'
                    f'</div>'
                )

            pkg_html = ""
            if pkgs:
                preview_rows = "".join(pkg_row(p) for p in preview)
                if rest:
                    uid = f"pkgs_{id(srv)}"
                    rest_rows = "".join(pkg_row(p) for p in rest)
                    pkg_html = (
                        f'<div style="margin-top:8px">'
                        f'{preview_rows}'
                        f'<div id="{uid}" style="display:none">{rest_rows}</div>'
                        f'<button class="toggle-btn" onclick="togglePkgs(\'{uid}\',this)">'
                        f'Show {len(rest)} more packages &#x25bc;</button>'
                        f'</div>'
                    )
                else:
                    pkg_html = f'<div style="margin-top:8px">{preview_rows}</div>'

            srv_badges_html = " ".join(srv_badges)
            srv_header = (
                f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">'
                f'<div style="font-weight:600;color:#e2e8f0;font-size:.9rem">&#x2699;&#xfe0f; {_esc(srv.name)} {srv_badges_html}</div>'
                f'<div style="font-size:.72rem;color:#475569">{pkg_count} pkg{"s" if pkg_count != 1 else ""}</div>'
                f'</div>'
            )
            cmd_html = (
                f'<div style="font-size:.72rem;color:#475569;font-family:monospace;'
                f'margin-bottom:6px;word-break:break-all">{cmd}</div>'
                if cmd else ""
            )

            servers_html.append(
                f'<div class="server-card" style="border-left-color:{accent}">'
                f'{srv_header}{cmd_html}{creds_html}{pkg_html}'
                f'</div>'
            )

        servers_content = "".join(servers_html) if servers_html else (
            '<p style="color:#334155;font-size:.85rem">No MCP servers configured.</p>'
        )

        cards.append(
            f'<details class="agent-card" open>'
            f'<summary class="agent-summary">'
            f'<span>&#x1f916; {_esc(agent.name)}</span>'
            f'<span style="display:flex;align-items:center;gap:8px">'
            f'{badges_html}'
            f'<span style="font-size:.72rem;color:#475569">'
            f'{len(agent.mcp_servers)} server(s) &middot; {agent.total_packages} pkg(s)'
            f'</span>'
            f'</span>'
            f'</summary>'
            f'<div class="agent-detail">'
            f'<div style="font-size:.72rem;color:#475569;margin-bottom:12px">'
            f'{_esc(agent.agent_type.value)} &middot; {_esc(agent.config_path or "")}'
            f'</div>'
            f'{servers_content}'
            f'</div>'
            f'</details>'
        )
    return "".join(cards)


# ─── Main assembler ───────────────────────────────────────────────────────────


def to_html(report: "AIBOMReport", blast_radii: list["BlastRadius"] | None = None) -> str:
    blast_radii = blast_radii or []
    generated = report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    elements_json = _cytoscape_elements(report, blast_radii)
    attack_flow_json = _attack_flow_elements(blast_radii)
    chart_data_json = _chart_data(blast_radii)
    crit = sum(1 for br in blast_radii if br.vulnerability.severity.value == "critical")
    total_vulns = len(blast_radii)

    if crit:
        status_color, status_label = "#dc2626", "CRITICAL FINDINGS"
    elif total_vulns:
        status_color, status_label = "#d97706", "VULNERABILITIES FOUND"
    else:
        status_color, status_label = "#16a34a", "CLEAN"

    # Sections
    vuln_sections = ""
    if blast_radii:
        vuln_sections = (
            f'<section id="vulns">'
            f'<div class="sec-title">&#x26a0;&#xfe0f; Vulnerabilities'
            f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{len(blast_radii)}</sup>'
            f'</div>'
            f'<div class="panel">{_vuln_table(blast_radii)}</div>'
            f'</section>'
            f'<section id="blast">'
            f'<div class="sec-title">&#x1f4a5; Blast Radius'
            f'<sup style="font-size:.65rem;color:#475569;margin-left:6px;font-weight:400">'
            f'risk = CVSS + agents + creds + tools + KEV/EPSS boosts (max 10)'
            f'</sup></div>'
            f'<div class="panel">{_blast_table(blast_radii)}</div>'
            f'</section>'
            f'<section id="remediation">'
            f'<div class="sec-title">&#x1f527; Remediation Plan</div>'
            f'<div class="panel">{_remediation_list(blast_radii)}</div>'
            f'</section>'
        )

    vuln_nav = (
        '<a href="#attackflow">Attack Flow</a>'
        '<a href="#vulns">Vulnerabilities</a>'
        '<a href="#blast">Blast Radius</a>'
        '<a href="#remediation">Remediation</a>'
        if blast_radii else ""
    )

    # Skill audit section
    skill_section = _skill_audit_section(report)
    skill_nav = '<a href="#skillaudit">Skill Audit</a>' if skill_section else ""

    # Determine node counts for graph subtitle
    vuln_node_count = len({(br.package.name, br.package.ecosystem) for br in blast_radii})
    graph_note = (
        f"agents + servers + {vuln_node_count} vulnerable pkg(s) only — "
        f"{report.total_packages - vuln_node_count} clean packages hidden"
        if report.total_packages > vuln_node_count
        else "agents + servers + packages"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>agent-bom AI-BOM &mdash; {_esc(generated)}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js"></script>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0b1120;color:#cbd5e1;line-height:1.6;font-size:14px}}
    a{{color:#60a5fa;text-decoration:none}}
    a:hover{{text-decoration:underline}}
    code{{font-family:"SF Mono","Cascadia Code",Consolas,monospace;font-size:.9em}}

    /* NAV */
    nav{{background:#0f172a;border-bottom:1px solid #1e293b;padding:0 32px;display:flex;align-items:center;gap:16px;height:56px;position:sticky;top:0;z-index:100;backdrop-filter:blur(12px);background:rgba(15,23,42,.92)}}
    .brand{{font-weight:700;font-size:1rem;color:#f1f5f9;letter-spacing:-.01em;white-space:nowrap}}
    .status-badge{{padding:4px 12px;border-radius:6px;font-size:.7rem;font-weight:700;letter-spacing:.05em;background:{status_color}15;color:{status_color};border:1px solid {status_color}30;white-space:nowrap}}
    .scan-time{{color:#475569;font-size:.73rem;white-space:nowrap}}
    .navlinks{{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}}
    .navlinks a{{color:#64748b;font-size:.8rem;padding:6px 12px;border-radius:6px;white-space:nowrap;transition:all .15s}}
    .navlinks a:hover{{background:#1e293b;color:#e2e8f0;text-decoration:none}}

    /* LAYOUT */
    .container{{max-width:1480px;margin:0 auto;padding:32px 32px 80px}}
    section{{margin-bottom:48px}}
    .sec-title{{font-size:.82rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#64748b;margin-bottom:18px;padding-bottom:10px;border-bottom:1px solid #1e293b}}
    .panel{{background:#1e293b;border-radius:12px;padding:24px;border:1px solid #ffffff08}}

    /* STAT CARDS */
    .stat-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:14px}}
    .stat-card{{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-radius:10px;padding:20px 22px;border-left:4px solid #334155;border:1px solid #ffffff06;transition:transform .15s,box-shadow .15s}}
    .stat-card:hover{{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.3)}}
    .stat-icon{{font-size:1.4rem;margin-bottom:6px}}
    .stat-value{{font-size:2.2rem;font-weight:800;line-height:1;margin-bottom:6px}}
    .stat-label{{font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em}}

    /* CHARTS ROW */
    .charts-row{{display:grid;grid-template-columns:320px 1fr;gap:16px}}
    .chart-panel{{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-radius:12px;padding:24px;border:1px solid #ffffff06}}
    .chart-title{{font-size:.73rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#64748b;margin-bottom:16px}}
    .chart-wrap{{position:relative}}
    .donut-wrap{{max-width:260px;margin:0 auto}}

    /* GRAPH */
    .graph-container{{position:relative;border-radius:12px;overflow:hidden;border:1px solid #ffffff08}}
    .graph-container:fullscreen{{border-radius:0;background:#0f172a}}
    .graph-container:fullscreen svg{{height:100vh}}
    .d3-graph{{width:100%;background:#0f172a}}
    #cy{{width:100%;height:600px}}
    #cy svg{{width:100%;height:600px}}
    #cyAttack{{width:100%;height:500px}}
    #cyAttack svg{{width:100%;height:500px}}
    .d3-graph .node-group{{cursor:pointer}}
    .d3-graph .node-group:hover rect,.d3-graph .node-group:hover polygon{{filter:brightness(1.3)}}
    .d3-graph .link{{fill:none;stroke-opacity:.6}}
    .d3-graph .node-label{{pointer-events:none;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}}
    .d3-graph .faded{{opacity:.08;transition:opacity .2s}}
    .d3-graph .highlighted rect,.d3-graph .highlighted polygon{{stroke:#f1f5f9!important;stroke-width:4!important}}
    .graph-controls{{position:absolute;top:12px;right:12px;display:flex;flex-direction:column;gap:4px;z-index:10}}
    .graph-btn{{width:36px;height:36px;border-radius:8px;border:1px solid #334155;background:rgba(15,23,42,.85);color:#94a3b8;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;backdrop-filter:blur(8px)}}
    .graph-btn:hover{{background:#1e293b;color:#e2e8f0;border-color:#475569}}
    .legend{{display:flex;gap:20px;flex-wrap:wrap;font-size:.76rem;color:#64748b;margin-top:12px;padding:0 4px}}
    .legend span{{display:flex;align-items:center;gap:6px}}
    .legend i{{display:inline-block;width:10px;height:10px;border-radius:3px}}
    .legend i.diamond{{transform:rotate(45deg);border-radius:1px}}

    /* NODE DETAIL SIDEBAR */
    .node-sidebar{{position:fixed;top:56px;right:0;bottom:0;width:340px;background:rgba(15,23,42,.97);border-left:1px solid #334155;backdrop-filter:blur(12px);z-index:200;overflow-y:auto;transform:translateX(100%);transition:transform .25s ease;padding:0}}
    .node-sidebar.open{{transform:translateX(0);display:block}}
    .sidebar-header{{display:flex;justify-content:space-between;align-items:center;padding:16px 20px 8px;border-bottom:1px solid #1e293b}}
    .sidebar-type{{font-size:.65rem;letter-spacing:.08em;text-transform:uppercase;color:#64748b;font-weight:700;padding:3px 8px;border-radius:4px;border:1px solid #334155}}
    .sidebar-close{{background:none;border:none;color:#64748b;font-size:1.4rem;cursor:pointer;padding:4px 8px;border-radius:4px;transition:all .15s}}
    .sidebar-close:hover{{color:#e2e8f0;background:#1e293b}}
    .sidebar-name{{font-size:1rem;font-weight:700;color:#f1f5f9;padding:12px 20px 4px;margin:0}}
    .sidebar-meta{{font-size:.78rem;color:#94a3b8;padding:0 20px 12px;font-family:monospace;white-space:pre-line}}
    .sidebar-section{{padding:0 20px 16px}}
    .sidebar-section:empty{{display:none}}
    .sidebar-label{{font-size:.68rem;letter-spacing:.06em;text-transform:uppercase;color:#64748b;font-weight:700;margin-bottom:8px}}
    .sidebar-list{{list-style:none;padding:0;margin:0}}
    .sidebar-list li{{font-size:.8rem;color:#cbd5e1;padding:5px 0;border-bottom:1px solid #0f172a}}
    .sidebar-list li:last-child{{border-bottom:none}}
    .sidebar-link{{color:#60a5fa;font-size:.78rem;text-decoration:none}}
    .sidebar-link:hover{{text-decoration:underline;color:#93c5fd}}
    .sidebar-cred{{color:#fbbf24;font-family:monospace;font-size:.78rem}}
    @media(max-width:900px){{.node-sidebar{{width:100%}}}}

    /* TOOLTIP */
    #tip{{position:fixed;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 14px;font-size:.76rem;color:#e2e8f0;pointer-events:none;white-space:pre-line;max-width:280px;z-index:9999;display:none;line-height:1.5;box-shadow:0 8px 24px rgba(0,0,0,.4)}}

    /* TABLES */
    .table-wrap{{overflow-x:auto;border-radius:8px}}
    .data-table{{width:100%;border-collapse:collapse;font-size:.83rem}}
    .data-table th{{padding:10px 14px;font-size:.68rem;letter-spacing:.06em;color:#64748b;font-weight:700;text-transform:uppercase;border-bottom:2px solid #334155;white-space:nowrap;background:#0f172a;position:sticky;top:0}}
    .data-table.sortable th{{cursor:pointer;user-select:none;transition:color .15s}}
    .data-table.sortable th:hover{{color:#e2e8f0}}
    .sort-arrow{{font-size:.6rem;margin-left:3px;opacity:.4}}
    .sort-arrow.asc::after{{content:"\\25B2"}}
    .sort-arrow.desc::after{{content:"\\25BC"}}
    .data-table td{{padding:10px 14px;border-bottom:1px solid #1e293b;vertical-align:middle}}
    .data-table tr{{transition:background .1s}}
    .data-table tr:hover td{{background:rgba(255,255,255,.03)}}

    /* BADGES */
    .badge-kev{{background:#7f1d1d;color:#fca5a5;padding:2px 8px;border-radius:4px;font-size:.68rem;font-weight:700}}
    .badge-ai{{background:#1d4ed8;color:#bfdbfe;padding:2px 8px;border-radius:4px;font-size:.68rem;font-weight:700;margin-right:4px}}
    .badge-vuln{{background:#7f1d1d;color:#fca5a5;font-size:.65rem;padding:2px 6px;border-radius:4px;font-weight:700}}
    .badge-cred{{background:#78350f;color:#fde68a;font-size:.65rem;padding:2px 6px;border-radius:4px;font-weight:700}}
    .vuln-id{{color:#93c5fd;font-size:.78rem}}

    /* REMEDIATION */
    .remediation-item{{display:flex;align-items:flex-start;gap:14px;padding:16px 0;border-bottom:1px solid #1e293b;transition:background .1s}}
    .remediation-item:hover{{background:rgba(255,255,255,.02);margin:0 -12px;padding-left:12px;padding-right:12px;border-radius:8px}}
    .subsection-label{{font-size:.7rem;letter-spacing:.07em;text-transform:uppercase;color:#64748b;margin-bottom:10px}}

    /* INVENTORY */
    .inv-search{{width:100%;padding:10px 14px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:.85rem;margin-bottom:16px;outline:none;transition:border-color .15s}}
    .inv-search:focus{{border-color:#3b82f6}}
    .inv-search::placeholder{{color:#475569}}
    .agent-card{{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-radius:12px;margin-bottom:12px;overflow:hidden;border:1px solid #ffffff06;transition:box-shadow .15s}}
    .agent-card:hover{{box-shadow:0 4px 16px rgba(0,0,0,.2)}}
    .agent-summary{{list-style:none;display:flex;justify-content:space-between;align-items:center;padding:18px 22px;cursor:pointer;user-select:none;font-weight:700;font-size:.95rem;color:#f1f5f9}}
    .agent-summary::-webkit-details-marker{{display:none}}
    .agent-summary::before{{content:"\\25B6";margin-right:10px;font-size:.6rem;color:#475569;transition:transform .2s}}
    details[open] .agent-summary::before{{transform:rotate(90deg)}}
    .agent-detail{{padding:18px 22px;border-top:1px solid #0b112060}}
    .server-card{{background:#0b1120;border-radius:8px;padding:14px 16px;margin-bottom:10px;border-left:3px solid #334155;border:1px solid #ffffff04;border-left:3px solid #334155}}
    .pkg-row{{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #0a162830;font-size:.78rem}}
    .pkg-row:last-child{{border-bottom:none}}
    .pkg-name{{color:#e2e8f0}}
    .pkg-ver{{color:#64748b;font-family:monospace;font-size:.73rem}}
    .toggle-btn{{background:transparent;border:1px solid #334155;color:#64748b;font-size:.72rem;padding:6px 12px;border-radius:6px;cursor:pointer;margin-top:10px;width:100%;transition:all .15s}}
    .toggle-btn:hover{{background:#1e293b;color:#94a3b8}}

    /* HINTS */
    .hint-box{{background:#1e3a5f40;border:1px solid #3b82f640;border-radius:8px;padding:14px 18px;margin-bottom:18px;font-size:.82rem;color:#93c5fd}}
    .empty-state{{background:#052e1615;border:1px solid #16a34a30;border-radius:10px;padding:24px;color:#4ade80;text-align:center;font-size:.9rem}}

    footer{{border-top:1px solid #1e293b;padding:24px 32px;text-align:center;font-size:.75rem;color:#334155}}
    .print-btn{{background:transparent;border:1px solid #334155;color:#64748b;font-size:.75rem;padding:4px 12px;border-radius:6px;cursor:pointer;margin-left:12px;transition:all .15s}}
    .print-btn:hover{{background:#1e293b;color:#94a3b8}}

    @media(max-width:900px){{
      .charts-row{{grid-template-columns:1fr}}
      .stat-grid{{grid-template-columns:repeat(auto-fill,minmax(140px,1fr))}}
      nav{{padding:0 16px;gap:8px}}
      .container{{padding:20px 16px 60px}}
    }}

    /* PRINT */
    @media print{{
      body{{background:#fff;color:#1e293b;font-size:12px}}
      nav,.graph-controls,.graph-filter-bar,.vuln-filter-bar,.toggle-btn,.inv-search,.print-btn,.node-sidebar{{display:none!important}}
      .container{{max-width:100%;padding:10px}}
      section{{page-break-inside:avoid;margin-bottom:20px}}
      .panel,.stat-card,.agent-card,.server-card,.chart-panel{{background:#f8fafc;border:1px solid #e2e8f0;box-shadow:none}}
      .stat-value,.sec-title{{color:#0f172a}}
      .data-table th{{background:#f1f5f9;color:#334155;border-bottom:2px solid #cbd5e1}}
      .data-table td{{border-bottom:1px solid #e2e8f0}}
      #cy{{height:400px;background:#f8fafc;border:1px solid #e2e8f0}}
      #cy svg{{height:400px}}
      .legend{{color:#475569}}
      a{{color:#2563eb}}
      footer{{color:#94a3b8}}
      .graph-container{{border:1px solid #e2e8f0}}
    }}
  </style>
</head>
<body>

<nav>
  <span class="brand">&#x1f6e1;&#xfe0f; agent-bom</span>
  <span class="status-badge">{status_label}</span>
  <span class="scan-time">{_esc(generated)} &middot; v{_esc(report.tool_version)}</span>
  <div class="navlinks">
    <a href="#summary">Summary</a>
    <a href="#charts">Charts</a>
    <a href="#riskmap">Risk Map</a>
    <a href="#inventory">Inventory</a>
    {skill_nav}
    {vuln_nav}
    <button class="print-btn" onclick="window.print()">&#x1f5b6;&#xfe0f; Print</button>
  </div>
</nav>

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

  <!-- Summary stat cards -->
  <section id="summary">
    <div class="sec-title">Summary</div>
    {_summary_cards(report, blast_radii)}
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
      <div id="cy" class="d3-graph"></div>
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

  <!-- Skill audit -->
  {skill_section}

  <!-- Attack flow graph (only when vulns exist) -->
  {_attack_flow_section(blast_radii)}

  <!-- Vuln / Blast / Remediation -->
  {vuln_sections}

</div>

<footer>
  Generated by <strong style="color:#475569">agent-bom</strong> v{_esc(report.tool_version)} &middot;
  <a href="https://github.com/msaad00/agent-bom">github.com/msaad00/agent-bom</a> &middot;
  Vulnerability data: OSV.dev &middot; NVD &middot; CISA KEV &middot; EPSS
</footer>

<script>
(function() {{
  // Injected data
  var CHART_DATA = {chart_data_json};
  var GRAPH_ELEMENTS = {elements_json};
  var ATTACK_FLOW = {attack_flow_json};

  // Chart.js: Severity donut
  var sevCtx = document.getElementById('sevChart');
  if (sevCtx && CHART_DATA.sev.data.some(function(v){{ return v > 0; }})) {{
    new Chart(sevCtx, {{
      type: 'doughnut',
      data: {{
        labels: CHART_DATA.sev.labels,
        datasets: [{{
          data: CHART_DATA.sev.data,
          backgroundColor: CHART_DATA.sev.colors,
          borderColor: '#0b1120',
          borderWidth: 3,
          hoverOffset: 8,
        }}],
      }},
      options: {{
        responsive: true,
        cutout: '68%',
        plugins: {{
          legend: {{
            position: 'bottom',
            labels: {{
              color: '#94a3b8',
              font: {{ size: 11 }},
              boxWidth: 12,
              padding: 14,
            }},
          }},
          tooltip: {{
            backgroundColor: '#0f172a',
            borderColor: '#334155',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
            cornerRadius: 8,
            padding: 10,
            callbacks: {{
              label: function(ctx) {{
                return ' ' + ctx.label + ': ' + ctx.parsed;
              }},
            }},
          }},
        }},
      }},
    }});
  }} else if (sevCtx) {{
    var p = document.createElement('p');
    p.style.cssText = 'color:#4ade80;text-align:center;padding:50px 0;font-size:.88rem';
    p.innerHTML = '&#x2705; No vulnerabilities';
    sevCtx.parentNode.replaceChild(p, sevCtx);
  }}

  // Chart.js: Blast radius bar
  var blastCtx = document.getElementById('blastChart');
  if (blastCtx && CHART_DATA.blast.labels.length > 0) {{
    new Chart(blastCtx, {{
      type: 'bar',
      data: {{
        labels: CHART_DATA.blast.labels,
        datasets: [{{
          label: 'Blast Score',
          data: CHART_DATA.blast.scores,
          backgroundColor: CHART_DATA.blast.colors,
          borderRadius: 6,
          borderSkipped: false,
        }}],
      }},
      options: {{
        indexAxis: 'y',
        responsive: true,
        scales: {{
          x: {{
            min: 0, max: 10,
            grid: {{ color: '#1e293b' }},
            ticks: {{ color: '#64748b', font: {{ size: 11 }} }},
          }},
          y: {{
            grid: {{ display: false }},
            ticks: {{ color: '#94a3b8', font: {{ size: 11 }} }},
          }},
        }},
        plugins: {{
          legend: {{ display: false }},
          tooltip: {{
            backgroundColor: '#0f172a',
            borderColor: '#334155',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
            cornerRadius: 8,
            callbacks: {{
              label: function(ctx) {{
                return ' Score: ' + ctx.parsed.x.toFixed(2);
              }},
            }},
          }},
        }},
      }},
    }});
  }} else if (blastCtx) {{
    var p2 = document.createElement('p');
    p2.style.cssText = 'color:#4ade80;text-align:center;padding:50px 0;font-size:.88rem';
    p2.innerHTML = '&#x2705; No blast radius data';
    blastCtx.parentNode.replaceChild(p2, blastCtx);
  }}

  // D3.js helper: convert Cytoscape elements to D3 nodes + links
  function cytoToD3(elements) {{
    var nodeMap = {{}};
    var nodes = [];
    var links = [];
    elements.forEach(function(el) {{
      var d = el.data;
      if (d.source && d.target) {{
        links.push({{ source: d.source, target: d.target, type: d.type || '' }});
      }} else if (d.id) {{
        var node = Object.assign({{}}, d);
        nodeMap[d.id] = node;
        nodes.push(node);
      }}
    }});
    // Build adjacency for neighbor lookups
    nodes.forEach(function(n) {{ n._neighbors = []; }});
    links.forEach(function(l) {{
      if (nodeMap[l.source]) nodeMap[l.source]._neighbors.push(l.target);
      if (nodeMap[l.target]) nodeMap[l.target]._neighbors.push(l.source);
    }});
    return {{ nodes: nodes, links: links, nodeMap: nodeMap }};
  }}

  // D3.js node style config
  var NODE_STYLES = {{
    'provider':      {{ fill:'#1e1b4b', stroke:'#818cf8', strokeW:3, w:140, h:44, fontSize:13, fontWeight:700, color:'#c7d2fe', shape:'rect' }},
    'agent':         {{ fill:'#1e3a8a', stroke:'#3b82f6', strokeW:2, w:120, h:40, fontSize:12, fontWeight:700, color:'#bfdbfe', shape:'rect' }},
    'server_clean':  {{ fill:'#052e16', stroke:'#10b981', strokeW:2, w:120, h:36, fontSize:10, fontWeight:400, color:'#6ee7b7', shape:'rect' }},
    'server_cred':   {{ fill:'#431407', stroke:'#f59e0b', strokeW:2, w:120, h:36, fontSize:10, fontWeight:400, color:'#fde68a', shape:'rect' }},
    'server_vuln':   {{ fill:'#450a0a', stroke:'#ef4444', strokeW:2.5, w:120, h:36, fontSize:10, fontWeight:400, color:'#fca5a5', shape:'rect' }},
    'pkg_vuln':      {{ fill:'#7f1d1d', stroke:'#dc2626', strokeW:2, w:130, h:38, fontSize:9, fontWeight:700, color:'#fca5a5', shape:'rect' }},
    'cve_critical':  {{ fill:'#991b1b', stroke:'#f87171', strokeW:2, w:110, h:30, fontSize:8, fontWeight:400, color:'#fecaca', shape:'diamond' }},
    'cve_high':      {{ fill:'#9a3412', stroke:'#fb923c', strokeW:2, w:100, h:28, fontSize:8, fontWeight:400, color:'#fed7aa', shape:'diamond' }},
    'cve_medium':    {{ fill:'#854d0e', stroke:'#fbbf24', strokeW:1.5, w:90, h:26, fontSize:8, fontWeight:400, color:'#fef08a', shape:'diamond' }},
    'cve_low':       {{ fill:'#854d0e', stroke:'#fbbf24', strokeW:1.5, w:90, h:26, fontSize:8, fontWeight:400, color:'#fef08a', shape:'diamond' }},
    'cve_none':      {{ fill:'#854d0e', stroke:'#fbbf24', strokeW:1.5, w:90, h:26, fontSize:8, fontWeight:400, color:'#fef08a', shape:'diamond' }},
  }};
  function getNodeStyle(type) {{
    return NODE_STYLES[type] || NODE_STYLES['cve_medium'];
  }}

  // Edge color config
  var EDGE_COLORS = {{
    'hosts':   {{ stroke:'#818cf8', opacity:0.3, dash:'6,3' }},
    'uses':    {{ stroke:'#334155', opacity:0.6, dash:'' }},
    'depends_on': {{ stroke:'#334155', opacity:0.6, dash:'' }},
    'affects': {{ stroke:'#dc2626', opacity:0.3, dash:'' }},
  }};
  function getEdgeStyle(type) {{
    return EDGE_COLORS[type] || {{ stroke:'#334155', opacity:0.6, dash:'' }};
  }}

  // Hierarchical rank for force X positioning
  var TYPE_RANK = {{ 'provider':0, 'agent':1, 'server_clean':2, 'server_cred':2, 'server_vuln':2, 'pkg_vuln':3, 'cve_critical':4, 'cve_high':4, 'cve_medium':4, 'cve_low':4, 'cve_none':4 }};

  // D3.js: Supply chain graph
  var cyContainer = document.getElementById('cy');
  if (cyContainer && GRAPH_ELEMENTS.length > 0) {{
    var graphData = cytoToD3(GRAPH_ELEMENTS);
    var gNodes = graphData.nodes;
    var gLinks = graphData.links;
    var gNodeMap = graphData.nodeMap;

    var width = cyContainer.clientWidth || 900;
    var height = 600;
    var svg = d3.select('#cy').append('svg')
      .attr('width', width)
      .attr('height', height);

    // Arrow markers
    var defs = svg.append('defs');
    ['default','hosts','affects'].forEach(function(key) {{
      var ec = key === 'hosts' ? '#818cf8' : key === 'affects' ? '#dc2626' : '#475569';
      defs.append('marker')
        .attr('id', 'arrow-' + key)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20).attr('refY', 0)
        .attr('markerWidth', 6).attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', ec);
    }});

    var g = svg.append('g');

    // Zoom/pan
    var zoomBehavior = d3.zoom()
      .scaleExtent([0.15, 4])
      .on('zoom', function(event) {{ g.attr('transform', event.transform); }});
    svg.call(zoomBehavior);

    // Assign initial X by rank for hierarchical feel
    var rankSpacing = width / 6;
    gNodes.forEach(function(n) {{
      var rank = TYPE_RANK[n.type] !== undefined ? TYPE_RANK[n.type] : 3;
      n.x = rank * rankSpacing + rankSpacing * 0.5;
      n.y = height / 2 + (Math.random() - 0.5) * height * 0.6;
    }});

    var simulation = d3.forceSimulation(gNodes)
      .force('link', d3.forceLink(gLinks).id(function(d) {{ return d.id; }}).distance(100).strength(0.7))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('x', d3.forceX(function(d) {{
        var rank = TYPE_RANK[d.type] !== undefined ? TYPE_RANK[d.type] : 3;
        return rank * rankSpacing + rankSpacing * 0.5;
      }}).strength(0.4))
      .force('y', d3.forceY(height / 2).strength(0.1))
      .force('collision', d3.forceCollide(function(d) {{
        var s = getNodeStyle(d.type);
        return Math.max(s.w, s.h) / 2 + 8;
      }}));

    // Links
    var linkGroup = g.append('g').attr('class', 'links');
    var link = linkGroup.selectAll('line')
      .data(gLinks).enter().append('line')
      .attr('class', 'link')
      .attr('stroke', function(d) {{ return getEdgeStyle(d.type).stroke; }})
      .attr('stroke-opacity', function(d) {{ return getEdgeStyle(d.type).opacity; }})
      .attr('stroke-width', 1.8)
      .attr('stroke-dasharray', function(d) {{ return getEdgeStyle(d.type).dash; }})
      .attr('marker-end', function(d) {{
        if (d.type === 'hosts') return 'url(#arrow-hosts)';
        if (d.type === 'affects') return 'url(#arrow-affects)';
        return 'url(#arrow-default)';
      }});

    // Nodes
    var nodeGroup = g.append('g').attr('class', 'nodes');
    var node = nodeGroup.selectAll('g')
      .data(gNodes).enter().append('g')
      .attr('class', 'node-group')
      .call(d3.drag()
        .on('start', function(event, d) {{
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        }})
        .on('drag', function(event, d) {{ d.fx = event.x; d.fy = event.y; }})
        .on('end', function(event, d) {{
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null; d.fy = null;
        }})
      );

    // Draw shapes
    node.each(function(d) {{
      var el = d3.select(this);
      var s = getNodeStyle(d.type);
      if (s.shape === 'diamond') {{
        var hw = s.w / 2, hh = s.h / 2;
        el.append('polygon')
          .attr('points', '0,' + (-hh) + ' ' + hw + ',0 0,' + hh + ' ' + (-hw) + ',0')
          .attr('fill', s.fill).attr('stroke', s.stroke).attr('stroke-width', s.strokeW)
          .attr('rx', 4);
      }} else {{
        el.append('rect')
          .attr('x', -s.w / 2).attr('y', -s.h / 2)
          .attr('width', s.w).attr('height', s.h)
          .attr('rx', 8).attr('ry', 8)
          .attr('fill', s.fill).attr('stroke', s.stroke).attr('stroke-width', s.strokeW);
      }}
    }});

    // Labels (split on newline)
    node.each(function(d) {{
      var el = d3.select(this);
      var s = getNodeStyle(d.type);
      var lines = (d.label || d.id || '').split('\\n');
      var lineH = s.fontSize + 2;
      var startY = -(lines.length - 1) * lineH / 2;
      lines.forEach(function(line, i) {{
        el.append('text')
          .attr('class', 'node-label')
          .attr('text-anchor', 'middle')
          .attr('dy', startY + i * lineH + s.fontSize * 0.35)
          .attr('fill', s.color)
          .attr('font-size', s.fontSize + 'px')
          .attr('font-weight', s.fontWeight)
          .text(line.length > 18 ? line.slice(0, 17) + '\u2026' : line);
      }});
    }});

    simulation.on('tick', function() {{
      link
        .attr('x1', function(d) {{ return d.source.x; }})
        .attr('y1', function(d) {{ return d.source.y; }})
        .attr('x2', function(d) {{ return d.target.x; }})
        .attr('y2', function(d) {{ return d.target.y; }});
      node.attr('transform', function(d) {{ return 'translate(' + d.x + ',' + d.y + ')'; }});
    }});

    // Auto-fit after simulation stabilizes
    simulation.on('end', function() {{
      var bounds = g.node().getBBox();
      if (bounds.width > 0 && bounds.height > 0) {{
        var pad = 40;
        var scale = Math.min(
          (width - 2 * pad) / bounds.width,
          (height - 2 * pad) / bounds.height,
          1.5
        );
        var tx = width / 2 - (bounds.x + bounds.width / 2) * scale;
        var ty = height / 2 - (bounds.y + bounds.height / 2) * scale;
        svg.transition().duration(500).call(
          zoomBehavior.transform,
          d3.zoomIdentity.translate(tx, ty).scale(scale)
        );
      }}
    }});

    // Tooltip
    var tip = document.getElementById('tip');
    node.on('mouseover', function(event, d) {{
      if (d.tip) {{ tip.textContent = d.tip; tip.style.display = 'block'; }}
    }});
    node.on('mousemove', function(event) {{
      if (tip.style.display === 'block') {{
        tip.style.left = (event.clientX + 14) + 'px';
        tip.style.top  = (event.clientY + 14) + 'px';
      }}
    }});
    node.on('mouseout', function() {{ tip.style.display = 'none'; }});

    // Click to highlight + sidebar
    var sidebar = document.getElementById('nodeDetailSidebar');
    var sidebarCloseBtn = document.getElementById('sidebarClose');

    function getNeighborIds(nodeId) {{
      var ids = new Set();
      gLinks.forEach(function(l) {{
        var sid = typeof l.source === 'object' ? l.source.id : l.source;
        var tid = typeof l.target === 'object' ? l.target.id : l.target;
        if (sid === nodeId) ids.add(tid);
        if (tid === nodeId) ids.add(sid);
      }});
      return ids;
    }}

    function showSidebar(d) {{
      var t = d.type || '';
      var typeLabels = {{'provider':'Provider','agent':'Agent','server_clean':'MCP Server','server_cred':'MCP Server','server_vuln':'MCP Server','pkg_vuln':'Package'}};
      var typeLabel = typeLabels[t] || (t.indexOf('cve_')===0 ? 'Vulnerability' : t);
      var typeColors = {{'provider':'#818cf8','agent':'#3b82f6','server_clean':'#10b981','server_cred':'#f59e0b','server_vuln':'#ef4444','pkg_vuln':'#dc2626'}};
      var badgeColor = typeColors[t] || (t.indexOf('cve_')===0 ? '#f87171' : '#64748b');

      document.getElementById('sidebarNodeType').textContent = typeLabel;
      document.getElementById('sidebarNodeType').style.borderColor = badgeColor;
      document.getElementById('sidebarNodeType').style.color = badgeColor;
      document.getElementById('sidebarNodeName').textContent = (d.label || d.id || '').replace('\\n', ' ');

      ['sidebarMeta','sidebarConnected','sidebarCredentials','sidebarCves','sidebarRemediation'].forEach(function(id) {{
        document.getElementById(id).innerHTML = '';
      }});

      // Connected nodes
      var nids = getNeighborIds(d.id);
      if (nids.size > 0) {{
        var h = '<div class="sidebar-label">Connected (' + nids.size + ')</div><ul class="sidebar-list">';
        nids.forEach(function(nid) {{
          var nb = gNodeMap[nid];
          if (!nb) return;
          var nt = nb.type || '';
          var icon = nt === 'agent' ? '&#x1f916;' : nt.indexOf('server')===0 ? '&#x2699;' : nt === 'pkg_vuln' ? '&#x1f4e6;' : nt.indexOf('cve_')===0 ? '&#x1f41b;' : '&#x25cf;';
          h += '<li>' + icon + ' ' + (nb.label || nb.id || '').replace('\\n',' ') + '</li>';
        }});
        h += '</ul>';
        document.getElementById('sidebarConnected').innerHTML = h;
      }}

      // Agent
      if (t === 'agent') {{
        var meta = '';
        if (d.agentType) meta += 'Type: ' + d.agentType + '\\n';
        if (d.source) meta += 'Source: ' + d.source + '\\n';
        if (d.configPath) meta += 'Config: ' + d.configPath;
        document.getElementById('sidebarMeta').textContent = meta;
        var s = '<div class="sidebar-label">Statistics</div><ul class="sidebar-list">';
        s += '<li>Servers: ' + (d.serverCount || 0) + '</li>';
        s += '<li>Packages: ' + (d.packageCount || 0) + '</li>';
        if (d.vulnCount) s += '<li style="color:#f87171">Vulnerabilities: ' + d.vulnCount + '</li>';
        s += '</ul>';
        document.getElementById('sidebarRemediation').innerHTML = s;
      }}

      // Server
      if (t.indexOf('server_')===0) {{
        if (d.command) document.getElementById('sidebarMeta').textContent = d.command;
        var creds = []; try {{ creds = JSON.parse(d.credentials || '[]'); }} catch(e) {{}}
        if (creds.length > 0) {{
          var ch = '<div class="sidebar-label">Credentials (' + creds.length + ')</div><ul class="sidebar-list">';
          creds.forEach(function(c) {{ ch += '<li>&#x1f511; <span class="sidebar-cred">' + c + '</span></li>'; }});
          ch += '</ul>';
          document.getElementById('sidebarCredentials').innerHTML = ch;
        }}
        var tools = []; try {{ tools = JSON.parse(d.toolNames || '[]'); }} catch(e) {{}}
        if (tools.length > 0) {{
          var th = '<div class="sidebar-label">MCP Tools (' + tools.length + ')</div><ul class="sidebar-list">';
          tools.forEach(function(tl) {{ th += '<li>&#x1f527; ' + tl + '</li>'; }});
          th += '</ul>';
          document.getElementById('sidebarRemediation').innerHTML = th;
        }}
        var ph = '<div class="sidebar-label">Packages</div><ul class="sidebar-list">';
        ph += '<li>Total: ' + (d.packageCount || 0) + '</li>';
        if (d.vulnCount) ph += '<li style="color:#f87171">Vulnerable: ' + d.vulnCount + '</li>';
        ph += '</ul>';
        document.getElementById('sidebarCves').innerHTML = ph;
      }}

      // Package
      if (t === 'pkg_vuln') {{
        document.getElementById('sidebarMeta').textContent = (d.ecosystem || '') + ' \\u00b7 ' + (d.version || '');
        var vids = []; try {{ vids = JSON.parse(d.vulnIds || '[]'); }} catch(e) {{}}
        if (vids.length > 0) {{
          var vh = '<div class="sidebar-label">CVEs (' + vids.length + ')</div><ul class="sidebar-list">';
          vids.forEach(function(vid) {{
            vh += '<li><a class="sidebar-link" href="https://osv.dev/vulnerability/' + vid + '" target="_blank" rel="noopener noreferrer">' + vid + ' &#x2197;</a></li>';
          }});
          vh += '</ul>';
          document.getElementById('sidebarCves').innerHTML = vh;
        }}
      }}

      // CVE
      if (t.indexOf('cve_')===0) {{
        var sev = t.replace('cve_', '');
        var mp = [];
        if (sev) mp.push('Severity: ' + sev.toUpperCase());
        if (d.cvssScore) mp.push('CVSS: ' + d.cvssScore);
        document.getElementById('sidebarMeta').textContent = mp.join(' \\u00b7 ');
        if (d.summary) {{
          document.getElementById('sidebarCredentials').innerHTML = '<div class="sidebar-label">Summary</div><p style="font-size:.8rem;color:#cbd5e1;margin:0">' + d.summary + '</p>';
        }}
        var rh = '<div class="sidebar-label">Remediation</div><ul class="sidebar-list">';
        if (d.fixVersion) {{
          rh += '<li style="color:#4ade80">&#x2705; Fix: upgrade to <code>' + d.fixVersion + '</code></li>';
        }} else {{
          rh += '<li style="color:#f59e0b">&#x26a0; No fix available</li>';
        }}
        var lbl = d.label || '';
        rh += '<li><a class="sidebar-link" href="https://osv.dev/vulnerability/' + lbl + '" target="_blank" rel="noopener noreferrer">View on OSV &#x2197;</a></li>';
        rh += '<li><a class="sidebar-link" href="https://nvd.nist.gov/vuln/detail/' + lbl + '" target="_blank" rel="noopener noreferrer">View on NVD &#x2197;</a></li>';
        rh += '</ul>';
        document.getElementById('sidebarRemediation').innerHTML = rh;
      }}

      sidebar.classList.add('open');
      sidebar.style.display = 'block';
    }}

    function closeSidebar() {{
      sidebar.classList.remove('open');
      setTimeout(function() {{ sidebar.style.display = 'none'; }}, 250);
    }}

    sidebarCloseBtn.addEventListener('click', closeSidebar);

    node.on('click', function(event, d) {{
      event.stopPropagation();
      // Remove all highlights
      node.classed('faded', false).classed('highlighted', false);
      link.classed('faded', false);

      var nids = getNeighborIds(d.id);
      nids.add(d.id);

      node.classed('faded', function(n) {{ return !nids.has(n.id); }});
      link.classed('faded', function(l) {{
        var sid = typeof l.source === 'object' ? l.source.id : l.source;
        var tid = typeof l.target === 'object' ? l.target.id : l.target;
        return !nids.has(sid) || !nids.has(tid);
      }});
      d3.select(this).classed('highlighted', true);
      showSidebar(d);
    }});

    svg.on('click', function(event) {{
      if (event.target === svg.node() || event.target.tagName === 'svg') {{
        node.classed('faded', false).classed('highlighted', false);
        link.classed('faded', false);
        closeSidebar();
      }}
    }});

    // Graph controls
    document.getElementById('zoomIn').addEventListener('click', function() {{
      svg.transition().duration(200).call(zoomBehavior.scaleBy, 1.3);
    }});
    document.getElementById('zoomOut').addEventListener('click', function() {{
      svg.transition().duration(200).call(zoomBehavior.scaleBy, 1 / 1.3);
    }});
    document.getElementById('fitBtn').addEventListener('click', function() {{
      var bounds = g.node().getBBox();
      if (bounds.width > 0) {{
        var pad = 40;
        var scale = Math.min((width - 2*pad)/bounds.width, (height - 2*pad)/bounds.height, 1.5);
        var tx = width/2 - (bounds.x + bounds.width/2)*scale;
        var ty = height/2 - (bounds.y + bounds.height/2)*scale;
        svg.transition().duration(400).call(
          zoomBehavior.transform,
          d3.zoomIdentity.translate(tx, ty).scale(scale)
        );
      }}
    }});
    document.getElementById('fullscreenBtn').addEventListener('click', function() {{
      var gc = document.querySelector('.graph-container');
      if (!document.fullscreenElement) {{
        gc.requestFullscreen().then(function() {{
          setTimeout(function() {{
            var fw = gc.clientWidth, fh = gc.clientHeight;
            svg.attr('width', fw).attr('height', fh);
            var bounds = g.node().getBBox();
            if (bounds.width > 0) {{
              var scale = Math.min((fw-80)/bounds.width, (fh-80)/bounds.height, 2);
              var tx = fw/2 - (bounds.x + bounds.width/2)*scale;
              var ty = fh/2 - (bounds.y + bounds.height/2)*scale;
              svg.call(zoomBehavior.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
            }}
          }}, 100);
        }}).catch(function() {{}});
      }} else {{
        document.exitFullscreen();
      }}
    }});
    document.addEventListener('fullscreenchange', function() {{
      if (!document.fullscreenElement) {{
        svg.attr('width', width).attr('height', height);
        setTimeout(function() {{
          var bounds = g.node().getBBox();
          if (bounds.width > 0) {{
            var scale = Math.min((width-80)/bounds.width, (height-80)/bounds.height, 1.5);
            var tx = width/2 - (bounds.x + bounds.width/2)*scale;
            var ty = height/2 - (bounds.y + bounds.height/2)*scale;
            svg.transition().duration(300).call(
              zoomBehavior.transform, d3.zoomIdentity.translate(tx, ty).scale(scale)
            );
          }}
        }}, 100);
      }}
    }});

    // Graph severity filter
    document.querySelectorAll('.graph-sev-filter').forEach(function(cb) {{
      cb.addEventListener('change', function() {{
        var checked = Array.from(document.querySelectorAll('.graph-sev-filter:checked')).map(function(c) {{ return c.value; }});
        node.each(function(d) {{
          var t = d.type || '';
          if (t.indexOf('cve_') === 0) {{
            var sev = t.replace('cve_', '');
            var show = checked.indexOf(sev) !== -1;
            d3.select(this).style('display', show ? null : 'none');
          }}
        }});
        link.each(function(l) {{
          var sid = typeof l.source === 'object' ? l.source : gNodeMap[l.source];
          var tid = typeof l.target === 'object' ? l.target : gNodeMap[l.target];
          if (sid && (sid.type||'').indexOf('cve_')===0) {{
            var sev = sid.type.replace('cve_','');
            d3.select(this).style('display', checked.indexOf(sev) !== -1 ? null : 'none');
          }}
          if (tid && (tid.type||'').indexOf('cve_')===0) {{
            var sev = tid.type.replace('cve_','');
            d3.select(this).style('display', checked.indexOf(sev) !== -1 ? null : 'none');
          }}
        }});
      }});
    }});

    // Graph search
    var graphSearchInput = document.getElementById('graphSearch');
    if (graphSearchInput) {{
      graphSearchInput.addEventListener('input', function() {{
        var q = this.value.toLowerCase();
        if (!q) {{
          node.classed('faded', false).classed('highlighted', false);
          link.classed('faded', false);
          return;
        }}
        var matchedIds = new Set();
        gNodes.forEach(function(n) {{
          if ((n.label || '').toLowerCase().indexOf(q) >= 0) matchedIds.add(n.id);
        }});
        // Expand to neighbors
        var hoodIds = new Set(matchedIds);
        matchedIds.forEach(function(mid) {{
          var nids = getNeighborIds(mid);
          nids.forEach(function(nid) {{ hoodIds.add(nid); }});
        }});
        if (matchedIds.size > 0) {{
          node.classed('faded', function(n) {{ return !hoodIds.has(n.id); }});
          node.classed('highlighted', function(n) {{ return matchedIds.has(n.id); }});
          link.classed('faded', function(l) {{
            var sid = typeof l.source === 'object' ? l.source.id : l.source;
            var tid = typeof l.target === 'object' ? l.target.id : l.target;
            return !hoodIds.has(sid) || !hoodIds.has(tid);
          }});
        }} else {{
          node.classed('faded', true).classed('highlighted', false);
          link.classed('faded', true);
        }}
      }});
    }}
  }} else if (cyContainer) {{
    cyContainer.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:600px;color:#4ade80;font-size:.9rem">&#x2705; No supply chain nodes to display</div>';
  }}

  // Vulnerability table filtering
  function filterVulnTable() {{
    var table = document.getElementById('vulnTable');
    if (!table) return;
    var rows = table.querySelectorAll('tbody tr');
    var checkedSevs = Array.from(document.querySelectorAll('.vuln-sev-filter:checked')).map(function(c) {{ return c.value; }});
    var kevOnly = document.getElementById('kevToggle') && document.getElementById('kevToggle').checked;
    var q = (document.getElementById('vulnSearch') || {{}}).value || '';
    q = q.toLowerCase();
    var visible = 0;
    rows.forEach(function(row) {{
      var sev = row.getAttribute('data-severity') || '';
      var kev = row.getAttribute('data-kev') === '1';
      var text = row.textContent.toLowerCase();
      var show = true;
      if (checkedSevs.indexOf(sev) === -1) show = false;
      if (kevOnly && !kev) show = false;
      if (q && text.indexOf(q) === -1) show = false;
      row.style.display = show ? '' : 'none';
      if (show) visible++;
    }});
  }}
  document.querySelectorAll('.vuln-sev-filter').forEach(function(cb) {{
    cb.addEventListener('change', filterVulnTable);
  }});
  var kevToggle = document.getElementById('kevToggle');
  if (kevToggle) kevToggle.addEventListener('change', filterVulnTable);
  var vulnSearchInput = document.getElementById('vulnSearch');
  if (vulnSearchInput) vulnSearchInput.addEventListener('input', filterVulnTable);

  // D3.js: CVE Attack Flow graph
  var AF_STYLES = {{
    'cve_critical':  {{ fill:'#7f1d1d', stroke:'#ef4444', strokeW:3, w:130, h:38, fontSize:9, fontWeight:700, color:'#fecaca', shape:'diamond' }},
    'cve_high':      {{ fill:'#9a3412', stroke:'#fb923c', strokeW:2.5, w:120, h:34, fontSize:9, fontWeight:700, color:'#fed7aa', shape:'diamond' }},
    'cve_medium':    {{ fill:'#854d0e', stroke:'#fbbf24', strokeW:1.5, w:100, h:28, fontSize:9, fontWeight:700, color:'#fef08a', shape:'diamond' }},
    'cve_low':       {{ fill:'#854d0e', stroke:'#fbbf24', strokeW:1.5, w:100, h:28, fontSize:9, fontWeight:700, color:'#fef08a', shape:'diamond' }},
    'cve_none':      {{ fill:'#854d0e', stroke:'#fbbf24', strokeW:1.5, w:100, h:28, fontSize:9, fontWeight:700, color:'#fef08a', shape:'diamond' }},
    'pkg_vuln':      {{ fill:'#7f1d1d', stroke:'#dc2626', strokeW:2, w:130, h:38, fontSize:9, fontWeight:700, color:'#fca5a5', shape:'rect' }},
    'server':        {{ fill:'#1e293b', stroke:'#475569', strokeW:2, w:120, h:36, fontSize:10, fontWeight:600, color:'#cbd5e1', shape:'rect' }},
    'credential':    {{ fill:'#78350f', stroke:'#fbbf24', strokeW:2, w:100, h:32, fontSize:9, fontWeight:700, color:'#fde68a', shape:'diamond' }},
    'tool':          {{ fill:'#312e81', stroke:'#818cf8', strokeW:2, w:100, h:30, fontSize:9, fontWeight:400, color:'#c7d2fe', shape:'rect' }},
    'agent':         {{ fill:'#1e3a8a', stroke:'#3b82f6', strokeW:2, w:120, h:38, fontSize:11, fontWeight:700, color:'#bfdbfe', shape:'rect' }},
  }};
  function getAFStyle(type) {{
    return AF_STYLES[type] || AF_STYLES['server'];
  }}

  var AF_EDGE_COLORS = {{
    'exploits':    {{ stroke:'#dc2626', opacity:0.8, dash:'', width:2.5 }},
    'runs_on':     {{ stroke:'#475569', opacity:0.6, dash:'', width:1.8 }},
    'exposes':     {{ stroke:'#f59e0b', opacity:0.7, dash:'6,3', width:2 }},
    'reaches':     {{ stroke:'#818cf8', opacity:0.6, dash:'4,4', width:1.8 }},
    'compromises': {{ stroke:'#ef4444', opacity:0.7, dash:'8,4', width:2.5 }},
  }};
  function getAFEdgeStyle(type) {{
    return AF_EDGE_COLORS[type] || {{ stroke:'#334155', opacity:0.6, dash:'', width:1.8 }};
  }}

  var AF_RANK = {{ 'cve_critical':0, 'cve_high':0, 'cve_medium':0, 'cve_low':0, 'cve_none':0, 'pkg_vuln':1, 'server':2, 'credential':3, 'tool':3, 'agent':3 }};

  var cyAtkContainer = document.getElementById('cyAttack');
  if (cyAtkContainer && ATTACK_FLOW.length > 0) {{
    var afData = cytoToD3(ATTACK_FLOW);
    var afNodes = afData.nodes;
    var afLinks = afData.links;
    var afNodeMap = afData.nodeMap;

    var afW = cyAtkContainer.clientWidth || 900;
    var afH = 500;
    var afSvg = d3.select('#cyAttack').append('svg')
      .attr('width', afW).attr('height', afH);

    // Arrow markers for attack flow
    var afDefs = afSvg.append('defs');
    ['af-default','af-exploits','af-exposes','af-compromises','af-reaches'].forEach(function(key) {{
      var colors = {{ 'af-exploits':'#ef4444','af-exposes':'#fbbf24','af-compromises':'#f87171','af-reaches':'#a5b4fc' }};
      var ec = colors[key] || '#475569';
      afDefs.append('marker')
        .attr('id', key)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20).attr('refY', 0)
        .attr('markerWidth', 6).attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', ec);
    }});

    var afG = afSvg.append('g');

    var afZoom = d3.zoom()
      .scaleExtent([0.15, 4])
      .on('zoom', function(event) {{ afG.attr('transform', event.transform); }});
    afSvg.call(afZoom);

    var afRankSpacing = afW / 5;
    afNodes.forEach(function(n) {{
      var rank = AF_RANK[n.type] !== undefined ? AF_RANK[n.type] : 2;
      n.x = rank * afRankSpacing + afRankSpacing * 0.5;
      n.y = afH / 2 + (Math.random() - 0.5) * afH * 0.6;
    }});

    var afSim = d3.forceSimulation(afNodes)
      .force('link', d3.forceLink(afLinks).id(function(d) {{ return d.id; }}).distance(120).strength(0.6))
      .force('charge', d3.forceManyBody().strength(-250))
      .force('x', d3.forceX(function(d) {{
        var rank = AF_RANK[d.type] !== undefined ? AF_RANK[d.type] : 2;
        return rank * afRankSpacing + afRankSpacing * 0.5;
      }}).strength(0.4))
      .force('y', d3.forceY(afH / 2).strength(0.1))
      .force('collision', d3.forceCollide(function(d) {{
        var s = getAFStyle(d.type);
        return Math.max(s.w, s.h) / 2 + 6;
      }}));

    var afLink = afG.append('g').attr('class', 'links').selectAll('line')
      .data(afLinks).enter().append('line')
      .attr('class', 'link')
      .attr('stroke', function(d) {{ return getAFEdgeStyle(d.type).stroke; }})
      .attr('stroke-opacity', function(d) {{ return getAFEdgeStyle(d.type).opacity; }})
      .attr('stroke-width', function(d) {{ return getAFEdgeStyle(d.type).width; }})
      .attr('stroke-dasharray', function(d) {{ return getAFEdgeStyle(d.type).dash; }})
      .attr('marker-end', function(d) {{
        if (d.type === 'exploits') return 'url(#af-exploits)';
        if (d.type === 'exposes') return 'url(#af-exposes)';
        if (d.type === 'compromises') return 'url(#af-compromises)';
        if (d.type === 'reaches') return 'url(#af-reaches)';
        return 'url(#af-default)';
      }});

    var afNode = afG.append('g').attr('class', 'nodes').selectAll('g')
      .data(afNodes).enter().append('g')
      .attr('class', 'node-group')
      .call(d3.drag()
        .on('start', function(event, d) {{
          if (!event.active) afSim.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        }})
        .on('drag', function(event, d) {{ d.fx = event.x; d.fy = event.y; }})
        .on('end', function(event, d) {{
          if (!event.active) afSim.alphaTarget(0);
          d.fx = null; d.fy = null;
        }})
      );

    afNode.each(function(d) {{
      var el = d3.select(this);
      var s = getAFStyle(d.type);
      if (s.shape === 'diamond') {{
        var hw = s.w / 2, hh = s.h / 2;
        el.append('polygon')
          .attr('points', '0,' + (-hh) + ' ' + hw + ',0 0,' + hh + ' ' + (-hw) + ',0')
          .attr('fill', s.fill).attr('stroke', s.stroke).attr('stroke-width', s.strokeW);
      }} else {{
        el.append('rect')
          .attr('x', -s.w / 2).attr('y', -s.h / 2)
          .attr('width', s.w).attr('height', s.h)
          .attr('rx', 8).attr('ry', 8)
          .attr('fill', s.fill).attr('stroke', s.stroke).attr('stroke-width', s.strokeW);
      }}
    }});

    afNode.each(function(d) {{
      var el = d3.select(this);
      var s = getAFStyle(d.type);
      var lines = (d.label || d.id || '').split('\\n');
      var lineH = s.fontSize + 2;
      var startY = -(lines.length - 1) * lineH / 2;
      lines.forEach(function(line, i) {{
        el.append('text')
          .attr('class', 'node-label')
          .attr('text-anchor', 'middle')
          .attr('dy', startY + i * lineH + s.fontSize * 0.35)
          .attr('fill', s.color)
          .attr('font-size', s.fontSize + 'px')
          .attr('font-weight', s.fontWeight)
          .text(line.length > 18 ? line.slice(0, 17) + '\u2026' : line);
      }});
    }});

    afSim.on('tick', function() {{
      afLink
        .attr('x1', function(d) {{ return d.source.x; }})
        .attr('y1', function(d) {{ return d.source.y; }})
        .attr('x2', function(d) {{ return d.target.x; }})
        .attr('y2', function(d) {{ return d.target.y; }});
      afNode.attr('transform', function(d) {{ return 'translate(' + d.x + ',' + d.y + ')'; }});
    }});

    afSim.on('end', function() {{
      var bounds = afG.node().getBBox();
      if (bounds.width > 0 && bounds.height > 0) {{
        var pad = 40;
        var scale = Math.min((afW - 2*pad)/bounds.width, (afH - 2*pad)/bounds.height, 1.5);
        var tx = afW/2 - (bounds.x + bounds.width/2)*scale;
        var ty = afH/2 - (bounds.y + bounds.height/2)*scale;
        afSvg.transition().duration(500).call(
          afZoom.transform,
          d3.zoomIdentity.translate(tx, ty).scale(scale)
        );
      }}
    }});

    // Attack flow tooltip
    if (!tip) var tip = document.getElementById('tip');
    afNode.on('mouseover', function(event, d) {{
      if (d.tip) {{ tip.textContent = d.tip; tip.style.display = 'block'; }}
    }});
    afNode.on('mousemove', function(event) {{
      if (tip.style.display === 'block') {{
        tip.style.left = (event.clientX + 14) + 'px';
        tip.style.top  = (event.clientY + 14) + 'px';
      }}
    }});
    afNode.on('mouseout', function() {{ tip.style.display = 'none'; }});

    // Attack flow click to highlight
    function getAFNeighborIds(nodeId) {{
      var ids = new Set();
      afLinks.forEach(function(l) {{
        var sid = typeof l.source === 'object' ? l.source.id : l.source;
        var tid = typeof l.target === 'object' ? l.target.id : l.target;
        if (sid === nodeId) ids.add(tid);
        if (tid === nodeId) ids.add(sid);
      }});
      return ids;
    }}

    afNode.on('click', function(event, d) {{
      event.stopPropagation();
      afNode.classed('faded', false).classed('highlighted', false);
      afLink.classed('faded', false);
      var nids = getAFNeighborIds(d.id);
      nids.add(d.id);
      afNode.classed('faded', function(n) {{ return !nids.has(n.id); }});
      afLink.classed('faded', function(l) {{
        var sid = typeof l.source === 'object' ? l.source.id : l.source;
        var tid = typeof l.target === 'object' ? l.target.id : l.target;
        return !nids.has(sid) || !nids.has(tid);
      }});
      d3.select(this).classed('highlighted', true);
    }});
    afSvg.on('click', function(event) {{
      if (event.target === afSvg.node() || event.target.tagName === 'svg') {{
        afNode.classed('faded', false).classed('highlighted', false);
        afLink.classed('faded', false);
      }}
    }});

    // Attack flow controls
    var afZoomInBtn = document.getElementById('afZoomIn');
    var afZoomOutBtn = document.getElementById('afZoomOut');
    var afFitBtnEl = document.getElementById('afFitBtn');
    if (afZoomInBtn) afZoomInBtn.addEventListener('click', function() {{
      afSvg.transition().duration(200).call(afZoom.scaleBy, 1.3);
    }});
    if (afZoomOutBtn) afZoomOutBtn.addEventListener('click', function() {{
      afSvg.transition().duration(200).call(afZoom.scaleBy, 1/1.3);
    }});
    if (afFitBtnEl) afFitBtnEl.addEventListener('click', function() {{
      var bounds = afG.node().getBBox();
      if (bounds.width > 0) {{
        var pad = 40;
        var scale = Math.min((afW-2*pad)/bounds.width, (afH-2*pad)/bounds.height, 1.5);
        var tx = afW/2 - (bounds.x + bounds.width/2)*scale;
        var ty = afH/2 - (bounds.y + bounds.height/2)*scale;
        afSvg.transition().duration(400).call(
          afZoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale)
        );
      }}
    }});
  }}

  // Table sorting
  document.querySelectorAll('.data-table.sortable th').forEach(function(th) {{
    th.addEventListener('click', function() {{
      var table = th.closest('table');
      var tbody = table.querySelector('tbody');
      var rows = Array.from(tbody.querySelectorAll('tr'));
      var col = parseInt(th.getAttribute('data-col'));
      var arrow = th.querySelector('.sort-arrow');
      var asc = !arrow.classList.contains('asc');

      table.querySelectorAll('.sort-arrow').forEach(function(a) {{ a.className = 'sort-arrow'; }});
      arrow.className = 'sort-arrow ' + (asc ? 'asc' : 'desc');

      rows.sort(function(a, b) {{
        var at = (a.children[col] || {{}}).textContent || '';
        var bt = (b.children[col] || {{}}).textContent || '';
        var an = parseFloat(at.replace(/[^\\d.-]/g, ''));
        var bn = parseFloat(bt.replace(/[^\\d.-]/g, ''));
        if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
        return asc ? at.localeCompare(bt) : bt.localeCompare(at);
      }});
      rows.forEach(function(r) {{ tbody.appendChild(r); }});
    }});
  }});

  // Inventory search
  var searchInput = document.getElementById('invSearch');
  if (searchInput) {{
    searchInput.addEventListener('input', function() {{
      var q = this.value.toLowerCase();
      document.querySelectorAll('.agent-card').forEach(function(card) {{
        var text = card.textContent.toLowerCase();
        card.style.display = text.includes(q) ? '' : 'none';
      }});
    }});
  }}

  // Package list toggle
  window.togglePkgs = function(id, btn) {{
    var el = document.getElementById(id);
    if (!el) return;
    var hidden = el.style.display === 'none';
    el.style.display = hidden ? 'block' : 'none';
    btn.innerHTML = hidden
      ? 'Show fewer &#x25B2;'
      : btn.dataset.orig || btn.innerHTML;
    if (hidden && !btn.dataset.orig) btn.dataset.orig = btn.innerHTML;
  }};

  // Smooth scroll
  document.querySelectorAll('a[href^="#"]').forEach(function(a) {{
    a.addEventListener('click', function(e) {{
      e.preventDefault();
      var el = document.querySelector(a.getAttribute('href'));
      if (el) el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
    }});
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
