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
        '<div id="cyAttack" class="cy-graph"></div>'
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
  <script src="https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"></script>
  <script src="https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"></script>
  <script src="https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js"></script>
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
    .graph-container:fullscreen .cy-graph{{height:100vh}}
    .cy-graph{{width:100%;height:600px;background:#0f172a}}
    #cy{{width:100%;height:600px}}
    #cyAttack{{width:100%;height:500px}}
    .graph-controls{{position:absolute;top:12px;right:12px;display:flex;flex-direction:column;gap:4px;z-index:10}}
    .graph-btn{{width:36px;height:36px;border-radius:8px;border:1px solid #334155;background:rgba(15,23,42,.85);color:#94a3b8;font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;backdrop-filter:blur(8px)}}
    .graph-btn:hover{{background:#1e293b;color:#e2e8f0;border-color:#475569}}
    .legend{{display:flex;gap:20px;flex-wrap:wrap;font-size:.76rem;color:#64748b;margin-top:12px;padding:0 4px}}
    .legend span{{display:flex;align-items:center;gap:6px}}
    .legend i{{display:inline-block;width:10px;height:10px;border-radius:3px}}
    .legend i.diamond{{transform:rotate(45deg);border-radius:1px}}

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
      nav,.graph-controls,.graph-filter-bar,.vuln-filter-bar,.toggle-btn,.inv-search,.print-btn{{display:none}}
      .container{{max-width:100%;padding:10px}}
      section{{page-break-inside:avoid;margin-bottom:20px}}
      .panel,.stat-card,.agent-card,.server-card,.chart-panel{{background:#f8fafc;border:1px solid #e2e8f0;box-shadow:none}}
      .stat-value,.sec-title{{color:#0f172a}}
      .data-table th{{background:#f1f5f9;color:#334155;border-bottom:2px solid #cbd5e1}}
      .data-table td{{border-bottom:1px solid #e2e8f0}}
      #cy{{height:400px;background:#f8fafc;border:1px solid #e2e8f0}}
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

  <!-- Skill audit -->
  {skill_section}

  <!-- Attack flow graph (only when vulns exist) -->
  {_attack_flow_section(blast_radii)}

  <!-- Vuln / Blast / Remediation -->
  {vuln_sections}

</div>

<footer>
  Generated by <strong style="color:#475569">agent-bom</strong> v{_esc(report.tool_version)} &middot;
  <a href="https://github.com/agent-bom/agent-bom">github.com/agent-bom/agent-bom</a> &middot;
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

  // Cytoscape: Supply chain graph with dagre hierarchical layout
  var cyContainer = document.getElementById('cy');
  if (cyContainer && GRAPH_ELEMENTS.length > 0) {{
    var cy = cytoscape({{
      container: cyContainer,
      elements: GRAPH_ELEMENTS,
      style: [
        {{
          selector: 'node[type="provider"]',
          style: {{
            'background-color': '#1e1b4b',
            'border-color': '#818cf8',
            'border-width': 3,
            'label': 'data(label)',
            'color': '#c7d2fe',
            'font-size': '13px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 140,
            'height': 44,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '125px',
          }},
        }},
        {{
          selector: 'node[type="agent"]',
          style: {{
            'background-color': '#1e3a8a',
            'border-color': '#3b82f6',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#bfdbfe',
            'font-size': '12px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 40,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '105px',
          }},
        }},
        {{
          selector: 'node[type="server_clean"]',
          style: {{
            'background-color': '#052e16',
            'border-color': '#10b981',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#6ee7b7',
            'font-size': '10px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          }},
        }},
        {{
          selector: 'node[type="server_cred"]',
          style: {{
            'background-color': '#431407',
            'border-color': '#f59e0b',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fde68a',
            'font-size': '10px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          }},
        }},
        {{
          selector: 'node[type="server_vuln"]',
          style: {{
            'background-color': '#450a0a',
            'border-color': '#ef4444',
            'border-width': 2.5,
            'label': 'data(label)',
            'color': '#fca5a5',
            'font-size': '10px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          }},
        }},
        {{
          selector: 'node[type="pkg_vuln"]',
          style: {{
            'background-color': '#7f1d1d',
            'border-color': '#dc2626',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fca5a5',
            'font-size': '9px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 130,
            'height': 38,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '120px',
          }},
        }},
        {{
          selector: 'node[type^="cve_critical"]',
          style: {{
            'background-color': '#991b1b',
            'border-color': '#f87171',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fecaca',
            'font-size': '8px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 110,
            'height': 30,
            'shape': 'diamond',
          }},
        }},
        {{
          selector: 'node[type^="cve_high"]',
          style: {{
            'background-color': '#9a3412',
            'border-color': '#fb923c',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fed7aa',
            'font-size': '8px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 100,
            'height': 28,
            'shape': 'diamond',
          }},
        }},
        {{
          selector: 'node[type^="cve_medium"], node[type^="cve_low"], node[type^="cve_none"]',
          style: {{
            'background-color': '#854d0e',
            'border-color': '#fbbf24',
            'border-width': 1.5,
            'label': 'data(label)',
            'color': '#fef08a',
            'font-size': '8px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 90,
            'height': 26,
            'shape': 'diamond',
          }},
        }},
        {{
          selector: 'edge',
          style: {{
            'width': 1.8,
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
          }},
        }},
        {{
          selector: 'edge[type="hosts"]',
          style: {{
            'line-color': '#818cf850',
            'target-arrow-color': '#818cf880',
            'line-style': 'dashed',
            'line-dash-pattern': [6, 3],
          }},
        }},
        {{
          selector: 'edge[type="affects"]',
          style: {{
            'line-color': '#dc262650',
            'target-arrow-color': '#dc262680',
          }},
        }},
        {{
          selector: '.highlighted',
          style: {{
            'border-width': 4,
            'border-color': '#f1f5f9',
            'z-index': 999,
          }},
        }},
        {{
          selector: '.faded',
          style: {{ 'opacity': 0.08 }},
        }},
      ],
      layout: {{
        name: 'dagre',
        rankDir: 'LR',
        nodeSep: 50,
        rankSep: 80,
        edgeSep: 15,
        padding: 30,
        animate: false,
        fit: true,
      }},
      minZoom: 0.15,
      maxZoom: 4,
      wheelSensitivity: 0.3,
      autoungrabify: false,
    }});
    cy.ready(function() {{ cy.fit(cy.elements(), 40); }});

    // Tooltip
    var tip = document.getElementById('tip');
    cy.on('mouseover', 'node', function(e) {{
      var t = e.target.data('tip');
      if (t) {{ tip.textContent = t; tip.style.display = 'block'; }}
    }});
    cy.on('mousemove', function(e) {{
      if (tip.style.display === 'block') {{
        tip.style.left = (e.originalEvent.clientX + 14) + 'px';
        tip.style.top  = (e.originalEvent.clientY + 14) + 'px';
      }}
    }});
    cy.on('mouseout', 'node', function() {{ tip.style.display = 'none'; }});

    // Click to highlight
    cy.on('tap', 'node', function(e) {{
      cy.elements().removeClass('faded highlighted');
      var hood = e.target.closedNeighborhood();
      cy.elements().not(hood).addClass('faded');
      e.target.addClass('highlighted');
    }});
    cy.on('tap', function(e) {{
      if (e.target === cy) {{
        cy.elements().removeClass('faded highlighted');
      }}
    }});

    // Graph controls
    document.getElementById('zoomIn').addEventListener('click', function() {{
      cy.zoom({{ level: cy.zoom() * 1.3, renderedPosition: {{ x: cy.width() / 2, y: cy.height() / 2 }} }});
    }});
    document.getElementById('zoomOut').addEventListener('click', function() {{
      cy.zoom({{ level: cy.zoom() / 1.3, renderedPosition: {{ x: cy.width() / 2, y: cy.height() / 2 }} }});
    }});
    document.getElementById('fitBtn').addEventListener('click', function() {{
      cy.fit(cy.elements(), 40);
    }});
    document.getElementById('fullscreenBtn').addEventListener('click', function() {{
      var gc = document.querySelector('.graph-container');
      if (!document.fullscreenElement) {{
        gc.requestFullscreen().then(function() {{
          setTimeout(function() {{ cy.resize(); cy.fit(cy.elements(), 50); }}, 100);
        }}).catch(function() {{}});
      }} else {{
        document.exitFullscreen();
      }}
    }});
    document.addEventListener('fullscreenchange', function() {{
      if (!document.fullscreenElement) {{
        setTimeout(function() {{ cy.resize(); cy.fit(cy.elements(), 40); }}, 100);
      }}
    }});
    // Graph severity filter
    document.querySelectorAll('.graph-sev-filter').forEach(function(cb) {{
      cb.addEventListener('change', function() {{
        var checked = Array.from(document.querySelectorAll('.graph-sev-filter:checked')).map(function(c) {{ return c.value; }});
        cy.nodes().forEach(function(n) {{
          var t = n.data('type') || '';
          if (t.startsWith('cve_')) {{
            var sev = t.replace('cve_', '');
            if (checked.indexOf(sev) === -1) {{
              n.style('display', 'none');
              n.connectedEdges().style('display', 'none');
            }} else {{
              n.style('display', 'element');
              n.connectedEdges().style('display', 'element');
            }}
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
          cy.elements().removeClass('faded highlighted');
          return;
        }}
        cy.elements().removeClass('faded highlighted');
        var matched = cy.nodes().filter(function(n) {{
          return (n.data('label') || '').toLowerCase().indexOf(q) >= 0;
        }});
        if (matched.length > 0) {{
          var hood = matched.closedNeighborhood();
          cy.elements().not(hood).addClass('faded');
          matched.addClass('highlighted');
        }} else {{
          cy.elements().addClass('faded');
        }}
      }});
    }}
  }} else if (cyContainer) {{
    cyContainer.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#4ade80;font-size:.9rem">&#x2705; No supply chain nodes to display</div>';
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

  // Cytoscape: CVE Attack Flow graph
  var cyAtkContainer = document.getElementById('cyAttack');
  if (cyAtkContainer && ATTACK_FLOW.length > 0) {{
    var cyAtk = cytoscape({{
      container: cyAtkContainer,
      elements: ATTACK_FLOW,
      style: [
        {{
          selector: 'node[type^="cve_"]',
          style: {{
            'shape': 'diamond',
            'width': 120,
            'height': 34,
            'label': 'data(label)',
            'font-size': '9px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'color': '#fecaca',
            'background-color': '#991b1b',
            'border-color': '#f87171',
            'border-width': 2.5,
          }},
        }},
        {{
          selector: 'node[type="cve_critical"]',
          style: {{
            'background-color': '#7f1d1d',
            'border-color': '#ef4444',
            'border-width': 3,
            'width': 130,
            'height': 38,
          }},
        }},
        {{
          selector: 'node[type="cve_high"]',
          style: {{
            'background-color': '#9a3412',
            'border-color': '#fb923c',
            'color': '#fed7aa',
          }},
        }},
        {{
          selector: 'node[type="cve_medium"], node[type="cve_low"], node[type="cve_none"]',
          style: {{
            'background-color': '#854d0e',
            'border-color': '#fbbf24',
            'border-width': 1.5,
            'color': '#fef08a',
            'width': 100,
            'height': 28,
          }},
        }},
        {{
          selector: 'node[type="pkg_vuln"]',
          style: {{
            'background-color': '#7f1d1d',
            'border-color': '#dc2626',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fca5a5',
            'font-size': '9px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 130,
            'height': 38,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '120px',
          }},
        }},
        {{
          selector: 'node[type="server"]',
          style: {{
            'background-color': '#1e293b',
            'border-color': '#475569',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#cbd5e1',
            'font-size': '10px',
            'font-weight': '600',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          }},
        }},
        {{
          selector: 'node[type="credential"]',
          style: {{
            'background-color': '#78350f',
            'border-color': '#fbbf24',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fde68a',
            'font-size': '9px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 100,
            'height': 32,
            'shape': 'hexagon',
          }},
        }},
        {{
          selector: 'node[type="tool"]',
          style: {{
            'background-color': '#312e81',
            'border-color': '#818cf8',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#c7d2fe',
            'font-size': '9px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 100,
            'height': 30,
            'shape': 'round-tag',
            'text-wrap': 'wrap',
            'text-max-width': '90px',
          }},
        }},
        {{
          selector: 'node[type="agent"]',
          style: {{
            'background-color': '#1e3a8a',
            'border-color': '#3b82f6',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#bfdbfe',
            'font-size': '11px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 38,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '105px',
          }},
        }},
        {{
          selector: 'edge',
          style: {{
            'width': 1.8,
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
          }},
        }},
        {{
          selector: 'edge[type="exploits"]',
          style: {{
            'line-color': '#dc2626',
            'target-arrow-color': '#ef4444',
            'width': 2.5,
          }},
        }},
        {{
          selector: 'edge[type="runs_on"]',
          style: {{
            'line-color': '#475569',
            'target-arrow-color': '#64748b',
          }},
        }},
        {{
          selector: 'edge[type="exposes"]',
          style: {{
            'line-color': '#f59e0b',
            'target-arrow-color': '#fbbf24',
            'line-style': 'dashed',
            'line-dash-pattern': [6, 3],
            'width': 2,
          }},
        }},
        {{
          selector: 'edge[type="reaches"]',
          style: {{
            'line-color': '#818cf8',
            'target-arrow-color': '#a5b4fc',
            'line-style': 'dashed',
            'line-dash-pattern': [4, 4],
          }},
        }},
        {{
          selector: 'edge[type="compromises"]',
          style: {{
            'line-color': '#ef4444',
            'target-arrow-color': '#f87171',
            'line-style': 'dashed',
            'line-dash-pattern': [8, 4],
            'width': 2.5,
          }},
        }},
        {{
          selector: '.highlighted',
          style: {{
            'border-width': 4,
            'border-color': '#f1f5f9',
            'z-index': 999,
          }},
        }},
        {{
          selector: '.faded',
          style: {{ 'opacity': 0.08 }},
        }},
      ],
      layout: {{
        name: 'dagre',
        rankDir: 'LR',
        nodeSep: 40,
        rankSep: 100,
        edgeSep: 12,
        padding: 30,
        animate: false,
        fit: true,
      }},
      minZoom: 0.15,
      maxZoom: 4,
      wheelSensitivity: 0.3,
    }});
    cyAtk.ready(function() {{ cyAtk.fit(cyAtk.elements(), 40); }});

    // Attack flow tooltip
    cyAtk.on('mouseover', 'node', function(e) {{
      var t = e.target.data('tip');
      if (t) {{ tip.textContent = t; tip.style.display = 'block'; }}
    }});
    cyAtk.on('mousemove', function(e) {{
      if (tip.style.display === 'block') {{
        tip.style.left = (e.originalEvent.clientX + 14) + 'px';
        tip.style.top  = (e.originalEvent.clientY + 14) + 'px';
      }}
    }});
    cyAtk.on('mouseout', 'node', function() {{ tip.style.display = 'none'; }});

    // Attack flow click to highlight
    cyAtk.on('tap', 'node', function(e) {{
      cyAtk.elements().removeClass('faded highlighted');
      var hood = e.target.closedNeighborhood();
      cyAtk.elements().not(hood).addClass('faded');
      e.target.addClass('highlighted');
    }});
    cyAtk.on('tap', function(e) {{
      if (e.target === cyAtk) {{
        cyAtk.elements().removeClass('faded highlighted');
      }}
    }});

    // Attack flow controls
    var afZoomIn = document.getElementById('afZoomIn');
    var afZoomOut = document.getElementById('afZoomOut');
    var afFitBtn = document.getElementById('afFitBtn');
    if (afZoomIn) afZoomIn.addEventListener('click', function() {{
      cyAtk.zoom({{ level: cyAtk.zoom() * 1.3, renderedPosition: {{ x: cyAtk.width() / 2, y: cyAtk.height() / 2 }} }});
    }});
    if (afZoomOut) afZoomOut.addEventListener('click', function() {{
      cyAtk.zoom({{ level: cyAtk.zoom() / 1.3, renderedPosition: {{ x: cyAtk.width() / 2, y: cyAtk.height() / 2 }} }});
    }});
    if (afFitBtn) afFitBtn.addEventListener('click', function() {{
      cyAtk.fit(cyAtk.elements(), 40);
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
