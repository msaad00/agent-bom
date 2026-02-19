"""Self-contained HTML report generator for AI-BOM scans.

Produces a single ``report.html`` file with:
- Grafana-style dashboard: stat cards, severity donut, blast radius bar chart
- Smart Cytoscape.js risk map — agents → servers → ONLY vulnerable packages
  (clean packages are hidden to prevent graph pollution from large image scans)
- Collapsible agent inventory panels with truncated package lists
- Sortable vulnerability table with severity pill, CVSS bar, EPSS, KEV badge
- Blast radius table ordered by risk score with visual bar
- Remediation plan ordered by impact

No server required — open the file in any browser.
Chart.js + Cytoscape.js loaded from CDN; everything else is inline.
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
    """Build Cytoscape element list.

    Only renders package nodes for VULNERABLE packages — clean packages are
    omitted so scans of large Docker images (2000+ packages) stay readable.
    Server nodes carry a package-count badge in their label.
    """
    elements: list[dict] = []
    vuln_pkg_keys: set[tuple[str, str]] = {
        (br.package.name, br.package.ecosystem) for br in blast_radii
    }

    for agent in report.agents:
        aid = f"a{id(agent)}"
        elements.append({"data": {
            "id": aid,
            "label": agent.name,
            "type": "agent",
            "tip": (
                f"Agent: {agent.name}\n"
                f"Type: {agent.agent_type.value}\n"
                f"Servers: {len(agent.mcp_servers)}"
            ),
        }})

        for srv in agent.mcp_servers:
            sid = f"s{id(srv)}"
            vuln_count = sum(
                1 for p in srv.packages
                if (p.name, p.ecosystem) in vuln_pkg_keys
            )
            has_vuln = vuln_count > 0
            has_cred = srv.has_credentials
            stype = "server_vuln" if has_vuln else ("server_cred" if has_cred else "server_clean")
            pkg_note = f"\nPackages: {len(srv.packages)}" + (f"\nVulnerable: {vuln_count}" if vuln_count else "")
            cinfo = f"\nCredentials: {', '.join(srv.credential_names)}" if has_cred else ""
            pkg_badge = f" ({len(srv.packages)})"

            elements.append({"data": {
                "id": sid,
                "label": srv.name + pkg_badge,
                "type": stype,
                "tip": (
                    f"MCP Server: {srv.name}"
                    f"{pkg_note}"
                    f"{cinfo}"
                ),
            }})
            elements.append({"data": {"source": aid, "target": sid}})

            # Only add package nodes for VULNERABLE packages
            seen_vuln_ids: set[str] = set()
            for pkg in srv.packages:
                if (pkg.name, pkg.ecosystem) not in vuln_pkg_keys:
                    continue
                pid = f"p{pkg.name}{pkg.ecosystem}"
                if pid in seen_vuln_ids:
                    elements.append({"data": {"source": sid, "target": pid}})
                    continue
                seen_vuln_ids.add(pid)
                vc = len(pkg.vulnerabilities)
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
                }})
                elements.append({"data": {"source": sid, "target": pid}})

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
        card("🤖", str(report.total_agents),   "Agents",          "#60a5fa",
             f"{report.total_servers} servers"),
        card("📦", str(report.total_packages), "Packages",        "#38bdf8",
             "direct + transitive"),
        card("⚠️",  str(total_vulns),           "Vulnerabilities", "#f87171" if total_vulns else "#34d399",
             "across all agents"),
        card("🔑", str(cred_servers),          "Servers w/ Creds","#fbbf24" if cred_servers else "#34d399",
             "credential exposure"),
        card("🚨", str(crit),                  "Critical",        "#ef4444" if crit else "#34d399",
             "needs immediate fix"),
        card("🦠", str(kev_count),             "CISA KEV",        "#a855f7" if kev_count else "#34d399",
             "actively exploited"),
    ]) + "</div>"


def _vuln_table(blast_radii: list["BlastRadius"]) -> str:
    if not blast_radii:
        return (
            '<div class="empty-state">✅ No vulnerabilities found in scanned packages.</div>'
        )

    has_missing = any(
        not br.vulnerability.cvss_score or not br.vulnerability.summary
        for br in blast_radii
    )
    hint = ""
    if has_missing:
        hint = (
            '<div class="hint-box">'
            '💡 <strong>Some entries are missing CVSS scores or descriptions.</strong> '
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
            cvss_bar = '<span style="color:#334155">—</span>'
        epss = f'{v.epss_score:.1%}' if v.epss_score else '<span style="color:#334155">—</span>'
        kev = (
            '<span class="badge-kev">KEV</span>'
            if v.is_kev else '<span style="color:#334155">—</span>'
        )
        fix = (
            f'<code style="color:#4ade80">{_esc(v.fixed_version)}</code>'
            if v.fixed_version else '<span style="color:#475569">No fix</span>'
        )
        summary_text = (v.summary or "")[:90]
        summary = _esc(summary_text) if summary_text else '<span style="color:#475569;font-style:italic">Run --enrich</span>'
        agents_s = ", ".join(_esc(a.name) for a in br.affected_agents) or "<span style='color:#334155'>—</span>"
        creds_s = (
            " ".join(f'<code style="color:#fbbf24">{_esc(c)}</code>' for c in br.exposed_credentials)
            or "<span style='color:#334155'>—</span>"
        )
        rows.append(
            f'<tr>'
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
    return (
        hint
        + '<div class="table-wrap"><table class="data-table">'
        + '<thead><tr>'
        + "".join(f'<th>{h}</th>' for h in headers)
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
            if v.fixed_version else '<span style="color:#475569">—</span>'
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
    return (
        '<div class="table-wrap"><table class="data-table">'
        + '<thead><tr>'
        + "".join(f'<th>{h}</th>' for h in [
            "#", "Vuln ID", "Severity", "Blast Score (0–10)",
            "Agents Hit", "Creds Exposed", "Tools Reachable", "Flags", "Fix",
        ])
        + f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
    )


def _remediation_list(blast_radii: list["BlastRadius"]) -> str:
    if not blast_radii:
        return '<p style="color:#4ade80">✅ Nothing to remediate.</p>'
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
            f' · frees <strong style="color:#fbbf24">{len(br.exposed_credentials)}</strong> credential(s)'
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
            f' · upgrade to <code style="color:#4ade80">{_esc(v.fixed_version)}</code>'
            f' · protects <strong>{len(br.affected_agents)}</strong> agent(s)'
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
            f'<code class="vuln-id">{_esc(b.vulnerability.id)}</code> — '
            f'<strong style="color:#e2e8f0">{_esc(b.package.name)}</strong>@{_esc(b.package.version)}'
            f' — <span style="color:#475569">no fix available — monitor upstream</span></div>'
            for b in no_fix
        )
        nf_html = (
            '<div style="margin-top:20px">'
            '<div class="subsection-label">No Fix Available</div>'
            + nf_rows + '</div>'
        )
    return "".join(items) + nf_html


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
                    cmd += f' <span style="color:#334155">…+{len(srv.args)-3} args</span>'

            # Credentials section
            creds_html = ""
            if srv.credential_names:
                creds_html = (
                    '<div style="margin-top:8px">'
                    + "".join(
                        f'<div style="font-size:.74rem;color:#fbbf24;padding:2px 0">'
                        f'🔑 <code>{_esc(c)}</code></div>'
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
                vuln_mark = " ⚠" if p.has_vulnerabilities else ""
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
                        f'Show {len(rest)} more packages ▼</button>'
                        f'</div>'
                    )
                else:
                    pkg_html = f'<div style="margin-top:8px">{preview_rows}</div>'

            srv_badges_html = " ".join(srv_badges)
            srv_header = (
                f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">'
                f'<div style="font-weight:600;color:#e2e8f0;font-size:.9rem">⚙️ {_esc(srv.name)} {srv_badges_html}</div>'
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
            f'<span>🤖 {_esc(agent.name)}</span>'
            f'<span style="display:flex;align-items:center;gap:8px">'
            f'{badges_html}'
            f'<span style="font-size:.72rem;color:#475569">'
            f'{len(agent.mcp_servers)} server(s) · {agent.total_packages} pkg(s)'
            f'</span>'
            f'</span>'
            f'</summary>'
            f'<div class="agent-detail">'
            f'<div style="font-size:.72rem;color:#475569;margin-bottom:12px">'
            f'{_esc(agent.agent_type.value)} · {_esc(agent.config_path or "")}'
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
            f'<div class="sec-title">⚠️ Vulnerabilities'
            f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{len(blast_radii)}</sup>'
            f'</div>'
            f'<div class="panel">{_vuln_table(blast_radii)}</div>'
            f'</section>'
            f'<section id="blast">'
            f'<div class="sec-title">💥 Blast Radius'
            f'<sup style="font-size:.65rem;color:#475569;margin-left:6px;font-weight:400">'
            f'risk = CVSS + agents + creds + tools + KEV/EPSS boosts (max 10)'
            f'</sup></div>'
            f'<div class="panel">{_blast_table(blast_radii)}</div>'
            f'</section>'
            f'<section id="remediation">'
            f'<div class="sec-title">🔧 Remediation Plan</div>'
            f'<div class="panel">{_remediation_list(blast_radii)}</div>'
            f'</section>'
        )

    vuln_nav = (
        '<a href="#vulns">Vulnerabilities</a>'
        '<a href="#blast">Blast Radius</a>'
        '<a href="#remediation">Remediation</a>'
        if blast_radii else ""
    )

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
  <title>agent-bom AI-BOM — {_esc(generated)}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
  <script src="https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"></script>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0b1120;color:#cbd5e1;line-height:1.5;font-size:14px}}
    a{{color:#60a5fa;text-decoration:none}}
    a:hover{{text-decoration:underline}}
    code{{font-family:"SF Mono","Cascadia Code",Consolas,monospace;font-size:.9em}}

    /* NAV */
    nav{{background:#0f172a;border-bottom:1px solid #1e293b;padding:0 28px;display:flex;align-items:center;gap:16px;height:52px;position:sticky;top:0;z-index:100}}
    .brand{{font-weight:700;font-size:.95rem;color:#f1f5f9;letter-spacing:-.01em;white-space:nowrap}}
    .status-badge{{padding:3px 10px;border-radius:4px;font-size:.7rem;font-weight:700;letter-spacing:.05em;background:{status_color}18;color:{status_color};border:1px solid {status_color}35;white-space:nowrap}}
    .scan-time{{color:#334155;font-size:.72rem;white-space:nowrap}}
    .navlinks{{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}}
    .navlinks a{{color:#475569;font-size:.8rem;padding:4px 9px;border-radius:4px;white-space:nowrap}}
    .navlinks a:hover{{background:#1e293b;color:#e2e8f0;text-decoration:none}}

    /* LAYOUT */
    .container{{max-width:1440px;margin:0 auto;padding:28px 28px 80px}}
    section{{margin-bottom:44px}}
    .sec-title{{font-size:.78rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#64748b;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #1e293b}}
    .panel{{background:#1e293b;border-radius:10px;padding:20px}}

    /* STAT CARDS */
    .stat-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(175px,1fr));gap:12px}}
    .stat-card{{background:#1e293b;border-radius:8px;padding:18px 20px;border-left:4px solid #334155}}
    .stat-icon{{font-size:1.3rem;margin-bottom:4px}}
    .stat-value{{font-size:2rem;font-weight:700;line-height:1;margin-bottom:4px}}
    .stat-label{{font-size:.68rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em}}

    /* CHARTS ROW */
    .charts-row{{display:grid;grid-template-columns:300px 1fr;gap:16px}}
    .chart-panel{{background:#1e293b;border-radius:10px;padding:20px}}
    .chart-title{{font-size:.72rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#64748b;margin-bottom:14px}}
    .chart-wrap{{position:relative}}
    .donut-wrap{{max-width:240px;margin:0 auto}}

    /* GRAPH */
    #cy{{width:100%;height:420px;background:#1e293b;border-radius:10px}}
    .graph-note{{font-size:.7rem;color:#475569;margin-top:8px}}
    .legend{{display:flex;gap:18px;flex-wrap:wrap;font-size:.75rem;color:#64748b;margin-top:10px}}
    .legend span{{display:flex;align-items:center;gap:5px}}
    .legend i{{display:inline-block;width:9px;height:9px;border-radius:50%}}

    /* TOOLTIP */
    #tip{{position:fixed;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 11px;font-size:.75rem;color:#e2e8f0;pointer-events:none;white-space:pre-line;max-width:260px;z-index:9999;display:none;line-height:1.45}}

    /* TABLES */
    .table-wrap{{overflow-x:auto}}
    .data-table{{width:100%;border-collapse:collapse;font-size:.83rem}}
    .data-table th{{padding:9px 12px;font-size:.68rem;letter-spacing:.06em;color:#64748b;font-weight:700;text-transform:uppercase;border-bottom:1px solid #334155;white-space:nowrap;background:#0f172a}}
    .data-table td{{padding:9px 12px;border-bottom:1px solid #1e293b;vertical-align:middle}}
    .data-table tr:hover td{{background:#ffffff06}}

    /* BADGES */
    .badge-kev{{background:#7f1d1d;color:#fca5a5;padding:1px 6px;border-radius:3px;font-size:.68rem;font-weight:700}}
    .badge-ai{{background:#1d4ed8;color:#bfdbfe;padding:2px 6px;border-radius:3px;font-size:.68rem;font-weight:700;margin-right:4px}}
    .badge-vuln{{background:#7f1d1d;color:#fca5a5;font-size:.65rem;padding:1px 5px;border-radius:3px;font-weight:700}}
    .badge-cred{{background:#78350f;color:#fde68a;font-size:.65rem;padding:1px 5px;border-radius:3px;font-weight:700}}
    .vuln-id{{color:#93c5fd;font-size:.78rem}}

    /* REMEDIATION */
    .remediation-item{{display:flex;align-items:flex-start;gap:14px;padding:14px 0;border-bottom:1px solid #1e293b}}
    .subsection-label{{font-size:.7rem;letter-spacing:.07em;text-transform:uppercase;color:#64748b;margin-bottom:8px}}

    /* INVENTORY */
    .agent-card{{background:#1e293b;border-radius:10px;margin-bottom:12px;overflow:hidden}}
    .agent-summary{{list-style:none;display:flex;justify-content:space-between;align-items:center;padding:16px 20px;cursor:pointer;user-select:none;font-weight:700;font-size:.95rem;color:#f1f5f9}}
    .agent-summary::-webkit-details-marker{{display:none}}
    .agent-summary::before{{content:"▶";margin-right:8px;font-size:.65rem;color:#475569;transition:transform .2s}}
    details[open] .agent-summary::before{{transform:rotate(90deg)}}
    .agent-detail{{padding:16px 20px;border-top:1px solid #0f172a}}
    .server-card{{background:#0f172a;border-radius:6px;padding:12px 14px;margin-bottom:8px;border-left:3px solid #334155}}
    .pkg-row{{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #0a1628;font-size:.78rem}}
    .pkg-row:last-child{{border-bottom:none}}
    .pkg-name{{color:#e2e8f0}}
    .pkg-ver{{color:#64748b;font-family:monospace;font-size:.73rem}}
    .toggle-btn{{background:transparent;border:1px solid #334155;color:#64748b;font-size:.72rem;padding:4px 10px;border-radius:4px;cursor:pointer;margin-top:8px;width:100%}}
    .toggle-btn:hover{{background:#1e293b;color:#94a3b8}}

    /* HINTS */
    .hint-box{{background:#1e3a5f;border:1px solid #3b82f660;border-radius:6px;padding:12px 16px;margin-bottom:16px;font-size:.82rem;color:#93c5fd}}
    .empty-state{{background:#052e1620;border:1px solid #16a34a40;border-radius:8px;padding:20px;color:#4ade80;text-align:center;font-size:.9rem}}

    footer{{border-top:1px solid #1e293b;padding:20px 28px;text-align:center;font-size:.75rem;color:#334155}}
    @media(max-width:800px){{.charts-row{{grid-template-columns:1fr}}}}
  </style>
</head>
<body>

<nav>
  <span class="brand">🛡️ agent-bom</span>
  <span class="status-badge">{status_label}</span>
  <span class="scan-time">{_esc(generated)} · v{_esc(report.tool_version)}</span>
  <div class="navlinks">
    <a href="#summary">Summary</a>
    <a href="#charts">Charts</a>
    <a href="#riskmap">Risk Map</a>
    <a href="#inventory">Inventory</a>
    {vuln_nav}
  </div>
</nav>

<div id="tip"></div>

<div class="container">

  <!-- ── Summary stat cards ── -->
  <section id="summary">
    <div class="sec-title">Summary</div>
    {_summary_cards(report, blast_radii)}
  </section>

  <!-- ── Charts row ── -->
  <section id="charts">
    <div class="sec-title">Risk Overview</div>
    <div class="charts-row">
      <div class="chart-panel">
        <div class="chart-title">Severity Distribution</div>
        <div class="donut-wrap">
          <canvas id="sevChart" height="220"></canvas>
        </div>
      </div>
      <div class="chart-panel">
        <div class="chart-title">Top Blast Radius Scores</div>
        <div class="chart-wrap">
          <canvas id="blastChart" height="220"></canvas>
        </div>
      </div>
    </div>
  </section>

  <!-- ── Risk map graph ── -->
  <section id="riskmap">
    <div class="sec-title">
      Risk Map
      <span style="font-size:.68rem;font-weight:400;opacity:.5;margin-left:8px">
        drag · scroll to zoom · hover for details · click to highlight · {_esc(graph_note)}
      </span>
    </div>
    <div id="cy"></div>
    <div class="legend">
      <span><i style="background:#3b82f6"></i>Agent</span>
      <span><i style="background:#10b981"></i>Server (clean)</span>
      <span><i style="background:#f59e0b"></i>Server (credentials)</span>
      <span><i style="background:#ef4444"></i>Server (vulnerable)</span>
      <span><i style="background:#dc2626"></i>Vulnerable package</span>
    </div>
  </section>

  <!-- ── Agent inventory (collapsible) ── -->
  <section id="inventory">
    <div class="sec-title">Agent Inventory</div>
    {_inventory_cards(report)}
  </section>

  <!-- ── Vuln / Blast / Remediation ── -->
  {vuln_sections}

</div>

<footer>
  Generated by <strong style="color:#475569">agent-bom</strong> v{_esc(report.tool_version)} ·
  <a href="https://github.com/agent-bom/agent-bom">github.com/agent-bom/agent-bom</a> ·
  Vulnerability data: OSV.dev · NVD · CISA KEV · EPSS
</footer>

<script>
(function() {{
  // ── Injected data ───────────────────────────────────────────────────────
  var CHART_DATA = {chart_data_json};
  var GRAPH_ELEMENTS = {elements_json};

  // ── Chart.js: Severity donut ────────────────────────────────────────────
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
          hoverOffset: 6,
        }}],
      }},
      options: {{
        responsive: true,
        cutout: '65%',
        plugins: {{
          legend: {{
            position: 'bottom',
            labels: {{
              color: '#94a3b8',
              font: {{ size: 11 }},
              boxWidth: 12,
              padding: 12,
            }},
          }},
          tooltip: {{
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
    p.style.cssText = 'color:#4ade80;text-align:center;padding:40px 0;font-size:.85rem';
    p.textContent = '✅ No vulnerabilities';
    sevCtx.parentNode.replaceChild(p, sevCtx);
  }}

  // ── Chart.js: Blast radius bar ──────────────────────────────────────────
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
          borderRadius: 4,
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
    p2.style.cssText = 'color:#4ade80;text-align:center;padding:40px 0;font-size:.85rem';
    p2.textContent = '✅ No blast radius data';
    blastCtx.parentNode.replaceChild(p2, blastCtx);
  }}

  // ── Cytoscape: Risk map ─────────────────────────────────────────────────
  var cyContainer = document.getElementById('cy');
  if (cyContainer && GRAPH_ELEMENTS.length > 0) {{
    var cy = cytoscape({{
      container: cyContainer,
      elements: GRAPH_ELEMENTS,
      style: [
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
            'width': 100,
            'height': 38,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '90px',
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
            'width': 110,
            'height': 34,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '100px',
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
            'width': 110,
            'height': 34,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '100px',
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
            'width': 110,
            'height': 34,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '100px',
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
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          }},
        }},
        {{
          selector: 'edge',
          style: {{
            'width': 1.5,
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.7,
          }},
        }},
        {{
          selector: '.faded',
          style: {{ 'opacity': 0.1 }},
        }},
      ],
      layout: {{
        name: 'cose',
        animate: false,
        padding: 30,
        nodeRepulsion: function() {{ return 8000; }},
        idealEdgeLength: function() {{ return 120; }},
        edgeElasticity: function() {{ return 100; }},
        gravity: 0.25,
        numIter: 1000,
        coolingFactor: 0.99,
      }},
      minZoom: 0.2,
      maxZoom: 4,
    }});
    cy.ready(function() {{ cy.fit(cy.elements(), 30); }});

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
    cy.on('tap', 'node', function(e) {{
      cy.elements().removeClass('faded');
      cy.elements().not(e.target.closedNeighborhood()).addClass('faded');
    }});
    cy.on('tap', function(e) {{
      if (e.target === cy) cy.elements().removeClass('faded');
    }});
  }}

  // ── Package list toggle ─────────────────────────────────────────────────
  window.togglePkgs = function(id, btn) {{
    var el = document.getElementById(id);
    if (!el) return;
    var hidden = el.style.display === 'none';
    el.style.display = hidden ? 'block' : 'none';
    btn.textContent = hidden
      ? 'Show fewer ▲'
      : btn.textContent.replace('Show fewer ▲', btn.dataset.orig || btn.textContent);
    if (hidden && !btn.dataset.orig) btn.dataset.orig = btn.textContent;
  }};

  // ── Smooth scroll ───────────────────────────────────────────────────────
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
