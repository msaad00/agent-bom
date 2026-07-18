"""HTML section renderers (summary, tables, graph data, CIS, compliance)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from agent_bom.finding import FindingType
from agent_bom.graph.severity import (
    SEVERITY_THRESHOLD_LABELS,
    severity_policy_rank,
    severity_worst_first_rank,
)
from agent_bom.output.exposure_path import exposure_path_brief_for_finding
from agent_bom.output.finding_views import (
    compliance_row_dict,
    cve_findings,
    evidence,
    exploit_likelihood_value,
    package_name,
    package_version,
    ranked_cve_findings,
    reachability_label,
    severity_value,
)
from agent_bom.output.html._common import (
    _PAGE_SIZE,
    _PKG_PREVIEW,
    _SEV_COLOR,
    _esc,
    _sev_badge,
)
from agent_bom.security import sanitize_launch_command, sanitize_path_label

if TYPE_CHECKING:
    from agent_bom.finding import Finding
    from agent_bom.models import AIBOMReport, BlastRadius

# Reachability cell colors, keyed by the state from ``reachability_label``.
_REACH_COLOR = {"reachable": "#f87171", "unreachable": "#64748b", "unknown": "#475569"}


def _pager_controls(table_id: str, total: int, page_size: int = _PAGE_SIZE) -> str:
    """Server-rendered pagination bar bound to a table by ``data-pager``.

    Rendered for every findings table so the controls exist in the static file
    (and in tests); the paginator JS wires the buttons and hides the whole bar
    when the filtered set fits on a single page.
    """
    return (
        f'<div class="pager" data-pager="{table_id}" data-page-size="{page_size}">'
        '<button class="pager-btn" data-act="first" title="First page">&laquo;</button>'
        '<button class="pager-btn" data-act="prev" title="Previous page">&lsaquo; Prev</button>'
        f'<span class="pager-info">1&ndash;{min(page_size, total)} of {total}</span>'
        '<button class="pager-btn" data-act="next" title="Next page">Next &rsaquo;</button>'
        '<button class="pager-btn" data-act="last" title="Last page">&raquo;</button>'
        '<span class="pager-sep"></span>'
        '<label class="pager-size-label">Rows'
        '<select class="pager-size">'
        '<option value="25">25</option>'
        f'<option value="50"{" selected" if page_size == 50 else ""}>50</option>'
        '<option value="100">100</option>'
        '<option value="250">250</option>'
        "</select></label>"
        "</div>"
    )


def _chart_data(findings: list["Finding"]) -> str:
    """Build Chart.js dataset JSON for severity donut + blast radius bar chart."""
    from agent_bom.models import Severity

    sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
    for finding in findings:
        sev = severity_value(finding)
        if sev in sev_counts:
            sev_counts[sev] += 1

    top10 = sorted(findings, key=lambda finding: float(finding.risk_score or 0.0), reverse=True)[:10]
    blast_labels = [f"{(finding.cve_id or finding.title)[:16]}/{package_name(finding)[:14]}" for finding in top10]
    blast_scores = [round(float(finding.risk_score or 0.0), 2) for finding in top10]
    blast_colors = [_SEV_COLOR.get(severity_value(finding), "#6b7280") for finding in top10]

    return json.dumps(
        {
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
        }
    )


def _cytoscape_elements(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    """Build Cytoscape element list using the shared graph builder."""
    from agent_bom.output.graph import build_graph_elements

    elements = build_graph_elements(report, blast_radii, include_cve_nodes=True)
    return json.dumps(elements)


def _attack_flow_elements(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    """Build attack flow element list showing CVE → impact propagation."""
    from agent_bom.output.graph import build_attack_flow_elements

    elements = build_attack_flow_elements(report, blast_radii)
    return json.dumps(elements)


# ─── HTML sections ────────────────────────────────────────────────────────────


def _delta_banner(report: "AIBOMReport") -> str:
    """Render a delta mode info banner when the scan used --delta."""
    scan_json = getattr(report, "_cached_json", None)
    delta = (scan_json or {}).get("delta") if scan_json else None
    if not delta or not delta.get("enabled"):
        return ""
    new_count = delta.get("new_count", 0)
    pre_count = delta.get("pre_existing_count", 0)
    baseline = _esc(str(delta.get("baseline_path") or ""))
    parts = []
    if new_count:
        parts.append(f"<b>{new_count}</b> new finding(s)")
    if pre_count:
        parts.append(f"<b>{pre_count}</b> pre-existing (suppressed from exit code)")
    body = " &middot; ".join(parts) if parts else "No new findings"
    baseline_html = f' &nbsp;<span style="color:#94a3b8;font-size:.75rem">baseline: {baseline}</span>' if baseline else ""
    return (
        '<div style="background:#1e3a5f;border:1px solid #2563eb;border-radius:8px;'
        'padding:10px 16px;margin-bottom:12px;font-size:.85rem;color:#93c5fd">'
        f"&#x1f504; <b>Delta mode</b>: {body}{baseline_html}"
        "</div>"
    )


def _warn_gate_banner(report: "AIBOMReport") -> str:
    """Render a warn-gate banner when findings triggered the warn threshold."""
    scan_json = getattr(report, "_cached_json", None)
    if not scan_json:
        return ""
    if scan_json.get("warn_gate_status") != "warn":
        return ""
    count = scan_json.get("warn_gate_count", 0)
    sev = _esc(str(scan_json.get("warn_gate_severity") or ""))
    return (
        '<div style="background:#422006;border:1px solid #d97706;border-radius:8px;'
        'padding:10px 16px;margin-bottom:12px;font-size:.85rem;color:#fcd34d">'
        f"&#x26a0;&#xfe0f; <b>Warn gate triggered</b>: {count} finding(s) at or above "
        f"<b>{sev}</b> severity &mdash; exit 0 (warning only, not a hard failure)"
        "</div>"
    )


def _summary_cards(report: "AIBOMReport", findings: list["Finding"], policy_findings: list["Finding"]) -> str:
    crit = sum(1 for finding in findings if severity_value(finding) == "critical")
    policy_crit = sum(1 for finding in policy_findings if str(finding.severity).lower() == "critical")
    total_vulns = len(findings)
    cred_servers = sum(1 for a in report.agents for s in a.mcp_servers if s.has_credentials)
    kev_count = sum(1 for finding in findings if finding.is_kev)

    def card(icon: str, value: str, label: str, accent: str, sub: str = "") -> str:
        sub_html = f'<div style="font-size:.68rem;color:#475569;margin-top:2px">{sub}</div>' if sub else ""
        return (
            f'<div class="stat-card" style="border-left-color:{accent}">'
            f'<div class="stat-icon">{icon}</div>'
            f'<div class="stat-value" style="color:{accent}">{_esc(value)}</div>'
            f'<div class="stat-label">{label}</div>'
            f"{sub_html}"
            f"</div>"
        )

    return (
        '<div class="stat-grid">'
        + "".join(
            [
                card("&#x1f916;", str(report.total_agents), "Agents", "#60a5fa", f"{report.total_servers} servers"),
                card("&#x1f4e6;", str(report.total_packages), "Packages", "#38bdf8", "direct + transitive"),
                card("&#x26a0;&#xfe0f;", str(total_vulns), "Vulnerabilities", "#f87171" if total_vulns else "#34d399", "across all agents"),
                card(
                    "&#x1f6e1;&#xfe0f;",
                    str(len(policy_findings)),
                    "Policy Findings",
                    "#f87171" if policy_findings else "#34d399",
                    "non-CVE controls",
                ),
                card("&#x1f511;", str(cred_servers), "Servers w/ Creds", "#fbbf24" if cred_servers else "#34d399", "credential exposure"),
                card(
                    "&#x1f6a8;", str(crit + policy_crit), "Critical", "#ef4444" if crit or policy_crit else "#34d399", "needs immediate fix"
                ),
                card("&#x1f9a0;", str(kev_count), "CISA KEV", "#a855f7" if kev_count else "#34d399", "actively exploited"),
            ]
        )
        + "</div>"
    )


def _vuln_table(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    findings = cve_findings(report, blast_radii)
    if not findings:
        return '<div class="empty-state">&#x2705; No vulnerabilities found in scanned packages.</div>'

    has_missing = any(not finding.cvss_score or not finding.description for finding in findings)
    hint = ""
    if has_missing:
        hint = (
            '<div class="hint-box">'
            "&#x1f4a1; <strong>Some entries are missing CVSS scores or descriptions.</strong> "
            "Run with <code>--enrich</code> to fetch full NVD metadata, CVSS 3.x vectors, EPSS, and CISA KEV status."
            "</div>"
        )

    sorted_findings = sorted(
        findings,
        key=lambda finding: severity_policy_rank(severity_value(finding)),
        reverse=True,
    )
    # Advisory AI-triage assessments joined by the finding id they describe.
    ai_assessments = {assessment.finding_id: assessment for assessment in getattr(report, "ai_finding_assessments", []) or []}
    rows = []
    for idx, finding in enumerate(sorted_findings):
        sev = severity_value(finding)
        color = _SEV_COLOR.get(sev, "#6b7280")
        cvss_bar = ""
        if finding.cvss_score:
            pct = int(finding.cvss_score * 10)
            cvss_bar = (
                f'<div style="display:flex;align-items:center;gap:6px">'
                f'<div style="background:#0f172a;border-radius:3px;height:4px;width:52px;flex-shrink:0">'
                f'<div style="background:{color};border-radius:3px;height:4px;width:{pct}%"></div></div>'
                f'<strong style="color:{color}">{finding.cvss_score:.1f}</strong></div>'
            )
        else:
            cvss_bar = '<span style="color:#334155">&mdash;</span>'
        epss = f"{finding.epss_score:.1%}" if finding.epss_score else '<span style="color:#334155">&mdash;</span>'
        exploit_level = exploit_likelihood_value(finding)
        if finding.is_kev:
            kev = '<span class="badge-kev" title="CISA Known Exploited Vulnerability">KEV</span>'
        elif exploit_level == "likely_exploited":
            kev = '<span class="badge-exploit-likely" title="EPSS ≥ 0.5 or percentile ≥ 95 — exploitation likely">EXPL</span>'
        elif exploit_level == "public_exploit":
            kev = '<span class="badge-exploit-public" title="EPSS percentile ≥ 80 — public exploit code">PoC</span>'
        else:
            kev = '<span style="color:#334155">&mdash;</span>'
        fix = (
            f'<code style="color:#4ade80">{_esc(finding.fixed_version)}</code>'
            if finding.fixed_version
            else '<span style="color:#475569">No fix</span>'
        )
        reach_label, reach_state = reachability_label(finding)
        reach_color = _REACH_COLOR.get(reach_state, "#475569")
        reach_title = {
            "reachable": "Vulnerable code is reached from an entrypoint",
            "unreachable": "Package present but not reached from any entrypoint",
            "unknown": "Reachability engine did not produce a verdict",
        }.get(reach_state, "")
        reach_cell = (
            f'<span class="reach-badge" data-reach="{reach_state}" title="{reach_title}" '
            f'style="font-size:.68rem;color:{reach_color}">{reach_label}</span>'
        )
        summary_text = (finding.description or "")[:90]
        summary = _esc(summary_text) if summary_text else '<span style="color:#475569;font-style:italic">Run --enrich</span>'
        assessment = ai_assessments.get(finding.id)
        if assessment is not None:
            summary += (
                f'<div class="ai-triage" style="margin-top:4px;font-size:.66rem;color:#a5b4fc">'
                f'<span class="badge-ai" title="AI triage (advisory)">AI</span> '
                f"{_esc(assessment.classification)} "
                f'<span style="color:#94a3b8">&middot; FP&nbsp;likelihood: {_esc(assessment.false_positive_likelihood)}</span>'
                f"</div>"
            )
        agents_s = ", ".join(_esc(name) for name in finding.affected_agents) or "<span style='color:#334155'>&mdash;</span>"
        creds_s = (
            " ".join(f'<code style="color:#fbbf24">{_esc(c)}</code>' for c in finding.exposed_credentials)
            or "<span style='color:#334155'>&mdash;</span>"
        )
        vendor_sev = finding.vendor_severity
        vendor_hint = ""
        if vendor_sev and vendor_sev.lower() != sev:
            vendor_hint = f'<br><span style="font-size:.62rem;color:#94a3b8;font-style:italic">vendor: {_esc(vendor_sev)}</span>'
        tier = evidence(finding, "match_confidence_tier", None)
        tier_hint = ""
        if tier:
            _tier_color = "#f59e0b" if tier == "nvd_cpe_candidate" else "#64748b"
            tier_hint = (
                f'<br><span class="match-tier" data-tier="{_esc(tier)}" '
                f'title="match confidence: {_esc(tier)}" '
                f'style="font-size:.6rem;color:{_tier_color}">{_esc(str(tier).replace("_", " "))}</span>'
            )
        vuln_id = finding.cve_id or finding.id
        pkg_name = package_name(finding)
        pkg_version = package_version(finding)
        pg_cls = " pg-hidden" if idx >= _PAGE_SIZE else ""
        rows.append(
            f'<tr class="pg-row{pg_cls}" data-severity="{sev}" data-kev="{"1" if finding.is_kev else "0"}" '
            f'data-exploit-likelihood="{exploit_level}" '
            f'data-reachability="{reach_state}" '
            f'data-match-tier="{_esc(tier or "")}" '
            f'data-cvss="{finding.cvss_score if finding.cvss_score else 0}">'
            f'<td><code class="vuln-id">{_esc(vuln_id)}</code>{tier_hint}</td>'
            f"<td>{_sev_badge(sev)}{vendor_hint}</td>"
            f'<td><strong style="color:#e2e8f0">{_esc(pkg_name)}</strong>'
            f'<span style="color:#475569;font-size:.78rem">@{_esc(pkg_version)}</span></td>'
            f"<td>{cvss_bar}</td>"
            f'<td style="text-align:center;font-size:.82rem;color:#94a3b8">{epss}</td>'
            f'<td style="text-align:center">{kev}</td>'
            f'<td style="text-align:center">{reach_cell}</td>'
            f"<td>{fix}</td>"
            f'<td style="font-size:.78rem;color:#94a3b8">{agents_s}</td>'
            f'<td style="font-size:.78rem">{creds_s}</td>'
            f'<td style="font-size:.75rem;color:#64748b;max-width:180px">{summary}</td>'
            f"</tr>"
        )

    headers = ["Vuln ID", "Severity", "Package", "CVSS", "EPSS", "KEV", "Reach", "Fix", "Affected Agents", "Exposed Creds", "Summary"]

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
        "</div>"
    )

    return (
        hint
        + filter_bar
        + '<div class="table-wrap"><table class="data-table sortable paginated" id="vulnTable">'
        + "<thead><tr>"
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + "</tr></thead>"
        + f"<tbody>{''.join(rows)}</tbody></table></div>"
        + _pager_controls("vulnTable", len(rows))
    )


def _blast_table(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    findings = cve_findings(report, blast_radii)
    if not findings:
        return ""
    sorted_findings = sorted(findings, key=lambda finding: float(finding.risk_score or 0.0), reverse=True)
    rows = []
    for i, finding in enumerate(sorted_findings, 1):
        sev = severity_value(finding)
        color = _SEV_COLOR.get(sev, "#6b7280")
        risk_score = float(finding.risk_score or 0.0)
        bar_w = int(risk_score * 9)
        ai_badge = '<span class="badge-ai">AI</span>' if finding.ai_risk_context else ""
        kev_badge = '<span class="badge-kev">KEV</span>' if finding.is_kev else ""
        fix = (
            f'<code style="color:#4ade80;font-size:.8rem">{_esc(finding.fixed_version)}</code>'
            if finding.fixed_version
            else '<span style="color:#475569">&mdash;</span>'
        )
        vuln_id = finding.cve_id or finding.id
        rows.append(
            f"<tr>"
            f'<td style="color:#475569;font-weight:600">#{i}</td>'
            f'<td><code class="vuln-id">{_esc(vuln_id)}</code></td>'
            f"<td>{_sev_badge(sev)}</td>"
            f"<td>"
            f'<div style="display:flex;align-items:center;gap:8px">'
            f'<div style="background:#0f172a;border-radius:3px;height:5px;width:90px">'
            f'<div style="background:{color};border-radius:3px;height:5px;width:{bar_w}px"></div></div>'
            f'<strong style="color:{color}">{risk_score:.1f}</strong></div>'
            f"</td>"
            f'<td style="text-align:center;color:#e2e8f0">{len(finding.affected_agents)}</td>'
            f'<td style="text-align:center;color:#fbbf24">{len(finding.exposed_credentials)}</td>'
            f'<td style="text-align:center;color:#94a3b8">{len(finding.exposed_tools)}</td>'
            f"<td>{ai_badge}{kev_badge}</td>"
            f"<td>{fix}</td>"
            f"</tr>"
        )
    headers = ["#", "Vuln ID", "Severity", "Blast Score (0&ndash;10)", "Agents Hit", "Creds Exposed", "Tools Reachable", "Flags", "Fix"]
    return (
        '<div class="table-wrap"><table class="data-table sortable">'
        + "<thead><tr>"
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def _exposure_path_section(report: "AIBOMReport", blast_radii: list["BlastRadius"]) -> str:
    findings = ranked_cve_findings(report, blast_radii)
    if not findings:
        return ""
    cards = []
    for rank, finding in enumerate(findings, 1):
        brief = exposure_path_brief_for_finding(finding, rank=rank)
        sev = str(finding.effective_severity() or finding.severity or "unknown").lower()
        color = _SEV_COLOR.get(sev, "#6b7280")
        cards.append(
            '<div class="exposure-path-card">'
            f'<div class="path-rank" style="border-color:{color};color:{color}">#{_esc(brief["rank"])}</div>'
            '<div class="path-body">'
            f'<div class="path-title">{_esc(brief["path"])}</div>'
            f'<div class="path-summary">{_esc(brief["why"])}</div>'
            '<div class="path-meta">'
            f'<span style="color:{color};font-weight:700">{_esc(brief["severity"])}</span>'
            f"<span>risk {_esc(brief['risk'])}</span>"
            f"<span>{_esc(brief['proof'])}</span>"
            f"</div>"
            f'<div class="path-fix">{_esc(brief["fix"])}</div>'
            "</div>"
            "</div>"
        )
    return "".join(cards)


def _remediation_list(findings: list["Finding"]) -> str:
    if not findings:
        return '<p style="color:#4ade80">&#x2705; Nothing to remediate.</p>'
    with_fix = sorted(
        [finding for finding in findings if finding.fixed_version],
        key=lambda finding: float(finding.risk_score or 0.0),
        reverse=True,
    )
    no_fix = [finding for finding in findings if not finding.fixed_version]
    items = []
    for finding in with_fix:
        creds_note = (
            f' &middot; frees <strong style="color:#fbbf24">{len(finding.exposed_credentials)}</strong> credential(s)'
            if finding.exposed_credentials
            else ""
        )
        items.append(
            f'<div class="remediation-item">'
            f'<div style="flex-shrink:0;padding-top:1px">{_sev_badge(severity_value(finding))}</div>'
            f'<div style="flex:1">'
            f'<div style="color:#e2e8f0;font-weight:600">{_esc(package_name(finding))}'
            f'<span style="color:#475569;font-weight:400">@{_esc(package_version(finding))}</span></div>'
            f'<div style="font-size:.8rem;color:#64748b;margin-top:3px">'
            f'<code class="vuln-id">{_esc(finding.cve_id or finding.title)}</code>'
            f' &middot; upgrade to <code style="color:#4ade80">{_esc(finding.fixed_version)}</code>'
            f" &middot; protects <strong>{len(finding.affected_agents)}</strong> agent(s)"
            f"{creds_note}"
            f"</div></div>"
            f'<div style="flex-shrink:0;color:#475569;font-size:.78rem;padding-top:3px">score&nbsp;{float(finding.risk_score or 0.0):.1f}</div>'
            f"</div>"
        )
    nf_html = ""
    if no_fix:
        nf_rows = "".join(
            f'<div style="padding:9px 0;border-bottom:1px solid #1e293b;font-size:.82rem">'
            f"{_sev_badge(severity_value(finding))} "
            f'<code class="vuln-id">{_esc(finding.cve_id or finding.title)}</code> &mdash; '
            f'<strong style="color:#e2e8f0">{_esc(package_name(finding))}</strong>@{_esc(package_version(finding))}'
            f' &mdash; <span style="color:#475569">no fix available &mdash; monitor upstream</span></div>'
            for finding in no_fix
        )
        nf_html = '<div style="margin-top:20px"><div class="subsection-label">No Fix Available</div>' + nf_rows + "</div>"
    return "".join(items) + nf_html


def _non_cve_findings(report: "AIBOMReport") -> list["Finding"]:
    """Return unified findings not already represented in the CVE or CIS tables.

    Cloud CIS benchmark FAILures are lifted into the unified stream by
    ``to_findings()`` AND rendered per-check by the dedicated CIS Benchmark
    Posture table (``_CIS_CLOUD_LABELS``). Skip the unified copy for any
    provider that table covers so each failed check renders exactly once (no
    double-emit). Snowflake governance findings are also ``CIS_FAIL`` but carry
    no ``benchmark`` marker and have no dedicated table, so they stay here.
    """
    findings: list[Finding] = []
    for finding in report.to_findings():
        if finding.finding_type == FindingType.CVE:
            continue
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        if (
            finding.finding_type in {FindingType.CIS_FAIL, FindingType.CIS_ERROR}
            and evidence.get("benchmark") == "CIS"
            and evidence.get("provider") in _CIS_CLOUD_LABELS
        ):
            continue
        findings.append(finding)
    return findings


def _policy_findings_section(findings: list["Finding"]) -> str:
    """Render unified non-CVE findings with asset, source, and evidence context."""
    if not findings:
        return ""

    rows = []
    for idx, finding in enumerate(sorted(findings, key=lambda f: severity_policy_rank(str(f.severity)), reverse=True)):
        sev = str(finding.severity or "unknown").lower()
        title = finding.title or finding.description or finding.finding_type.value
        asset_label = finding.asset.name or finding.asset.identifier or "unknown asset"
        location = (
            f'<br><code style="color:#64748b;font-size:.72rem">{_esc(finding.asset.location)}</code>' if finding.asset.location else ""
        )
        description = finding.description or finding.remediation_guidance or ""
        evidence_items = [f"{_esc(key)}={_esc(value)}" for key, value in finding.evidence.items() if value not in (None, "", [], {})][:4]
        evidence = (
            "<br>".join(f'<code style="color:#94a3b8;font-size:.72rem">{item}</code>' for item in evidence_items)
            if evidence_items
            else '<span style="color:#334155">&mdash;</span>'
        )
        remediation = finding.remediation_guidance or ""
        description_html = f'<br><span style="color:#94a3b8">{_esc(description)}</span>' if description else ""
        remediation_html = _esc(remediation) if remediation else '<span style="color:#334155">&mdash;</span>'
        pg_cls = " pg-hidden" if idx >= _PAGE_SIZE else ""
        rows.append(
            f'<tr class="pg-row{pg_cls}" data-severity="{sev}" data-type="{_esc(finding.finding_type.value)}" '
            f'data-source="{_esc(finding.source.value)}" data-asset-type="{_esc(finding.asset.asset_type)}">'
            f"<td>{_sev_badge(sev)}</td>"
            f'<td><code style="color:#c4b5fd;font-size:.75rem">{_esc(finding.finding_type.value)}</code></td>'
            f'<td><strong style="color:#e2e8f0">{_esc(asset_label)}</strong>'
            f'<br><span style="color:#64748b;font-size:.72rem">{_esc(finding.asset.asset_type)}</span>{location}</td>'
            f'<td style="font-size:.82rem;color:#cbd5e1;max-width:260px"><strong>{_esc(title)}</strong>'
            f"{description_html}</td>"
            f'<td><code style="color:#94a3b8;font-size:.75rem">{_esc(finding.source.value)}</code></td>'
            f'<td style="font-size:.75rem;color:#94a3b8;max-width:220px">{evidence}</td>'
            f'<td style="font-size:.75rem;color:#4ade80;max-width:220px">{remediation_html}</td>'
            "</tr>"
        )

    headers = ["Severity", "Type", "Asset", "Finding", "Source", "Evidence", "Remediation"]
    header_html = "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
    severity_filters = "".join(
        f'<label style="display:flex;align-items:center;gap:4px;font-size:.78rem;color:{color};cursor:pointer">'
        f'<input type="checkbox" class="policy-sev-filter" value="{sev}" checked> {label}</label>'
        for sev, label, color in (
            ("critical", "Critical", "#fca5a5"),
            ("high", "High", "#fb923c"),
            ("medium", "Medium", "#fbbf24"),
            ("low", "Low", "#94a3b8"),
            ("unknown", "Unknown", "#94a3b8"),
        )
    )
    finding_types = sorted({finding.finding_type.value for finding in findings})
    type_options = "".join(f'<option value="{_esc(ftype)}">{_esc(ftype)}</option>' for ftype in finding_types)
    asset_types = sorted({finding.asset.asset_type for finding in findings if finding.asset.asset_type})
    asset_options = "".join(f'<option value="{_esc(asset_type)}">{_esc(asset_type)}</option>' for asset_type in asset_types)
    filter_bar = (
        '<div class="policy-filter-bar" style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;'
        'margin-bottom:14px;padding:12px 16px;background:#0f172a;border-radius:8px;border:1px solid #1e293b">'
        '<span style="font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em;font-weight:700">Filter:</span>'
        f"{severity_filters}"
        '<span style="width:1px;height:18px;background:#334155"></span>'
        '<select id="policyTypeFilter" style="padding:6px 10px;background:#1e293b;border:1px solid #334155;border-radius:6px;'
        'color:#e2e8f0;font-size:.78rem;outline:none"><option value="">All types</option>'
        f"{type_options}</select>"
        '<select id="policyAssetFilter" style="padding:6px 10px;background:#1e293b;border:1px solid #334155;border-radius:6px;'
        'color:#e2e8f0;font-size:.78rem;outline:none"><option value="">All assets</option>'
        f"{asset_options}</select>"
        '<input type="text" id="policySearch" placeholder="Search policy findings&hellip;" '
        'style="padding:6px 10px;background:#1e293b;border:1px solid #334155;border-radius:6px;'
        'color:#e2e8f0;font-size:.78rem;width:220px;outline:none">'
        '<span id="policyVisibleCount" style="margin-left:auto;font-size:.72rem;color:#64748b"></span>'
        "</div>"
    )
    return (
        f'<section id="policyfindings">'
        f'<div class="sec-title">&#x1f6e1;&#xfe0f; Policy &amp; Security Findings'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{len(findings)}</sup></div>'
        f'<div class="panel">'
        f'<div class="hint-box">'
        f"Unified non-CVE findings from scanners, policy checks, runtime controls, and MCP intelligence. "
        f"These are the same findings emitted in JSON and SARIF."
        f"</div>"
        f"{filter_bar}"
        f'<div class="table-wrap"><table class="data-table sortable paginated" id="policyFindingsTable">'
        f"<thead><tr>{header_html}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
        f"{_pager_controls('policyFindingsTable', len(rows))}"
        f"</div></section>"
    )


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
            f"</div>"
        )

    stats_html = (
        f'<div style="display:flex;gap:24px;margin-bottom:16px;font-size:.82rem;color:#94a3b8">'
        f'<span>Status: <strong style="color:{status_color}">{status_text}</strong></span>'
        f"<span>Packages checked: <strong>{pkgs_checked}</strong></span>"
        f"<span>Servers checked: <strong>{servers_checked}</strong></span>"
        f"<span>Credentials checked: <strong>{creds_checked}</strong></span>"
        + (
            f'<span>AI risk level: <strong style="color:{_SEV_COLOR.get(ai_risk, "#64748b")}">{_esc(ai_risk).upper()}</strong></span>'
            if ai_risk
            else ""
        )
        + "</div>"
    )

    if not findings:
        return (
            f'<section id="skillaudit">'
            f'<div class="sec-title">&#x1f6e1;&#xfe0f; Skill File Audit</div>'
            f'<div class="panel">{stats_html}{summary_html}'
            f'<div class="empty-state">&#x2705; No security findings in skill files.</div>'
            f"</div></section>"
        )

    rows = []
    for f in findings:
        sev = f.get("severity", "low")
        rows.append(
            f"<tr>"
            f"<td>{_sev_badge(sev)}</td>"
            f'<td style="color:#e2e8f0;font-weight:600;font-size:.85rem">{_esc(f.get("title", ""))}</td>'
            f'<td><code style="color:#94a3b8;font-size:.75rem">{_esc(f.get("category", ""))}</code></td>'
            f'<td style="font-size:.78rem;color:#94a3b8;max-width:300px">{_esc(f.get("detail", ""))}</td>'
            f'<td style="font-size:.75rem;color:#64748b">{_esc(f.get("source_file", ""))}</td>'
            f'<td style="font-size:.75rem;color:#4ade80">{_esc(f.get("recommendation", ""))}</td>'
            f"</tr>"
        )

    headers = ["Severity", "Finding", "Category", "Detail", "Source", "Recommendation"]
    table_html = (
        '<div class="table-wrap"><table class="data-table sortable">'
        + "<thead><tr>"
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + "</tr></thead>"
        + f"<tbody>{''.join(rows)}</tbody></table></div>"
    )

    return (
        f'<section id="skillaudit">'
        f'<div class="sec-title">&#x1f6e1;&#xfe0f; Skill File Audit'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{len(findings)}</sup></div>'
        f'<div class="panel">{stats_html}{summary_html}{table_html}</div>'
        f"</section>"
    )


def _ai_inventory_section(report: "AIBOMReport") -> str:
    """Build the AI component inventory section if data is available."""
    data = getattr(report, "ai_inventory_data", None)
    if not data:
        return ""

    components = data.get("components", [])
    total = data.get("total_components", 0)
    files_scanned = data.get("files_scanned", 0)
    shadow_count = data.get("shadow_ai_count", 0)
    deprecated_count = data.get("deprecated_models_count", 0)
    unique_sdks = data.get("unique_sdks", [])
    unique_models = data.get("unique_models", [])

    stats_html = (
        f'<div style="display:flex;gap:24px;margin-bottom:16px;font-size:.82rem;color:#94a3b8">'
        f"<span>Files scanned: <strong>{files_scanned}</strong></span>"
        f"<span>Components: <strong>{total}</strong></span>"
        f"<span>SDKs: <strong>{len(unique_sdks)}</strong></span>"
        f"<span>Models: <strong>{len(unique_models)}</strong></span>"
        + (f'<span>Shadow AI: <strong style="color:#eab308">{shadow_count}</strong></span>' if shadow_count else "")
        + (f'<span>Deprecated: <strong style="color:#f97316">{deprecated_count}</strong></span>' if deprecated_count else "")
        + "</div>"
    )

    if not components:
        return (
            f'<section id="aiinventory">'
            f'<div class="sec-title">&#x1f916; AI Component Inventory</div>'
            f'<div class="panel">{stats_html}'
            f'<div class="empty-state">&#x2705; No AI components detected.</div>'
            f"</div></section>"
        )

    rows = []
    for c in components:
        sev = c.get("severity", "info")
        comp_type = c.get("type", "").replace("_", " ")
        # Redact API key values — never render credential fragments in HTML
        raw_name = c.get("name", "")
        name = "[REDACTED]" if c.get("type") == "api_key" else _esc(raw_name)
        shadow_tag = ' <span style="color:#eab308;font-size:.7rem">(shadow)</span>' if c.get("is_shadow") else ""
        replacement = c.get("deprecated_replacement", "")
        repl_tag = f'<br><span style="color:#64748b;font-size:.7rem">&rarr; {_esc(replacement)}</span>' if replacement else ""
        file_loc = f"{_esc(c.get('file', ''))}:{c.get('line', '')}"
        rows.append(
            f"<tr>"
            f"<td>{_sev_badge(sev)}</td>"
            f'<td><code style="color:#94a3b8;font-size:.75rem">{_esc(comp_type)}</code></td>'
            f'<td style="color:#e2e8f0;font-weight:600;font-size:.85rem">{name}{shadow_tag}{repl_tag}</td>'
            f'<td style="font-size:.75rem;color:#64748b">{file_loc}</td>'
            f'<td style="font-size:.75rem;color:#67e8f9">{_esc(c.get("language", ""))}</td>'
            f"</tr>"
        )

    headers = ["Severity", "Type", "Name", "File", "Language"]
    table_html = (
        '<div class="table-wrap"><table class="data-table sortable">'
        + "<thead><tr>"
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + "</tr></thead>"
        + f"<tbody>{''.join(rows)}</tbody></table></div>"
    )

    return (
        f'<section id="aiinventory">'
        f'<div class="sec-title">&#x1f916; AI Component Inventory'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{total}</sup></div>'
        f'<div class="panel">{stats_html}{table_html}</div>'
        f"</section>"
    )


_CIS_CLOUD_LABELS = {
    "aws": ("AWS", "cis_benchmark_data"),
    "azure": ("Azure", "azure_cis_benchmark_data"),
    "gcp": ("GCP", "gcp_cis_benchmark_data"),
    "snowflake": ("Snowflake", "snowflake_cis_benchmark_data"),
    "databricks": ("Databricks", "databricks_cis_benchmark_data"),
}


def _cis_evidence_html(check: dict) -> str:
    """Affected-resource evidence cell: resource IDs when present, else text."""
    resources = check.get("resource_ids") or []
    if resources:
        chips = "".join(
            f'<span style="display:inline-block;padding:1px 7px;margin:1px 3px 1px 0;border-radius:4px;'
            f"background:#0f172a;color:#cbd5e1;font-size:.66rem;font-family:monospace;"
            f'word-break:break-all">{_esc(r)}</span>'
            for r in resources[:6]
        )
        if len(resources) > 6:
            chips += f'<span style="color:#475569;font-size:.66rem">+{len(resources) - 6} more</span>'
        return chips
    evidence = str(check.get("evidence") or "").strip()
    if evidence:
        return f'<span style="color:#94a3b8;font-size:.72rem">{_esc(evidence)}</span>'
    return '<span style="color:#475569;font-size:.7rem">&mdash;</span>'


def _cis_benchmark_section(report: "AIBOMReport") -> str:
    """Build the CIS benchmark posture section (issue #665).

    Renders one sub-panel per cloud with a CIS benchmark bundle. Each failed
    or unevaluable check surfaces its structured remediation dict (``fix_cli``,
    ``fix_console``, ``priority``, ``guardrails``, human-review flag).
    Returns an empty string when no CIS data is present.
    """

    def _sort_key(c: dict) -> tuple[int, int, str]:
        rem = c.get("remediation") or {}
        priority = rem.get("priority", 3)
        if not isinstance(priority, int):
            priority = 3
        return (severity_worst_first_rank(c.get("severity")), priority, str(c.get("check_id") or ""))

    panels: list[str] = []
    for idx, (cloud_key, (label, attr)) in enumerate(_CIS_CLOUD_LABELS.items()):
        bundle = getattr(report, attr, None)
        if not bundle:
            continue
        checks = bundle.get("checks") or []
        if not checks:
            continue
        failed = [c for c in checks if c.get("status") == "fail"]
        errored = [c for c in checks if c.get("status") == "error"]
        actionable = failed + errored
        evaluated = [c for c in checks if c.get("status") in ("pass", "fail")]
        passed_n = bundle.get("passed", sum(1 for c in checks if c.get("status") == "pass"))
        pass_rate = bundle.get("pass_rate", 0.0)
        band_color = "#16a34a" if pass_rate >= 90 else "#eab308" if pass_rate >= 70 else "#ef4444"

        # Verdict + per-severity failed counts for the summary header.
        sev_counts = {s: sum(1 for c in failed if (c.get("severity") or "").lower() == s) for s in SEVERITY_THRESHOLD_LABELS}
        if errored and not evaluated:
            verdict_text, verdict_color = "ERROR", "#dc2626"
        elif errored:
            verdict_text, verdict_color = "INCOMPLETE", "#d97706"
        elif not failed:
            verdict_text, verdict_color = "PASS", "#16a34a"
        else:
            worst_check = min(failed, key=lambda c: severity_worst_first_rank(c.get("severity")))
            worst_sev = (worst_check.get("severity") or "low").lower()
            if worst_sev not in SEVERITY_THRESHOLD_LABELS:
                worst_sev = "low"
            worst_band = worst_sev.upper()
            verdict_text = f"{worst_band} GAPS"
            verdict_color = _SEV_COLOR.get(worst_sev, "#ef4444")

        top = sorted(actionable, key=_sort_key)[:3]
        top_html = ""
        if top:
            chips = "".join(
                f'<code style="background:#1e293b;color:#f1f5f9;padding:1px 6px;border-radius:4px;'
                f'margin-right:5px;font-size:.7rem">{_esc(c.get("check_id", ""))}</code>'
                for c in top
            )
            top_html = f'<div style="color:#64748b;font-size:.74rem;margin-top:6px">top risks: {chips}</div>'

        counts_html = " ".join(
            f'<span style="color:{_SEV_COLOR.get(s, "#6b7280")};font-size:.72rem;font-weight:700">{n} {s[0].upper()}</span>'
            for s, n in sev_counts.items()
            if n
        )
        pass_html = (
            f'<div style="color:{band_color};font-weight:700">{pass_rate:.0f}% pass</div>'
            if evaluated
            else '<div style="color:#94a3b8;font-weight:700">pass rate unavailable</div>'
        )

        header = (
            f'<div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;margin-bottom:4px">'
            f'<div style="font-weight:700;color:#f1f5f9;font-size:.95rem">{_esc(label)}</div>'
            f'<span style="background:{verdict_color};color:#fff;padding:2px 9px;border-radius:4px;'
            f'font-size:.7rem;font-weight:700;letter-spacing:.04em">{verdict_text}</span>'
            f"{pass_html}"
            f'<div style="color:#64748b;font-size:.78rem">'
            f"{passed_n}/{len(evaluated)} evaluated &middot; "
            f'<strong style="color:#f97316">{len(failed)} failed</strong>'
            f' &middot; <strong style="color:#d97706">{len(errored)} unevaluable</strong>'
            f"</div>"
            f'<div style="display:flex;gap:10px">{counts_html}</div>'
            f"</div>"
            f"{top_html}"
        )

        if not actionable:
            panels.append(
                f'<div class="panel" style="margin-bottom:16px">{header}'
                f'<div class="empty-state" style="margin-top:12px">&#x2705; No failed security checks.</div></div>'
            )
            continue

        # Severity filter buttons (client-side, per panel).
        panel_id = f"cis-{_esc(cloud_key)}"
        filter_btns = (
            f'<div class="cis-filter" data-target="{panel_id}" style="margin:10px 0 4px">'
            + "".join(
                f'<button type="button" class="cis-filter-btn" data-sev="{sev}" '
                f'style="background:#1e293b;color:#94a3b8;border:1px solid #334155;border-radius:4px;'
                f'padding:2px 9px;margin-right:6px;font-size:.7rem;cursor:pointer">{lbl}</button>'
                for sev, lbl in (
                    ("all", "All"),
                    ("critical", "Critical"),
                    ("high", "High"),
                    ("medium", "Medium"),
                    ("low", "Low"),
                )
                if sev == "all" or sev_counts.get(sev)
            )
            + "</div>"
        )

        rows = []
        for check in sorted(actionable, key=_sort_key):
            sev = (check.get("severity") or "").lower()
            rem = check.get("remediation") or {}
            fix_cli = rem.get("fix_cli")
            fix_console = rem.get("fix_console") or ""
            effort = rem.get("effort") or "manual"
            priority = rem.get("priority", 3)
            guardrails = rem.get("guardrails") or []
            guard_html = "".join(
                f'<span style="display:inline-block;padding:1px 7px;margin:1px 3px 1px 0;border-radius:4px;background:#1e293b;color:#94a3b8;font-size:.65rem;font-family:monospace">{_esc(g)}</span>'
                for g in guardrails[:5]
            )
            if len(guardrails) > 5:
                guard_html += f'<span style="color:#475569;font-size:.65rem">+{len(guardrails) - 5}</span>'
            review_badge = (
                '<span style="color:#eab308;font-size:.7rem;margin-left:6px">&#8634; review</span>'
                if rem.get("requires_human_review")
                else ""
            )

            fix_cell = ""
            if fix_cli:
                fix_cell = f'<code style="color:#67e8f9;font-size:.72rem;white-space:pre-wrap;word-break:break-all">{_esc(fix_cli)}</code>'
            elif fix_console:
                fix_cell = f'<span style="color:#94a3b8;font-size:.72rem">&rarr; {_esc(fix_console)}</span>'
            elif check.get("recommendation"):
                fix_cell = f'<span style="color:#94a3b8;font-size:.72rem">{_esc(check.get("recommendation"))}</span>'

            docs_link = ""
            docs = rem.get("docs") or ""
            if docs:
                docs_link = f' &middot; <a href="{_esc(docs)}" target="_blank" rel="noopener" style="font-size:.7rem">docs</a>'

            rows.append(
                f'<tr class="cis-row" data-sev="{_esc(sev)}">'
                f"<td>{_sev_badge(sev)}</td>"
                f'<td style="font-family:monospace;color:#f1f5f9;font-weight:600">{_esc(check.get("check_id", ""))}</td>'
                f'<td style="color:#e2e8f0;font-size:.82rem">{_esc(check.get("title", ""))}{review_badge}</td>'
                f'<td style="color:#94a3b8;font-size:.75rem">P{priority} &middot; {_esc(effort)}</td>'
                f"<td>{_cis_evidence_html(check)}</td>"
                f"<td>{guard_html}</td>"
                f"<td>{fix_cell}{docs_link}</td>"
                "</tr>"
            )

        table_html = (
            f'<div class="table-wrap"><table class="data-table sortable" id="{panel_id}">'
            + "<thead><tr>"
            + "".join(
                f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>'
                for i, h in enumerate(["Severity", "Check", "Title", "Priority", "Evidence", "Guardrails", "Remediation"])
            )
            + "</tr></thead>"
            + f"<tbody>{''.join(rows)}</tbody></table></div>"
        )

        panels.append(f'<div class="panel" style="margin-bottom:16px">{header}{filter_btns}{table_html}</div>')

    if not panels:
        return ""

    filter_script = (
        "<script>document.querySelectorAll('.cis-filter').forEach(function(bar){"
        "bar.querySelectorAll('.cis-filter-btn').forEach(function(btn){"
        "btn.addEventListener('click',function(){"
        "var tbl=document.getElementById(bar.getAttribute('data-target'));if(!tbl)return;"
        "var sev=btn.getAttribute('data-sev');"
        "tbl.querySelectorAll('tbody tr.cis-row').forEach(function(r){"
        "r.style.display=(sev==='all'||r.getAttribute('data-sev')===sev)?'':'none';});"
        "bar.querySelectorAll('.cis-filter-btn').forEach(function(b){b.style.color='#94a3b8';});"
        "btn.style.color='#f1f5f9';});});});</script>"
    )

    return (
        '<section id="cisbenchmarks"><div class="sec-title">&#x1f6e1;&#xfe0f; Cloud Security Posture</div>'
        + "".join(panels)
        + filter_script
        + "</section>"
    )


def _trust_assessment_section(report: "AIBOMReport") -> str:
    """Build the trust assessment section if data is available."""
    data = getattr(report, "trust_assessment_data", None)
    if not data:
        return ""

    skill_name = _esc(data.get("skill_name", ""))
    source_file = _esc(data.get("source_file", ""))
    verdict = data.get("verdict", "benign").upper()
    content_verdict = data.get("content_verdict", data.get("verdict", "benign")).upper()
    provenance_verdict = data.get("provenance_verdict", "unverified").upper()
    recommendation = data.get("overall_recommendation") or data.get("review_verdict", "review")
    confidence = data.get("confidence", "low")
    categories = data.get("categories", [])
    recommendations = data.get("recommendations", [])

    verdict_colors = {"BENIGN": "#16a34a", "SUSPICIOUS": "#d97706", "MALICIOUS": "#dc2626"}
    verdict_color = verdict_colors.get(verdict, "#6b7280")

    level_icons = {"pass": "&#x2713;", "info": "&#x2139;", "warn": "&#x26a0;", "fail": "&#x2717;"}
    level_colors = {"pass": "#16a34a", "info": "#60a5fa", "warn": "#d97706", "fail": "#dc2626"}

    cat_rows = []
    for cat in categories:
        level = cat.get("level", "pass")
        icon = level_icons.get(level, "?")
        color = level_colors.get(level, "#6b7280")
        cat_rows.append(
            f"<tr>"
            f'<td style="text-align:center;color:{color};font-size:1.1rem">{icon}</td>'
            f'<td style="color:#e2e8f0;font-weight:600;font-size:.85rem">{_esc(cat.get("name", ""))}</td>'
            f"<td>{_sev_badge(level)}</td>"
            f'<td style="font-size:.78rem;color:#94a3b8">{_esc(cat.get("summary", ""))}</td>'
            f"</tr>"
        )

    verdict_badge = (
        f'<span style="background:{verdict_color};color:#fff;padding:4px 14px;border-radius:6px;'
        f'font-size:.82rem;font-weight:700;letter-spacing:.04em">{verdict}</span>'
        f'<span style="color:#64748b;font-size:.78rem;margin-left:8px">({confidence} confidence)</span>'
    )
    axis_html = (
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">'
        f'<span style="background:#0f766e;color:#fff;padding:4px 10px;border-radius:6px;font-size:.76rem">'
        f"content: {_esc(content_verdict)}</span>"
        f'<span style="background:#4338ca;color:#fff;padding:4px 10px;border-radius:6px;font-size:.76rem">'
        f"provenance: {_esc(provenance_verdict)}</span>"
        f'<span style="background:#475569;color:#fff;padding:4px 10px;border-radius:6px;font-size:.76rem">'
        f"recommendation: {_esc(str(recommendation).upper())}</span>"
        "</div>"
    )

    title_suffix = f" &mdash; {skill_name}" if skill_name else ""
    source_note = (
        f'<div style="font-size:.72rem;color:#475569;margin-bottom:12px">Source: <code>{source_file}</code></div>' if source_file else ""
    )

    rec_html = ""
    if recommendations:
        rec_items = "".join(f'<li style="color:#4ade80;font-size:.78rem;margin-bottom:4px">{_esc(r)}</li>' for r in recommendations)
        rec_html = f'<ul style="list-style:none;padding:0;margin-top:16px">{rec_items}</ul>'

    headers = ["", "Category", "Level", "Summary"]
    table_html = (
        '<div class="table-wrap"><table class="data-table">'
        + "<thead><tr>"
        + "".join(f"<th>{h}</th>" for h in headers)
        + "</tr></thead>"
        + f"<tbody>{''.join(cat_rows)}</tbody></table></div>"
    )

    return (
        f'<section id="trust">'
        f'<div class="sec-title">&#x1f50d; Trust Assessment{title_suffix}</div>'
        f'<div class="panel">'
        f"{source_note}"
        f'<div style="margin-bottom:16px">{verdict_badge}</div>'
        f"{axis_html}"
        f"{table_html}"
        f"{rec_html}"
        f"</div></section>"
    )


def _enforcement_section(report: "AIBOMReport") -> str:
    """Build the enforcement findings section if data is available."""
    data = getattr(report, "enforcement_data", None)
    if not data:
        return ""

    findings = data.get("findings", [])
    passed = data.get("passed", True)
    servers_checked = data.get("servers_checked", 0)
    tools_checked = data.get("tools_checked", 0)
    critical_count = data.get("critical_count", 0)
    high_count = data.get("high_count", 0)

    status_color = "#16a34a" if passed else "#dc2626"
    status_text = "PASSED" if passed else "FAILED"

    stats_html = (
        f'<div style="display:flex;gap:24px;margin-bottom:16px;font-size:.82rem;color:#94a3b8">'
        f'<span>Status: <strong style="color:{status_color}">{status_text}</strong></span>'
        f"<span>Servers checked: <strong>{servers_checked}</strong></span>"
        f"<span>Tools checked: <strong>{tools_checked}</strong></span>"
        f'<span>Critical: <strong style="color:#dc2626">{critical_count}</strong></span>'
        f'<span>High: <strong style="color:#ea580c">{high_count}</strong></span>'
        f"</div>"
    )

    if not findings:
        return (
            f'<section id="enforcement">'
            f'<div class="sec-title">&#x1f6a8; Enforcement</div>'
            f'<div class="panel">{stats_html}'
            f'<div class="empty-state">&#x2705; No enforcement findings — all checks passed.</div>'
            f"</div></section>"
        )

    rows = []
    for f in findings:
        sev = f.get("severity", "low")
        rows.append(
            f"<tr>"
            f"<td>{_sev_badge(sev)}</td>"
            f'<td><code style="color:#94a3b8;font-size:.75rem">{_esc(f.get("category", ""))}</code></td>'
            f'<td style="color:#e2e8f0;font-weight:600;font-size:.85rem">{_esc(f.get("server_name", ""))}</td>'
            f'<td style="font-size:.78rem;color:#94a3b8">{_esc(f.get("tool_name", "") or "—")}</td>'
            f'<td style="font-size:.78rem;color:#94a3b8;max-width:350px">{_esc(f.get("reason", ""))}</td>'
            f'<td style="font-size:.75rem;color:#4ade80">{_esc(f.get("recommendation", ""))}</td>'
            f"</tr>"
        )

    headers = ["Severity", "Category", "Server", "Tool", "Reason", "Recommendation"]
    table_html = (
        '<div class="table-wrap"><table class="data-table sortable">'
        + "<thead><tr>"
        + "".join(f'<th data-col="{i}">{h} <span class="sort-arrow"></span></th>' for i, h in enumerate(headers))
        + "</tr></thead>"
        + f"<tbody>{''.join(rows)}</tbody></table></div>"
    )

    return (
        f'<section id="enforcement">'
        f'<div class="sec-title">&#x1f6a8; Enforcement'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">{len(findings)}</sup></div>'
        f'<div class="panel">{stats_html}{table_html}</div>'
        f"</section>"
    )


def _attack_flow_section(findings: list["Finding"]) -> str:
    """Build the CVE attack flow graph section (only when vulns exist)."""
    if not findings:
        return ""

    total_creds = len({cred for finding in findings for cred in finding.exposed_credentials})
    total_tools = len({tool for finding in findings for tool in finding.exposed_tools})
    total_agents = len({agent for finding in findings for agent in finding.affected_agents})

    return (
        '<section id="attackflow">'
        '<div class="sec-title">&#x1f525; CVE Attack Flow'
        '<span style="font-size:.68rem;font-weight:400;opacity:.5;margin-left:8px">'
        f"{len(findings)} CVEs &#x2192; {total_agents} agents &#x2192; "
        f"{total_creds} credentials &#x2192; {total_tools} tools at risk"
        "</span></div>"
        '<div class="graph-container">'
        '<div id="cyAttack" class="cy-graph"></div>'
        '<div class="graph-controls" style="top:12px;right:12px">'
        '<button class="graph-btn" id="afZoomIn" title="Zoom in">+</button>'
        '<button class="graph-btn" id="afZoomOut" title="Zoom out">&minus;</button>'
        '<button class="graph-btn" id="afFitBtn" title="Fit to view">&#x2922;</button>'
        "</div>"
        "</div>"
        '<div class="legend">'
        '<span><i class="diamond" style="background:#f87171"></i>CVE</span>'
        '<span><i style="background:#dc2626"></i>Vulnerable Package</span>'
        '<span><i style="background:#475569"></i>MCP Server</span>'
        '<span><i style="background:#fbbf24"></i>Credential</span>'
        '<span><i style="background:#818cf8"></i>Tool</span>'
        '<span><i style="background:#3b82f6"></i>Agent</span>'
        "</div>"
        "</section>"
    )


def _inventory_cards(report: "AIBOMReport") -> str:
    cards = []
    for agent in report.agents:
        total_vulns = agent.total_vulnerabilities
        total_creds = sum(len(s.credential_names) for s in agent.mcp_servers)
        agent_badges = []
        if total_vulns:
            agent_badges.append(f'<span class="badge-vuln">{total_vulns} vuln{"s" if total_vulns != 1 else ""}</span>')
        if total_creds:
            agent_badges.append(f'<span class="badge-cred">{total_creds} credential{"s" if total_creds != 1 else ""}</span>')
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
                cmd = _esc(sanitize_launch_command(srv.command, srv.args, max_args=3))
                if srv.args and len(srv.args) > 3:
                    cmd += f' <span style="color:#334155">&hellip;+{len(srv.args) - 3} args</span>'

            # Credentials section
            creds_html = ""
            if srv.credential_names:
                creds_html = (
                    '<div style="margin-top:8px">'
                    + "".join(
                        f'<div style="font-size:.74rem;color:#fbbf24;padding:2px 0">&#x1f511; <code>{_esc(c)}</code></div>'
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
                    f"</div>"
                )

            pkg_html = ""
            if pkgs:
                preview_rows = "".join(pkg_row(p) for p in preview)
                if rest:
                    uid = f"pkgs_{id(srv)}"
                    rest_rows = "".join(pkg_row(p) for p in rest)
                    pkg_html = (
                        f'<div style="margin-top:8px">'
                        f"{preview_rows}"
                        f'<div id="{uid}" style="display:none">{rest_rows}</div>'
                        f'<button class="toggle-btn" onclick="togglePkgs(\'{uid}\',this)">'
                        f"Show {len(rest)} more packages &#x25bc;</button>"
                        f"</div>"
                    )
                else:
                    pkg_html = f'<div style="margin-top:8px">{preview_rows}</div>'

            srv_badges_html = " ".join(srv_badges)
            srv_header = (
                f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">'
                f'<div style="font-weight:600;color:#e2e8f0;font-size:.9rem">&#x2699;&#xfe0f; {_esc(srv.name)} {srv_badges_html}</div>'
                f'<div style="font-size:.72rem;color:#475569">{pkg_count} pkg{"s" if pkg_count != 1 else ""}</div>'
                f"</div>"
            )
            cmd_html = (
                f'<div style="font-size:.72rem;color:#475569;font-family:monospace;margin-bottom:6px;word-break:break-all">{cmd}</div>'
                if cmd
                else ""
            )

            servers_html.append(
                f'<div class="server-card" style="border-left-color:{accent}">{srv_header}{cmd_html}{creds_html}{pkg_html}</div>'
            )

        servers_content = (
            "".join(servers_html) if servers_html else ('<p style="color:#334155;font-size:.85rem">No MCP servers configured.</p>')
        )

        cards.append(
            f'<details class="agent-card" open>'
            f'<summary class="agent-summary">'
            f"<span>&#x1f916; {_esc(agent.name)}</span>"
            f'<span style="display:flex;align-items:center;gap:8px">'
            f"{badges_html}"
            f'<span style="font-size:.72rem;color:#475569">'
            f"{len(agent.mcp_servers)} server(s) &middot; {agent.total_packages} pkg(s)"
            f"</span>"
            f"</span>"
            f"</summary>"
            f'<div class="agent-detail">'
            f'<div style="font-size:.72rem;color:#475569;margin-bottom:12px">'
            f"{_esc(agent.agent_type.value)} &middot; {_esc(sanitize_path_label(agent.config_path) if agent.config_path else '')}"
            f"</div>"
            f"{servers_content}"
            f"</div>"
            f"</details>"
        )
    return "".join(cards)


# ─── Compliance section ──────────────────────────────────────────────────────

_STATUS_BADGE = {
    "pass": '<span style="background:#16a34a;color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem">PASS</span>',
    "warning": '<span style="background:#d97706;color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem">WARN</span>',
    "fail": '<span style="background:#dc2626;color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem">FAIL</span>',
}


def _compliance_section(findings: list["Finding"]) -> str:
    """Build OWASP/ATLAS/ATT&CK/NIST compliance tables from unified CVE findings."""
    try:
        from agent_bom.atlas import ATLAS_TECHNIQUES
        from agent_bom.eu_ai_act import EU_AI_ACT
        from agent_bom.mitre_attack import ATTACK_TECHNIQUES
        from agent_bom.nist_ai_rmf import NIST_AI_RMF
        from agent_bom.owasp import OWASP_LLM_TOP10
        from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
    except ImportError:
        return ""

    br_dicts = [compliance_row_dict(finding) for finding in findings]

    def _build_rows(catalog: dict[str, str], tag_field: str) -> tuple[str, int, int, int]:
        rows = []
        pass_count = fail_count = warn_count = 0
        for code, name in sorted(catalog.items()):
            findings = sum(1 for b in br_dicts if code in b.get(tag_field, []))
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for b in br_dicts:
                if code in b.get(tag_field, []):
                    s = b.get("severity", "").lower()
                    if s in sev_counts:
                        sev_counts[s] += 1
            if findings == 0:
                status = "pass"
                pass_count += 1
            elif sev_counts["critical"] > 0 or sev_counts["high"] > 0:
                status = "fail"
                fail_count += 1
            else:
                status = "warning"
                warn_count += 1
            badge = _STATUS_BADGE[status]
            rows.append(
                f"<tr><td><code>{_esc(code)}</code></td><td>{_esc(name)}</td>"
                f"<td style='text-align:center'>{findings}</td><td style='text-align:center'>{badge}</td></tr>"
            )
        return "\n".join(rows), pass_count, fail_count, warn_count

    owasp_rows, op, of, ow = _build_rows(OWASP_LLM_TOP10, "owasp_tags")
    atlas_rows, ap, af, aw = _build_rows(ATLAS_TECHNIQUES, "atlas_tags")
    attack_rows, atp, atf, atw = _build_rows(dict(ATTACK_TECHNIQUES), "attack_tags")
    nist_rows, np_, nf, nw = _build_rows(NIST_AI_RMF, "nist_ai_rmf_tags")
    agentic_rows, oap, oaf, oaw = _build_rows(OWASP_AGENTIC_TOP10, "owasp_agentic_tags")
    eu_rows, ep, ef_, ew = _build_rows(EU_AI_ACT, "eu_ai_act_tags")

    total = (op + of + ow) + (ap + af + aw) + (atp + atf + atw) + (np_ + nf + nw) + (oap + oaf + oaw) + (ep + ef_ + ew)
    total_pass = op + ap + atp + np_ + oap + ep
    score = round((total_pass / total) * 100, 1) if total > 0 else 0.0
    has_fail = (of + af + atf + nf + oaf + ef_) > 0
    has_warn = (ow + aw + atw + nw + oaw + ew) > 0
    overall = "fail" if has_fail else ("warning" if has_warn else "pass")
    overall_badge = _STATUS_BADGE[overall]

    def _framework_table(title: str, rows: str, p: int, f: int, w: int) -> str:
        sub_total = p + f + w
        return (
            f'<details style="margin-bottom:12px" {"open" if f > 0 else ""}>'
            f'<summary style="cursor:pointer;font-weight:600;padding:6px 0">'
            f'{title} <span style="font-size:.8rem;color:#94a3b8">({p}/{sub_total} pass)</span></summary>'
            f'<table class="vtable" style="margin-top:8px"><thead><tr>'
            f"<th>Code</th><th>Control</th><th>Findings</th><th>Status</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></details>"
        )

    return (
        f'<section id="compliance">'
        f'<div class="sec-title">&#x1f6e1;&#xfe0f; Compliance Posture'
        f'<sup style="font-size:.7rem;color:#475569;margin-left:6px">'
        f"Score: {score}% {overall_badge}</sup></div>"
        f'<div class="panel">'
        f"{_framework_table('OWASP LLM Top 10', owasp_rows, op, of, ow)}"
        f"{_framework_table('OWASP Agentic Top 10', agentic_rows, oap, oaf, oaw)}"
        f"{_framework_table('MITRE ATT&CK Enterprise', attack_rows, atp, atf, atw)}"
        f"{_framework_table('MITRE ATLAS (AI/ML)', atlas_rows, ap, af, aw)}"
        f"{_framework_table('NIST AI RMF', nist_rows, np_, nf, nw)}"
        f"{_framework_table('EU AI Act', eu_rows, ep, ef_, ew)}"
        f"</div></section>"
    )
