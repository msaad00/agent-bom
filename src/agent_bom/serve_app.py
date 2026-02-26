"""Streamlit dashboard for agent-bom — ``agent-bom serve``.

Launched by ``agent-bom serve``. Do not import this module directly —
it is executed as a Streamlit script.

Features:
- Sidebar filters (severity, agent, has credentials, KEV only)
- Summary stat cards
- Plotly severity donut + blast radius scatter plot
- DFS dependency tree with nested expanders: Agent → Server → Package → Vulnerabilities
- Sortable vulnerability dataframe
- Remediation checklist
- Re-scan button

Requires: pip install 'agent-bom[ui]'  (streamlit + plotly)
"""

from __future__ import annotations

import sys
from pathlib import Path

# ─── Guard: ensure streamlit is available ─────────────────────────────────────
try:
    import plotly.express as px  # type: ignore[import]
    import plotly.graph_objects as go  # type: ignore[import]
    import streamlit as st
except ImportError:
    print(
        "ERROR: Streamlit and Plotly are required for agent-bom serve.\n"
        "Install them with:  pip install 'agent-bom[ui]'",
        file=sys.stderr,
    )
    sys.exit(1)

# ─── Page config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="agent-bom Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── CSS ──────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
  [data-testid="stMetricValue"] { font-size: 2rem !important; }
  .stDataFrame { font-size: 0.82rem; }
  .block-container { padding-top: 1rem; }
  .sev-critical { color: #dc2626; font-weight: 700; }
  .sev-high     { color: #ea580c; font-weight: 700; }
  .sev-medium   { color: #d97706; font-weight: 700; }
  .sev-low      { color: #6b7280; }
</style>
""", unsafe_allow_html=True)

_SEV_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#6b7280",
    "none":     "#16a34a",
}
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


# ─── Scan runner (cached) ─────────────────────────────────────────────────────

@st.cache_data(show_spinner="Running scan…")
def _run_scan(
    inventory: str | None,
    enrich: bool,
    tf_dirs_str: str,
    gha_path: str | None,
) -> tuple[list, list, object]:
    """Run agent-bom scan and return (agents, blast_radii, report)."""
    import json as _json

    from agent_bom.discovery import discover_all
    from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
    from agent_bom.parsers import extract_packages
    from agent_bom.scanners import scan_agents_sync

    agents: list[Agent] = []

    if inventory:
        inv_path = Path(inventory).expanduser().resolve()
        if not inv_path.is_file():
            raise ValueError(f"Inventory file not found: {inventory}")
        with open(inv_path) as f:
            data = _json.load(f)
        for ad in data.get("agents", []):
            servers = []
            for sd in ad.get("mcp_servers", []):
                pkgs = []
                for pd in sd.get("packages", []):
                    if isinstance(pd, str):
                        n, v = (pd.rsplit("@", 1) if "@" in pd else (pd, "unknown"))
                        pkgs.append(Package(name=n, version=v, ecosystem="unknown"))
                    else:
                        pkgs.append(Package(
                            name=pd.get("name", ""),
                            version=pd.get("version", "unknown"),
                            ecosystem=pd.get("ecosystem", "unknown"),
                        ))
                servers.append(MCPServer(
                    name=sd.get("name", ""),
                    command=sd.get("command", ""),
                    args=sd.get("args", []),
                    env=sd.get("env", {}),
                    packages=pkgs,
                ))
            agents.append(Agent(
                name=ad.get("name", "unknown"),
                agent_type=AgentType(ad.get("agent_type", "custom")),
                config_path=ad.get("config_path", inventory),
                mcp_servers=servers,
            ))
    else:
        agents = discover_all()

    # Terraform
    if tf_dirs_str:
        from agent_bom.terraform import scan_terraform_dir
        for tf_dir in tf_dirs_str.split("|"):
            if tf_dir.strip():
                tf_agents, _ = scan_terraform_dir(tf_dir.strip())
                agents.extend(tf_agents)

    # GitHub Actions
    if gha_path:
        from agent_bom.github_actions import scan_github_actions
        gha_agents, _ = scan_github_actions(gha_path)
        agents.extend(gha_agents)

    # Extract packages
    for agent in agents:
        for server in agent.mcp_servers:
            pre = list(server.packages)
            discovered = extract_packages(server)
            disc_keys = {(p.name, p.ecosystem) for p in discovered}
            server.packages = discovered + [p for p in pre if (p.name, p.ecosystem) not in disc_keys]

    blast_radii = scan_agents_sync(agents, enable_enrichment=enrich)
    report = AIBOMReport(agents=agents, blast_radii=blast_radii)
    return agents, blast_radii, report


# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🛡️ agent-bom")
    st.caption("AI Bill of Materials Scanner")
    st.divider()

    # Scan source
    st.subheader("Scan Source")
    inventory_path = st.text_input("Inventory JSON (optional)", placeholder="/path/to/agents.json")
    tf_dirs_input  = st.text_input("Terraform dir(s)", placeholder="/path/to/tf  (comma-sep)")
    gha_path_input = st.text_input("Repo path (GitHub Actions)", placeholder="/path/to/repo")
    enrich_flag    = st.checkbox("Enrich (NVD / EPSS / KEV)", value=False)

    if st.button("🔄 Run Scan", type="primary", use_container_width=True):
        st.cache_data.clear()

    st.divider()

    # Filters (populated after scan)
    st.subheader("Filters")
    sev_filter  = st.multiselect(
        "Severity", ["critical", "high", "medium", "low"],
        default=["critical", "high", "medium", "low"],
    )
    creds_only   = st.checkbox("With credentials only")
    kev_only     = st.checkbox("CISA KEV only")


# ─── Run scan ─────────────────────────────────────────────────────────────────

inv = inventory_path.strip() or None
tf_dirs_str = "|".join(d.strip() for d in tf_dirs_input.split(",") if d.strip())
gha = gha_path_input.strip() or None

with st.spinner("Scanning…"):
    try:
        agents, blast_radii, report = _run_scan(inv, enrich_flag, tf_dirs_str, gha)
    except Exception as exc:
        st.error(f"Scan failed: {exc}")
        st.stop()

# Apply filters
filtered_brs = [
    br for br in blast_radii
    if br.vulnerability.severity.value in sev_filter
    and (not kev_only or br.vulnerability.is_kev)
    and (not creds_only or br.exposed_credentials)
]

# ─── Header ───────────────────────────────────────────────────────────────────

total_vulns = len(blast_radii)
crit = sum(1 for br in blast_radii if br.vulnerability.severity.value == "critical")
kev_count = sum(1 for br in blast_radii if br.vulnerability.is_kev)
cred_servers = sum(1 for a in agents for s in a.mcp_servers if s.has_credentials)

status = "🔴 CRITICAL" if crit else ("🟡 VULNERABILITIES FOUND" if total_vulns else "🟢 CLEAN")
st.title(f"{status} — agent-bom Scan Results")
st.caption(f"Scanned at {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')} · v{report.tool_version}")

# ─── Stat cards ───────────────────────────────────────────────────────────────

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("🤖 Agents",       report.total_agents)
c2.metric("📦 Packages",     report.total_packages)
c3.metric("⚠️ Vulns",        total_vulns,   delta=None)
c4.metric("🔑 Cred Servers", cred_servers)
c5.metric("🚨 Critical",     crit)
c6.metric("🦠 KEV",          kev_count)

st.divider()

# ─── Tabs ─────────────────────────────────────────────────────────────────────

tab_overview, tab_tree, tab_vulns, tab_remediation = st.tabs([
    "📊 Overview", "🌲 Dependency Tree", "🛡️ Vulnerabilities", "🔧 Remediation",
])

# ── Overview tab ─────────────────────────────────────────────────────────────
with tab_overview:
    col_left, col_right = st.columns([1, 2])

    with col_left:
        # Severity donut
        from agent_bom.models import Severity
        sev_counts = {s.value: 0 for s in Severity if s != Severity.NONE}
        for br in blast_radii:
            sev = br.vulnerability.severity.value
            if sev in sev_counts:
                sev_counts[sev] += 1

        if any(sev_counts.values()):
            fig_donut = go.Figure(go.Pie(
                labels=[k.capitalize() for k in sev_counts],
                values=list(sev_counts.values()),
                hole=0.6,
                marker_colors=[_SEV_COLOR[k] for k in sev_counts],
                textinfo="label+value",
            ))
            fig_donut.update_layout(
                title="Severity Distribution",
                showlegend=True,
                height=320,
                margin=dict(t=40, b=10, l=10, r=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.success("✅ No vulnerabilities found!")

    with col_right:
        # Blast radius scatter: x=CVSS, y=risk_score, size=affected_agents, color=severity
        if blast_radii:
            scatter_data = {
                "vuln_id":   [br.vulnerability.id for br in blast_radii],
                "package":   [br.package.name for br in blast_radii],
                "severity":  [br.vulnerability.severity.value for br in blast_radii],
                "risk_score":[br.risk_score for br in blast_radii],
                "cvss":      [br.vulnerability.cvss_score or 0 for br in blast_radii],
                "agents":    [len(br.affected_agents) for br in blast_radii],
                "creds":     [len(br.exposed_credentials) for br in blast_radii],
            }
            fig_scatter = px.scatter(
                scatter_data,
                x="cvss",
                y="risk_score",
                size="agents",
                color="severity",
                color_discrete_map=_SEV_COLOR,
                hover_data=["vuln_id", "package", "creds"],
                title="Blast Radius: CVSS vs Risk Score",
                labels={"cvss": "CVSS Base Score", "risk_score": "Blast Radius Score"},
                size_max=40,
            )
            fig_scatter.update_layout(
                height=320,
                margin=dict(t=40, b=10, l=10, r=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig_scatter, use_container_width=True)
        else:
            st.info("No blast radius data to display.")

    # Top-10 blast radius bar
    if blast_radii:
        top10 = sorted(blast_radii, key=lambda b: b.risk_score, reverse=True)[:10]
        bar_data = {
            "label":  [f"{br.vulnerability.id[:14]}/{br.package.name[:12]}" for br in top10],
            "score":  [br.risk_score for br in top10],
            "color":  [_SEV_COLOR.get(br.vulnerability.severity.value, "#6b7280") for br in top10],
        }
        fig_bar = go.Figure(go.Bar(
            x=bar_data["score"],
            y=bar_data["label"],
            orientation="h",
            marker_color=bar_data["color"],
        ))
        fig_bar.update_layout(
            title="Top 10 Blast Radius Scores",
            xaxis=dict(range=[0, 10], title="Score"),
            yaxis=dict(autorange="reversed"),
            height=320,
            margin=dict(t=40, b=10, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig_bar, use_container_width=True)

# ── Dependency Tree tab (DFS expanders) ──────────────────────────────────────
with tab_tree:
    st.subheader("Agent → Server → Package → Vulnerabilities")

    vuln_pkg_keys = {(br.package.name, br.package.ecosystem) for br in blast_radii}

    for agent in agents:
        agent_vuln_count = agent.total_vulnerabilities
        agent_cred_count = sum(len(s.credential_names) for s in agent.mcp_servers)
        agent_label = f"🤖 **{agent.name}**"
        if agent_vuln_count:
            agent_label += f"  `{agent_vuln_count} vuln(s)`"
        if agent_cred_count:
            agent_label += f"  🔑 `{agent_cred_count} cred(s)`"

        with st.expander(agent_label, expanded=agent_vuln_count > 0):
            st.caption(f"`{agent.agent_type.value}` · {agent.config_path or ''}")

            for srv in agent.mcp_servers:
                has_vuln = any(
                    (p.name, p.ecosystem) in vuln_pkg_keys for p in srv.packages
                )
                srv_icon = "🔴" if has_vuln else ("🟡" if srv.has_credentials else "🟢")
                srv_label = f"{srv_icon} **{srv.name}** — {len(srv.packages)} pkg(s)"
                if srv.has_credentials:
                    srv_label += f"  🔑 `{', '.join(srv.credential_names)}`"

                with st.expander(srv_label, expanded=has_vuln):
                    if srv.command:
                        st.code(f"{srv.command} {' '.join(srv.args[:5])}", language="bash")

                    for pkg in srv.packages:
                        is_vuln = (pkg.name, pkg.ecosystem) in vuln_pkg_keys
                        pkg_icon = "🔴" if is_vuln else "⚪"
                        pkg_text = f"{pkg_icon} `{pkg.ecosystem}` **{pkg.name}** @ `{pkg.version}`"

                        if is_vuln:
                            with st.expander(pkg_text, expanded=True):
                                # Show matching blast radii
                                pkg_brs = [
                                    br for br in blast_radii
                                    if br.package.name == pkg.name
                                    and br.package.ecosystem == pkg.ecosystem
                                ]
                                for br in pkg_brs:
                                    v = br.vulnerability
                                    sev_color = _SEV_COLOR.get(v.severity.value, "#6b7280")
                                    col_a, col_b, col_c, col_d = st.columns([2, 1, 1, 2])
                                    col_a.markdown(f"[{v.id}](https://osv.dev/vulnerability/{v.id})")
                                    col_b.markdown(
                                        f'<span style="color:{sev_color};font-weight:700">'
                                        f'{v.severity.value.upper()}</span>',
                                        unsafe_allow_html=True,
                                    )
                                    col_c.write(f"Score: **{br.risk_score:.1f}**")
                                    col_d.write(
                                        f"Fix: `{v.fixed_version}`" if v.fixed_version else "No fix yet"
                                    )
                        else:
                            st.markdown(pkg_text)

# ── Vulnerabilities tab ───────────────────────────────────────────────────────
with tab_vulns:
    if not filtered_brs:
        st.success("✅ No vulnerabilities match the current filters.")
    else:
        import pandas as pd

        rows = []
        for br in sorted(filtered_brs, key=lambda b: b.risk_score, reverse=True):
            v = br.vulnerability
            rows.append({
                "Vuln ID":        v.id,
                "Severity":       v.severity.value.upper(),
                "Package":        br.package.name,
                "Version":        br.package.version,
                "CVSS":           v.cvss_score,
                "EPSS":           f"{v.epss_score:.1%}" if v.epss_score else "—",
                "KEV":            "✅" if v.is_kev else "—",
                "Blast Score":    round(br.risk_score, 2),
                "Agents Hit":     len(br.affected_agents),
                "Creds Exposed":  len(br.exposed_credentials),
                "Fix":            v.fixed_version or "—",
                "Summary":        (v.summary or "")[:80],
            })

        df = pd.DataFrame(rows)
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Vuln ID": st.column_config.TextColumn(width="small"),
                "CVSS": st.column_config.NumberColumn(format="%.1f"),
                "Blast Score": st.column_config.ProgressColumn(min_value=0, max_value=10),
            },
        )
        st.caption(f"Showing {len(filtered_brs)} of {len(blast_radii)} findings")

# ── Remediation tab ───────────────────────────────────────────────────────────
with tab_remediation:
    with_fix = sorted(
        [br for br in blast_radii if br.vulnerability.fixed_version],
        key=lambda b: b.risk_score,
        reverse=True,
    )
    no_fix = [br for br in blast_radii if not br.vulnerability.fixed_version]

    if not blast_radii:
        st.success("✅ Nothing to remediate.")
    else:
        if with_fix:
            st.subheader(f"✅ Fixable ({len(with_fix)})")
            for br in with_fix:
                v = br.vulnerability
                sev_color = _SEV_COLOR.get(v.severity.value, "#6b7280")
                col_a, col_b, col_c = st.columns([3, 2, 2])
                col_a.markdown(
                    f'<span style="color:{sev_color};font-weight:700">{v.severity.value.upper()}</span> '
                    f'**{br.package.name}** @ `{br.package.version}`',
                    unsafe_allow_html=True,
                )
                col_b.markdown(f"Upgrade to `{v.fixed_version}`")
                col_c.markdown(
                    f"Protects **{len(br.affected_agents)}** agent(s)"
                    + (f" · frees **{len(br.exposed_credentials)}** cred(s)" if br.exposed_credentials else "")
                )

        if no_fix:
            st.divider()
            st.subheader(f"⏳ No fix available ({len(no_fix)})")
            for br in no_fix:
                v = br.vulnerability
                sev_color = _SEV_COLOR.get(v.severity.value, "#6b7280")
                st.markdown(
                    f'<span style="color:{sev_color}">{v.severity.value.upper()}</span> '
                    f'`{v.id}` — **{br.package.name}** @ `{br.package.version}` '
                    f'— monitor upstream for a patch',
                    unsafe_allow_html=True,
                )
