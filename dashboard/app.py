"""agent-bom Interactive Dashboard — Streamlit app for AI-BOM / SBOM visualization.

Launch:
    streamlit run dashboard/app.py
    streamlit run dashboard/app.py -- --report path/to/report.json

Or generate a report first:
    agent-bom scan --demo -f json -o report.json
    agent-bom scan --self-scan -f json -o report.json
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

try:
    from dashboard.data import SEV_COLORS, SEV_ORDER, extract_blast_radius, extract_packages
except ImportError:
    from data import SEV_COLORS, SEV_ORDER, extract_blast_radius, extract_packages

# ─── Page Config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="agent-bom Dashboard",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────

st.markdown(
    """
<style>
    .block-container { padding-top: 1rem; }
    [data-testid="stMetric"] {
        background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
        padding: 12px 16px;
        border-radius: 8px;
        border-left: 3px solid #6366f1;
    }
    [data-testid="stMetric"] label { font-size: 0.8rem; color: #a1a1aa; }
    .severity-critical { color: #ef4444; font-weight: 700; }
    .severity-high { color: #f97316; font-weight: 700; }
    .severity-medium { color: #eab308; font-weight: 600; }
    .severity-low { color: #3b82f6; }
    div[data-testid="stTabs"] button { font-size: 0.9rem; }
</style>
""",
    unsafe_allow_html=True,
)


# ─── Data Loading ─────────────────────────────────────────────────────────────


def _run_scan(mode: str) -> dict:
    """Run agent-bom scan and return JSON report."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp = f.name
    cmd = ["agent-bom", "scan", f"--{mode}", "-f", "json", "-o", tmp, "--quiet"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=120)
        return json.loads(Path(tmp).read_text())
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        st.error(f"Scan failed: {e}")
        return {}
    finally:
        Path(tmp).unlink(missing_ok=True)


@st.cache_data(ttl=300)
def load_report(path: str | None, mode: str | None) -> dict:
    if path and Path(path).exists():
        return json.loads(Path(path).read_text())
    if mode:
        return _run_scan(mode)
    return {}


# ─── Sidebar ──────────────────────────────────────────────────────────────────

st.sidebar.title("agent-bom")
st.sidebar.caption("AI Supply Chain Security")

source = st.sidebar.radio(
    "Data source",
    ["Upload JSON report", "Live scan (--self-scan)", "Live scan (--demo)"],
    index=0,
)

report_data: dict = {}
uploaded = None

if source == "Upload JSON report":
    uploaded = st.sidebar.file_uploader("Upload report JSON", type=["json"])
    if uploaded:
        report_data = json.loads(uploaded.read())
    else:
        # Check CLI args
        report_path = None
        for i, arg in enumerate(sys.argv):
            if arg == "--report" and i + 1 < len(sys.argv):
                report_path = sys.argv[i + 1]
        if report_path:
            report_data = load_report(report_path, None)
elif source == "Live scan (--self-scan)":
    if st.sidebar.button("Run Self-Scan"):
        with st.spinner("Scanning agent-bom dependencies..."):
            report_data = load_report(None, "self-scan")
elif source == "Live scan (--demo)":
    if st.sidebar.button("Run Demo Scan"):
        with st.spinner("Running demo scan with vulnerable packages..."):
            report_data = load_report(None, "demo")

if not report_data:
    st.title("agent-bom Dashboard")
    st.info(
        "Upload an agent-bom JSON report, or run a live scan from the sidebar.\n\n"
        "Generate a report:\n"
        "```bash\n"
        "agent-bom scan --self-scan -f json -o report.json\n"
        "agent-bom scan --demo -f json -o report.json\n"
        "```"
    )
    st.stop()

# ─── Parse Data ───────────────────────────────────────────────────────────────

summary = report_data.get("summary", {})
agents = report_data.get("agents", [])
pkg_df = extract_packages(report_data)
br_df = extract_blast_radius(report_data)
vuln_df = pkg_df[pkg_df["vuln_id"] != ""].copy() if not pkg_df.empty else pd.DataFrame()
posture = report_data.get("posture_scorecard", {})
frameworks = report_data.get("threat_framework_summary", {})

# ─── Severity filter ─────────────────────────────────────────────────────────

sev_filter = st.sidebar.multiselect(
    "Severity filter",
    options=SEV_ORDER[:4],
    default=SEV_ORDER[:4],
)

if not vuln_df.empty:
    vuln_df = vuln_df[vuln_df["severity"].isin(sev_filter)]
if not br_df.empty:
    br_df = br_df[br_df["severity"].isin(sev_filter)]

st.sidebar.divider()
st.sidebar.markdown(f"**Version:** {report_data.get('ai_bom_version', '?')}")
st.sidebar.markdown(f"**Generated:** {report_data.get('generated_at', '?')[:19]}")

# ─── Tabs ─────────────────────────────────────────────────────────────────────

tabs = st.tabs(
    [
        "Overview",
        "Supply Chain",
        "Vulnerabilities",
        "Blast Radius",
        "Compliance",
        "SBOM / AI-BOM",
        "Scan Pipeline",
    ]
)

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1: OVERVIEW
# ═══════════════════════════════════════════════════════════════════════════════

with tabs[0]:
    st.header("Security Posture Overview")

    # KPI metrics row
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Agents", summary.get("total_agents", 0))
    c2.metric("MCP Servers", summary.get("total_mcp_servers", 0))
    c3.metric("Packages", summary.get("total_packages", 0))
    c4.metric("Vulnerabilities", summary.get("total_vulnerabilities", 0))
    c5.metric("Critical", summary.get("critical_findings", 0))

    grade = posture.get("grade", "?")
    score = posture.get("score", 0)
    c6.metric("Posture Grade", f"{grade} ({score}%)")

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Severity Distribution")
        if not vuln_df.empty:
            sev_counts = vuln_df["severity"].value_counts().reindex(SEV_ORDER).dropna().reset_index()
            sev_counts.columns = ["severity", "count"]
            fig = px.bar(
                sev_counts,
                x="severity",
                y="count",
                color="severity",
                color_discrete_map=SEV_COLORS,
            )
            fig.update_layout(showlegend=False, height=300, margin=dict(t=10))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.success("No vulnerabilities found.")

    with right:
        st.subheader("Packages by Ecosystem")
        if not pkg_df.empty:
            eco_counts = pkg_df.drop_duplicates(subset=["package", "ecosystem"]).groupby("ecosystem").size().reset_index(name="count")
            fig = px.pie(eco_counts, names="ecosystem", values="count", hole=0.4)
            fig.update_layout(height=300, margin=dict(t=10))
            st.plotly_chart(fig, use_container_width=True)

    # Posture dimensions
    dims = posture.get("dimensions", {})
    if dims:
        st.subheader("Posture Scorecard Dimensions")
        dim_names = []
        dim_scores = []
        dim_colors = []
        for name, info in dims.items():
            dim_names.append(name.replace("_", " ").title())
            s = info.get("score", 0) if isinstance(info, dict) else 0
            dim_scores.append(s)
            dim_colors.append("#22c55e" if s >= 80 else "#eab308" if s >= 50 else "#ef4444")

        fig = go.Figure(
            go.Bar(
                x=dim_scores,
                y=dim_names,
                orientation="h",
                marker_color=dim_colors,
                text=[f"{s}%" for s in dim_scores],
                textposition="auto",
            )
        )
        fig.update_layout(height=max(200, len(dim_names) * 35), margin=dict(l=10, r=10, t=10, b=10), xaxis_range=[0, 100])
        st.plotly_chart(fig, use_container_width=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2: SUPPLY CHAIN (treemap + dependency tree)
# ═══════════════════════════════════════════════════════════════════════════════

with tabs[1]:
    st.header("Supply Chain Map")

    if not pkg_df.empty:
        # Treemap: agent → server → ecosystem → package
        tree_rows = []
        for _, row in pkg_df.drop_duplicates(subset=["agent", "server", "package"]).iterrows():
            has_vuln = row["vuln_id"] != "" if "vuln_id" in row else False
            tree_rows.append(
                {
                    "agent": row["agent"],
                    "server": row["server"],
                    "ecosystem": row["ecosystem"],
                    "package": f"{row['package']}@{row['version']}",
                    "value": 1,
                    "color": SEV_COLORS.get(row["severity"], "#22c55e") if has_vuln else "#22c55e",
                }
            )

        tree_df = pd.DataFrame(tree_rows)

        st.subheader("Dependency Treemap")
        st.caption("Agent > Server > Ecosystem > Package. Red = vulnerable, green = clean.")

        # Build identity map from unique color values so Plotly keeps them as-is
        color_identity = {c: c for c in tree_df["color"].unique()}
        fig = px.treemap(
            tree_df,
            path=["agent", "server", "ecosystem", "package"],
            values="value",
            color="color",
            color_discrete_map=color_identity,
        )
        fig.update_layout(height=500, margin=dict(t=30, l=10, r=10, b=10))
        fig.update_traces(textinfo="label+value")
        st.plotly_chart(fig, use_container_width=True)

        # Dependency table
        st.subheader("All Packages")
        display_cols = ["agent", "server", "package", "version", "ecosystem", "license"]
        deduped = pkg_df.drop_duplicates(subset=["agent", "server", "package"])[display_cols]
        st.dataframe(deduped, use_container_width=True, hide_index=True, height=400)
    else:
        st.info("No packages found in report.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3: VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════════

with tabs[2]:
    st.header("Vulnerability Browser")

    if not vuln_df.empty:
        # Summary metrics
        vc1, vc2, vc3, vc4 = st.columns(4)
        vc1.metric("Total", len(vuln_df))
        vc2.metric("CISA KEV", int(vuln_df["is_kev"].sum()))
        vc3.metric("With Fix", int((vuln_df["fixed_version"] != "").sum()))
        vc4.metric("Avg CVSS", f"{vuln_df['cvss'].mean():.1f}")

        st.divider()

        left, right = st.columns(2)

        with left:
            st.subheader("CVSS vs EPSS Scatter")
            fig = px.scatter(
                vuln_df,
                x="cvss",
                y="epss",
                color="severity",
                hover_data=["vuln_id", "package", "agent"],
                color_discrete_map=SEV_COLORS,
                size="cvss",
                size_max=15,
            )
            fig.update_layout(height=350, margin=dict(t=10))
            st.plotly_chart(fig, use_container_width=True)

        with right:
            st.subheader("Top Vulnerable Packages")
            pkg_vuln_counts = (
                vuln_df.groupby("package")
                .agg(
                    count=("vuln_id", "nunique"),
                    max_cvss=("cvss", "max"),
                )
                .sort_values("count", ascending=False)
                .head(15)
                .reset_index()
            )
            fig = px.bar(
                pkg_vuln_counts,
                x="count",
                y="package",
                orientation="h",
                color="max_cvss",
                color_continuous_scale="YlOrRd",
            )
            fig.update_layout(height=350, margin=dict(t=10, l=10))
            st.plotly_chart(fig, use_container_width=True)

        # Full table
        st.subheader("All Vulnerabilities")
        display = vuln_df[
            ["vuln_id", "severity", "cvss", "epss", "is_kev", "package", "version", "fixed_version", "agent", "server"]
        ].copy()
        display.columns = ["CVE", "Severity", "CVSS", "EPSS", "KEV", "Package", "Version", "Fix", "Agent", "Server"]
        display = display.sort_values(["CVSS", "EPSS"], ascending=[False, False])
        st.dataframe(
            display,
            use_container_width=True,
            hide_index=True,
            height=400,
            column_config={
                "CVSS": st.column_config.NumberColumn(format="%.1f"),
                "EPSS": st.column_config.NumberColumn(format="%.4f"),
                "KEV": st.column_config.CheckboxColumn(),
            },
        )
    else:
        st.success("No vulnerabilities found. Your supply chain is clean.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4: BLAST RADIUS
# ═══════════════════════════════════════════════════════════════════════════════

with tabs[3]:
    st.header("Blast Radius Analysis")

    if not br_df.empty:
        st.caption("How vulnerabilities propagate to agents, credentials, and tools.")

        bc1, bc2, bc3 = st.columns(3)
        bc1.metric("Unique CVEs", br_df["vuln_id"].nunique())
        bc2.metric("Exposed Credentials", int((br_df["exposed_creds"] != "").sum()))
        bc3.metric("Avg Risk Score", f"{br_df['risk_score'].mean():.1f}")

        st.divider()

        # Sunburst: severity → package → agent
        st.subheader("Blast Radius Sunburst")
        fig = px.sunburst(
            br_df,
            path=["severity", "package", "affected_agents"],
            values="risk_score",
            color="severity",
            color_discrete_map=SEV_COLORS,
        )
        fig.update_layout(height=500, margin=dict(t=30, l=10, r=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

        # Risk heatmap: package vs agent
        st.subheader("Risk Heatmap (Package x Agent)")
        pivot_rows = []
        for _, row in br_df.iterrows():
            for agent in row["affected_agents"].split(", "):
                if agent:
                    pivot_rows.append({"package": row["package"], "agent": agent, "risk": row["risk_score"]})
        if pivot_rows:
            pivot_df = pd.DataFrame(pivot_rows)
            heatmap = pivot_df.pivot_table(index="package", columns="agent", values="risk", aggfunc="max", fill_value=0)
            fig = px.imshow(
                heatmap,
                color_continuous_scale="YlOrRd",
                aspect="auto",
                labels={"color": "Risk Score"},
            )
            fig.update_layout(height=max(300, len(heatmap) * 30), margin=dict(t=10))
            st.plotly_chart(fig, use_container_width=True)

        # Full blast radius table
        st.subheader("Blast Radius Detail")
        st.dataframe(br_df, use_container_width=True, hide_index=True, height=400)
    else:
        st.success("No blast radius findings. Your supply chain is clean.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5: COMPLIANCE
# ═══════════════════════════════════════════════════════════════════════════════

with tabs[4]:
    st.header("Compliance & Threat Frameworks")

    if frameworks:
        fw_names = []
        fw_scores = []
        fw_statuses = []

        for fw_key, fw_data in frameworks.items():
            if not isinstance(fw_data, dict):
                continue
            name = fw_key.replace("_", " ").upper()
            score = fw_data.get("overall_score", fw_data.get("score", 0))
            status = fw_data.get("overall_status", fw_data.get("status", "unknown"))
            fw_names.append(name)
            fw_scores.append(score)
            fw_statuses.append(status)

        if fw_names:
            # Radar chart
            st.subheader("Framework Coverage Radar")
            fig = go.Figure()
            fig.add_trace(
                go.Scatterpolar(
                    r=fw_scores + [fw_scores[0]],
                    theta=fw_names + [fw_names[0]],
                    fill="toself",
                    fillcolor="rgba(99, 102, 241, 0.2)",
                    line=dict(color="#6366f1"),
                    name="Score",
                )
            )
            fig.update_layout(
                polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
                height=450,
                margin=dict(t=30),
            )
            st.plotly_chart(fig, use_container_width=True)

            # Framework bars
            st.subheader("Framework Scores")
            fw_df = pd.DataFrame({"Framework": fw_names, "Score": fw_scores, "Status": fw_statuses})
            fw_df = fw_df.sort_values("Score", ascending=True)
            colors = ["#22c55e" if s >= 80 else "#eab308" if s >= 50 else "#ef4444" for s in fw_df["Score"]]
            fig = go.Figure(
                go.Bar(
                    x=fw_df["Score"],
                    y=fw_df["Framework"],
                    orientation="h",
                    marker_color=colors,
                    text=[f"{s}% ({st})" for s, st in zip(fw_df["Score"], fw_df["Status"])],
                    textposition="auto",
                )
            )
            fig.update_layout(height=max(250, len(fw_names) * 40), margin=dict(l=10, r=10, t=10, b=10), xaxis_range=[0, 100])
            st.plotly_chart(fig, use_container_width=True)

            # Expandable details per framework
            for fw_key, fw_data in frameworks.items():
                if not isinstance(fw_data, dict):
                    continue
                name = fw_key.replace("_", " ").upper()
                controls = fw_data.get("controls", fw_data.get("checks", fw_data.get("techniques", [])))
                if not controls or not isinstance(controls, list):
                    continue
                with st.expander(f"{name} — {len(controls)} controls"):
                    ctrl_rows = []
                    for ctrl in controls:
                        if isinstance(ctrl, dict):
                            ctrl_rows.append(
                                {
                                    "ID": ctrl.get("id", ctrl.get("technique_id", "")),
                                    "Name": ctrl.get("name", ctrl.get("description", ctrl.get("title", ""))),
                                    "Status": ctrl.get("status", ctrl.get("overall_status", "")),
                                    "Score": ctrl.get("score", ""),
                                }
                            )
                    if ctrl_rows:
                        st.dataframe(pd.DataFrame(ctrl_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No compliance data in this report.")

    # CIS benchmark data
    cis_aws = report_data.get("cis_benchmark_data")
    cis_sf = report_data.get("snowflake_cis_benchmark_data")

    if cis_aws or cis_sf:
        st.divider()
        st.subheader("CIS Benchmarks")

        for label, cis_data in [("AWS CIS Foundations v3.0", cis_aws), ("Snowflake CIS v1.0", cis_sf)]:
            if not cis_data:
                continue
            with st.expander(
                f"{label} — {cis_data.get('passed', 0)}/{cis_data.get('total', 0)} passed ({cis_data.get('pass_rate', 0):.0f}%)"
            ):
                checks = cis_data.get("checks", [])
                if checks:
                    cis_rows = []
                    for c in checks:
                        icon = {"pass": "PASS", "fail": "FAIL", "error": "ERROR", "not_applicable": "N/A"}.get(
                            c.get("status", ""), c.get("status", "")
                        )
                        cis_rows.append(
                            {
                                "ID": c.get("check_id", ""),
                                "Title": c.get("title", ""),
                                "Status": icon,
                                "Severity": c.get("severity", ""),
                                "Evidence": c.get("evidence", "")[:100],
                            }
                        )
                    st.dataframe(pd.DataFrame(cis_rows), use_container_width=True, hide_index=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 6: SBOM / AI-BOM
# ═══════════════════════════════════════════════════════════════════════════════

with tabs[5]:
    st.header("SBOM / AI-BOM Explorer")

    st.subheader("Document Info")
    info_cols = st.columns(4)
    info_cols[0].metric("Document Type", report_data.get("document_type", "AI-BOM"))
    info_cols[1].metric("Spec Version", report_data.get("spec_version", "?"))
    info_cols[2].metric("Tool Version", report_data.get("ai_bom_version", "?"))
    info_cols[3].metric("Generated", report_data.get("generated_at", "?")[:10])

    st.divider()

    # Agent inventory
    st.subheader("Agent Inventory")
    for agent in agents:
        agent_name = agent.get("name", "unknown")
        servers = agent.get("mcp_servers", [])
        total_pkgs = sum(len(s.get("packages", [])) for s in servers)
        total_tools = sum(len(s.get("tools", [])) for s in servers)
        creds = []
        for s in servers:
            creds.extend(s.get("credential_env_vars", []))

        with st.expander(f"**{agent_name}** — {len(servers)} server(s), {total_pkgs} package(s), {total_tools} tool(s)"):
            st.markdown(f"- **Type:** {agent.get('type', '?')}")
            st.markdown(f"- **Source:** {agent.get('source', '?')}")
            st.markdown(f"- **Config:** {agent.get('config_path', 'N/A')}")

            if creds:
                st.warning(f"Credentials: {', '.join(creds)}")

            for srv in servers:
                st.markdown(f"---\n**Server: {srv['name']}** ({srv.get('transport', '?')})")

                tools = srv.get("tools", [])
                if tools:
                    tool_names = [t.get("name", "?") for t in tools]
                    st.markdown(f"Tools: `{'`, `'.join(tool_names)}`")

                pkgs = srv.get("packages", [])
                if pkgs:
                    pkg_rows = []
                    for p in pkgs:
                        vuln_count = len(p.get("vulnerabilities", []))
                        pkg_rows.append(
                            {
                                "Package": p["name"],
                                "Version": p.get("version", "?"),
                                "Ecosystem": p.get("ecosystem", "?"),
                                "License": p.get("license", ""),
                                "Vulns": vuln_count,
                            }
                        )
                    st.dataframe(pd.DataFrame(pkg_rows), use_container_width=True, hide_index=True)

    st.divider()

    # Raw JSON viewer
    st.subheader("Raw Report JSON")
    with st.expander("View raw JSON"):
        st.json(report_data)

    # Download buttons
    dl1, dl2 = st.columns(2)
    with dl1:
        st.download_button(
            "Download AI-BOM (JSON)",
            data=json.dumps(report_data, indent=2, default=str),
            file_name="ai-bom.json",
            mime="application/json",
        )
    with dl2:
        st.caption("Generate CycloneDX/SPDX SBOMs via CLI:")
        st.code("agent-bom scan -f cyclonedx -o sbom.json\nagent-bom scan -f spdx -o sbom.spdx.json", language="bash")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 7: SCAN PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

with tabs[6]:
    st.header("Scan Pipeline Visualization")

    st.caption("How agent-bom discovers, parses, enriches, scans, and reports.")

    # Pipeline stages as a Sankey diagram
    stages = [
        "Discovery",
        "Parsing",
        "Resolution",
        "Enrichment",
        "Scanning",
        "Blast Radius",
        "Compliance",
        "Output",
    ]
    descriptions = {
        "Discovery": "Auto-detect 22 MCP client configs (Claude Desktop, Cursor, VS Code, etc.)",
        "Parsing": "Extract servers, packages, credentials, tools from config JSON/YAML",
        "Resolution": "Resolve versions via npm/PyPI registries, deps.dev, lock files",
        "Enrichment": "Add licenses, EPSS scores, KEV status, NVD data, scorecards",
        "Scanning": "Match packages against OSV, NVD, GitHub Advisories for CVEs",
        "Blast Radius": "Map CVE → package → server → credentials → tools → agents",
        "Compliance": "Tag findings against 14 frameworks (OWASP, ATLAS, NIST, EU AI Act, ...)",
        "Output": "JSON, CycloneDX SBOM, SPDX SBOM, HTML, SARIF, Prometheus, Badge",
    }

    for i, stage in enumerate(stages):
        col_num, col_desc = st.columns([1, 4])
        with col_num:
            st.markdown(f"### Step {i + 1}")
        with col_desc:
            st.markdown(f"**{stage}**")
            st.markdown(descriptions[stage])
            if i < len(stages) - 1:
                st.markdown("---")

    st.divider()

    # Data flow stats from this report
    st.subheader("This Scan's Pipeline Stats")
    p1, p2, p3, p4 = st.columns(4)
    p1.metric("Agents Discovered", summary.get("total_agents", 0))
    p2.metric("Packages Parsed", summary.get("total_packages", 0))
    p3.metric("CVEs Matched", summary.get("total_vulnerabilities", 0))
    p4.metric("Frameworks Evaluated", len(frameworks))

    # Sankey: flow from sources to agents to servers to packages to vulns
    if agents:
        st.subheader("Data Flow Sankey")

        labels = []
        sources_idx = []
        targets_idx = []
        values = []
        colors = []

        node_map: dict[str, int] = {}

        def _get_idx(name: str) -> int:
            if name not in node_map:
                node_map[name] = len(labels)
                labels.append(name)
            return node_map[name]

        for agent in agents:
            src = agent.get("source", "local") or "local"
            src_idx = _get_idx(f"Source: {src}")
            agent_idx = _get_idx(f"Agent: {agent['name']}")
            srv_list = agent.get("mcp_servers", [])

            sources_idx.append(src_idx)
            targets_idx.append(agent_idx)
            values.append(max(1, len(srv_list)))
            colors.append("rgba(99, 102, 241, 0.4)")

            for srv in srv_list:
                srv_idx = _get_idx(f"Server: {srv['name']}")
                sources_idx.append(agent_idx)
                targets_idx.append(srv_idx)
                pkg_count = len(srv.get("packages", []))
                values.append(max(1, pkg_count))
                colors.append("rgba(34, 197, 94, 0.4)")

                vuln_count = sum(len(p.get("vulnerabilities", [])) for p in srv.get("packages", []))
                if vuln_count > 0:
                    vuln_idx = _get_idx(f"CVEs ({vuln_count})")
                    sources_idx.append(srv_idx)
                    targets_idx.append(vuln_idx)
                    values.append(vuln_count)
                    colors.append("rgba(239, 68, 68, 0.4)")

                clean = pkg_count - sum(1 for p in srv.get("packages", []) if p.get("vulnerabilities"))
                if clean > 0:
                    clean_idx = _get_idx("Clean Packages")
                    sources_idx.append(srv_idx)
                    targets_idx.append(clean_idx)
                    values.append(clean)
                    colors.append("rgba(34, 197, 94, 0.4)")

        if sources_idx:
            fig = go.Figure(
                go.Sankey(
                    node=dict(
                        label=labels,
                        pad=15,
                        thickness=20,
                        color=["#6366f1"] * len(labels),
                    ),
                    link=dict(
                        source=sources_idx,
                        target=targets_idx,
                        value=values,
                        color=colors,
                    ),
                )
            )
            fig.update_layout(height=400, margin=dict(t=10, l=10, r=10, b=10))
            st.plotly_chart(fig, use_container_width=True)


# ─── Footer ───────────────────────────────────────────────────────────────────

st.divider()
st.caption("agent-bom Dashboard | AI Supply Chain Security | github.com/msaad00/agent-bom")
