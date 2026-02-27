"""
agent-bom: Streamlit in Snowflake (SiS) Dashboard

Reads directly from shared Snowflake tables populated by the agent-bom API
running in Snowpark Container Services. No HTTP calls required.

Tables: scan_jobs, fleet_agents, gateway_policies, policy_audit_log
"""

import json

import pandas as pd
import plotly.express as px
import streamlit as st

# ─── Connection ───────────────────────────────────────────────────────────────

_conn = st.connection("snowflake")


def _query(sql: str) -> pd.DataFrame:
    return _conn.query(sql)


# ─── Data Loading ─────────────────────────────────────────────────────────────


@st.cache_data(ttl=60)
def load_jobs() -> pd.DataFrame:
    return _query(
        "SELECT job_id, status, created_at, completed_at, data "
        "FROM core.scan_jobs ORDER BY created_at DESC LIMIT 100"
    )


@st.cache_data(ttl=60)
def load_fleet() -> pd.DataFrame:
    return _query(
        "SELECT agent_id, name, lifecycle_state, trust_score, updated_at, data "
        "FROM core.fleet_agents ORDER BY name"
    )


@st.cache_data(ttl=60)
def load_policies() -> pd.DataFrame:
    return _query(
        "SELECT policy_id, name, mode, enabled, updated_at, data "
        "FROM core.gateway_policies ORDER BY name"
    )


@st.cache_data(ttl=60)
def load_audit(limit: int = 200) -> pd.DataFrame:
    return _query(
        f"SELECT entry_id, policy_id, agent_name, action_taken, timestamp, data "
        f"FROM core.policy_audit_log ORDER BY timestamp DESC LIMIT {limit}"
    )


def _parse_variant(df: pd.DataFrame, col: str = "DATA") -> list[dict]:
    """Parse VARIANT column into list of dicts."""
    results = []
    for val in df[col]:
        if isinstance(val, str):
            results.append(json.loads(val))
        elif isinstance(val, dict):
            results.append(val)
        else:
            results.append({})
    return results


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _extract_vulns_from_job(job_data: dict) -> list[dict]:
    """Extract vulnerability records from a scan job result."""
    vulns = []
    result = job_data.get("result", {})
    if not result:
        return vulns
    for agent in result.get("agents", []):
        agent_name = agent.get("name", "unknown")
        for server in agent.get("mcp_servers", []):
            for pkg in server.get("packages", []):
                for vuln in pkg.get("vulnerabilities", []):
                    vulns.append({
                        "id": vuln.get("id", ""),
                        "severity": vuln.get("severity", "unknown"),
                        "cvss": vuln.get("cvss_score", 0),
                        "epss": vuln.get("epss_score", 0),
                        "kev": vuln.get("is_kev", False),
                        "package": pkg.get("name", ""),
                        "version": pkg.get("version", ""),
                        "fixed_version": vuln.get("fixed_version", ""),
                        "agent": agent_name,
                        "server": server.get("name", ""),
                    })
    return vulns


def _severity_color(sev: str) -> str:
    return {
        "critical": "#dc2626",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#3b82f6",
    }.get(sev.lower(), "#6b7280")


# ─── Page Config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="agent-bom | AI Supply Chain Security",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ agent-bom — AI Supply Chain Security")

# ─── Sidebar ──────────────────────────────────────────────────────────────────

st.sidebar.header("Filters")

jobs_df = load_jobs()
job_ids = jobs_df["JOB_ID"].tolist() if not jobs_df.empty else []
selected_job = st.sidebar.selectbox(
    "Scan Job",
    options=["Latest"] + job_ids,
    index=0,
)

severity_filter = st.sidebar.multiselect(
    "Severity",
    options=["critical", "high", "medium", "low"],
    default=["critical", "high", "medium", "low"],
)

fleet_df = load_fleet()
agent_names = fleet_df["NAME"].tolist() if not fleet_df.empty else []
agent_filter = st.sidebar.multiselect(
    "Agents",
    options=agent_names,
    default=agent_names,
)

# ─── Load Selected Job ───────────────────────────────────────────────────────

job_data: dict = {}
if not jobs_df.empty:
    if selected_job == "Latest":
        job_data = _parse_variant(jobs_df.head(1))[0]
    else:
        match = jobs_df[jobs_df["JOB_ID"] == selected_job]
        if not match.empty:
            job_data = _parse_variant(match)[0]

all_vulns = _extract_vulns_from_job(job_data) if job_data else []
filtered_vulns = [
    v for v in all_vulns
    if v["severity"].lower() in severity_filter
    and (not agent_filter or v["agent"] in agent_filter)
]

# ─── Tabs ─────────────────────────────────────────────────────────────────────

tab_dash, tab_agents, tab_vulns, tab_compliance, tab_policies = st.tabs(
    ["Dashboard", "Agents", "Vulnerabilities", "Compliance", "Policies"]
)

# ── Tab 1: Dashboard ─────────────────────────────────────────────────────────

with tab_dash:
    col1, col2, col3, col4, col5 = st.columns(5)

    result = job_data.get("result", {})
    agents = result.get("agents", [])
    total_servers = sum(len(a.get("mcp_servers", [])) for a in agents)
    total_pkgs = sum(
        len(s.get("packages", []))
        for a in agents for s in a.get("mcp_servers", [])
    )
    total_creds = sum(
        len(s.get("env_keys", []))
        for a in agents for s in a.get("mcp_servers", [])
    )
    kev_count = sum(1 for v in all_vulns if v.get("kev"))

    col1.metric("Agents", len(agents))
    col2.metric("MCP Servers", total_servers)
    col3.metric("Packages", total_pkgs)
    col4.metric("Vulnerabilities", len(all_vulns))
    col5.metric("CISA KEV", kev_count)

    st.divider()

    if all_vulns:
        left, right = st.columns(2)

        with left:
            st.subheader("Severity Distribution")
            sev_counts = pd.DataFrame(all_vulns).groupby("severity").size().reset_index(name="count")
            order = ["critical", "high", "medium", "low"]
            sev_counts["severity"] = pd.Categorical(sev_counts["severity"], categories=order, ordered=True)
            sev_counts = sev_counts.sort_values("severity")
            fig = px.bar(
                sev_counts,
                x="severity",
                y="count",
                color="severity",
                color_discrete_map={
                    "critical": "#dc2626", "high": "#f97316",
                    "medium": "#eab308", "low": "#3b82f6",
                },
            )
            fig.update_layout(showlegend=False, height=300)
            st.plotly_chart(fig, use_container_width=True)

        with right:
            st.subheader("Blast Radius (CVSS vs EPSS)")
            vuln_df = pd.DataFrame(all_vulns)
            if not vuln_df.empty and vuln_df["cvss"].sum() > 0:
                fig2 = px.scatter(
                    vuln_df,
                    x="cvss",
                    y="epss",
                    color="severity",
                    hover_data=["id", "package", "agent"],
                    color_discrete_map={
                        "critical": "#dc2626", "high": "#f97316",
                        "medium": "#eab308", "low": "#3b82f6",
                    },
                )
                fig2.update_layout(height=300)
                st.plotly_chart(fig2, use_container_width=True)
            else:
                st.info("No CVSS/EPSS data available for scatter plot.")
    else:
        st.success("No vulnerabilities found in the selected scan.")

# ── Tab 2: Agents ────────────────────────────────────────────────────────────

with tab_agents:
    st.subheader("Fleet Registry")

    if not fleet_df.empty:
        display_df = fleet_df[["NAME", "LIFECYCLE_STATE", "TRUST_SCORE", "UPDATED_AT"]].copy()
        display_df.columns = ["Name", "State", "Trust Score", "Updated"]

        # Color-code states
        def _state_badge(state: str) -> str:
            colors = {
                "discovered": "🔵", "pending_review": "🟡",
                "approved": "🟢", "quarantined": "🔴",
                "decommissioned": "⚫",
            }
            return f"{colors.get(state, '⚪')} {state}"

        display_df["State"] = display_df["State"].apply(_state_badge)
        st.dataframe(display_df, use_container_width=True, hide_index=True)

        # State distribution
        state_counts = fleet_df["LIFECYCLE_STATE"].value_counts().reset_index()
        state_counts.columns = ["State", "Count"]
        fig = px.pie(state_counts, names="State", values="Count", hole=0.4)
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No agents registered in the fleet. Run a scan to discover agents.")

# ── Tab 3: Vulnerabilities ───────────────────────────────────────────────────

with tab_vulns:
    st.subheader("Vulnerability Browser")

    if filtered_vulns:
        vuln_table = pd.DataFrame(filtered_vulns)
        vuln_table = vuln_table[["id", "severity", "cvss", "epss", "kev", "package", "version", "fixed_version", "agent", "server"]]
        vuln_table.columns = ["CVE", "Severity", "CVSS", "EPSS", "KEV", "Package", "Version", "Fix", "Agent", "Server"]
        vuln_table = vuln_table.sort_values(["CVSS", "EPSS"], ascending=[False, False])

        st.dataframe(
            vuln_table,
            use_container_width=True,
            hide_index=True,
            column_config={
                "CVSS": st.column_config.NumberColumn(format="%.1f"),
                "EPSS": st.column_config.NumberColumn(format="%.3f"),
                "KEV": st.column_config.CheckboxColumn(),
            },
        )

        st.caption(f"Showing {len(filtered_vulns)} of {len(all_vulns)} vulnerabilities")
    else:
        st.success("No vulnerabilities match the current filters.")

# ── Tab 4: Compliance ────────────────────────────────────────────────────────

with tab_compliance:
    st.subheader("Compliance Posture")

    compliance = result.get("compliance", {})
    if compliance:
        frameworks = compliance.get("frameworks", {})
        for fw_name, fw_data in frameworks.items():
            score = fw_data.get("score", 0)
            status = fw_data.get("status", "unknown")
            checks = fw_data.get("checks", [])

            color = "green" if score >= 80 else "orange" if score >= 50 else "red"
            st.markdown(f"### {fw_name} — :{color}[{score}%] ({status})")

            if checks:
                for check in checks:
                    icon = "✅" if check.get("passed") else "❌"
                    st.markdown(f"- {icon} **{check.get('id', '')}**: {check.get('description', '')}")
            st.divider()
    else:
        st.info("No compliance data in the selected scan. Run with `--compliance` flag.")

# ── Tab 5: Policies ──────────────────────────────────────────────────────────

with tab_policies:
    left_col, right_col = st.columns(2)

    with left_col:
        st.subheader("Gateway Policies")
        policies_df = load_policies()

        if not policies_df.empty:
            display_p = policies_df[["NAME", "MODE", "ENABLED", "UPDATED_AT"]].copy()
            display_p.columns = ["Name", "Mode", "Enabled", "Updated"]
            st.dataframe(display_p, use_container_width=True, hide_index=True)
        else:
            st.info("No policies configured.")

    with right_col:
        st.subheader("Audit Log")
        audit_df = load_audit()

        if not audit_df.empty:
            display_a = audit_df[["AGENT_NAME", "ACTION_TAKEN", "POLICY_ID", "TIMESTAMP"]].copy()
            display_a.columns = ["Agent", "Action", "Policy", "Time"]
            st.dataframe(display_a, use_container_width=True, hide_index=True)

            # Action distribution
            action_counts = audit_df["ACTION_TAKEN"].value_counts().reset_index()
            action_counts.columns = ["Action", "Count"]
            fig = px.pie(
                action_counts,
                names="Action",
                values="Count",
                hole=0.4,
                color="Action",
                color_discrete_map={
                    "blocked": "#dc2626",
                    "alerted": "#eab308",
                    "allowed": "#22c55e",
                },
            )
            fig.update_layout(height=250)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No audit entries yet.")

# ─── Footer ──────────────────────────────────────────────────────────────────

st.divider()
st.caption("agent-bom | AI Supply Chain Security | github.com/msaad00/agent-bom")
