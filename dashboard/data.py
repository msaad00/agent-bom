"""Pure data extraction helpers for the agent-bom dashboard.

No Streamlit imports — can be used standalone or from tests.

Consumed by ``dashboard/app.py`` and ``tests/test_dashboard.py``.
"""

from __future__ import annotations

import pandas as pd

SEV_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "unknown": "#6b7280",
}

SEV_ORDER = ["critical", "high", "medium", "low", "unknown"]


def extract_packages(report: dict) -> pd.DataFrame:
    """Extract all packages from an agent-bom report into a flat DataFrame."""
    rows = []
    for agent in report.get("agents", []):
        for srv in agent.get("mcp_servers", []):
            for pkg in srv.get("packages", []):
                for vuln in pkg.get("vulnerabilities", []):
                    rows.append(
                        {
                            "agent": agent["name"],
                            "server": srv["name"],
                            "package": pkg["name"],
                            "version": pkg.get("version", "?"),
                            "ecosystem": pkg.get("ecosystem", "unknown"),
                            "license": pkg.get("license", ""),
                            "vuln_id": vuln.get("id", ""),
                            "severity": vuln.get("severity", "unknown"),
                            "cvss": vuln.get("cvss_score") or 0,
                            "epss": vuln.get("epss_score") or 0,
                            "is_kev": vuln.get("is_kev", False),
                            "fixed_version": vuln.get("fixed_version", ""),
                        }
                    )
                if not pkg.get("vulnerabilities"):
                    rows.append(
                        {
                            "agent": agent["name"],
                            "server": srv["name"],
                            "package": pkg["name"],
                            "version": pkg.get("version", "?"),
                            "ecosystem": pkg.get("ecosystem", "unknown"),
                            "license": pkg.get("license", ""),
                            "vuln_id": "",
                            "severity": "",
                            "cvss": 0,
                            "epss": 0,
                            "is_kev": False,
                            "fixed_version": "",
                        }
                    )
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def extract_blast_radius(report: dict) -> pd.DataFrame:
    """Extract blast radius findings into a flat DataFrame."""
    rows = []
    for br in report.get("blast_radius", []):
        rows.append(
            {
                "vuln_id": br.get("vulnerability_id", ""),
                "severity": br.get("severity", "unknown"),
                "cvss": br.get("cvss_score") or 0,
                "epss": br.get("epss_score") or 0,
                "is_kev": br.get("is_kev", False),
                "risk_score": br.get("risk_score", 0),
                "package": br.get("package", ""),
                "ecosystem": br.get("ecosystem", ""),
                "affected_agents": ", ".join(br.get("affected_agents", [])),
                "affected_servers": ", ".join(br.get("affected_servers", [])),
                "exposed_creds": ", ".join(br.get("exposed_credentials", [])),
                "exposed_tools": ", ".join(br.get("exposed_tools", [])),
                "fixed_version": br.get("fixed_version", ""),
                "owasp_tags": ", ".join(br.get("owasp_tags", [])),
                "atlas_tags": ", ".join(br.get("atlas_tags", [])),
            }
        )
    return pd.DataFrame(rows) if rows else pd.DataFrame()
