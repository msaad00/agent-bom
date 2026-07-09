"""Curated advisory evidence for the bundled demo inventory.

These rows are intentionally narrow and are used only for
``agent-bom agents --demo`` and the hosted demo estate. They keep the
first-run demo deterministic when a developer or CI machine has no local
vulnerability DB, while still exercising the same SQLite lookup and
version-range parser used by real scans.

Every row uses a genuine, published advisory ID (CVE / GHSA / PYSEC) with a
real CWE and CVSS so the findings list, blast radius, and reachability
screenshots map to something an operator can look up. A subset is on the
CISA Known Exploited Vulnerabilities (KEV) catalog so the KEV differentiator
lights up in the demo.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class DemoAdvisory:
    ecosystem: str
    package: str
    introduced: str
    fixed: str
    vuln_id: str
    severity: str
    cvss_score: float
    summary: str
    cwe: str = ""
    is_kev: bool = False
    source: str = "demo-advisory"


DEMO_ADVISORIES: tuple[DemoAdvisory, ...] = (
    # ── npm ───────────────────────────────────────────────────────────────
    DemoAdvisory(
        "npm", "express", "0", "4.19.2", "CVE-2024-29041", "medium", 6.1,
        "Express open redirect via malformed URLs passed to res.location/redirect",
        cwe="CWE-601",
    ),
    DemoAdvisory(
        "npm", "jsonwebtoken", "0", "9.0.0", "CVE-2022-23529", "high", 7.6,
        "jsonwebtoken insecure key handling allows signature verification bypass",
        cwe="CWE-347",
    ),
    DemoAdvisory(
        "npm", "node-fetch", "0", "3.1.1", "CVE-2022-0235", "high", 6.1,
        "node-fetch leaks Cookie/Authorization headers on cross-origin redirect",
        cwe="CWE-200",
    ),
    DemoAdvisory(
        "npm", "axios", "0", "1.6.0", "CVE-2023-45857", "high", 6.5,
        "axios SSRF and credential leak via follow-redirects proxy handling",
        cwe="CWE-918",
    ),
    DemoAdvisory(
        "npm", "ws", "0", "8.17.1", "CVE-2024-37890", "high", 7.5,
        "ws denial of service when handling a request with many HTTP headers",
        cwe="CWE-400",
    ),
    DemoAdvisory(
        "npm", "lodash", "0", "4.17.21", "CVE-2021-23337", "high", 7.2,
        "lodash command injection via template() with tainted options",
        cwe="CWE-77",
    ),
    # ── pypi ──────────────────────────────────────────────────────────────
    DemoAdvisory(
        "pypi", "pyyaml", "0", "5.4", "CVE-2020-14343", "critical", 9.8,
        "PyYAML arbitrary code execution via yaml.full_load on untrusted input",
        cwe="CWE-20",
    ),
    DemoAdvisory(
        "pypi", "langchain", "0", "0.0.247", "CVE-2023-36258", "critical", 9.8,
        "LangChain arbitrary code execution via PALChain prompt-to-Python evaluation",
        cwe="CWE-94",
    ),
    DemoAdvisory(
        "pypi", "pillow", "0", "10.0.1", "CVE-2023-4863", "high", 8.8,
        "Pillow bundled libwebp heap buffer overflow — exploited in the wild (CISA KEV)",
        cwe="CWE-787",
        is_kev=True,
    ),
    DemoAdvisory(
        "pypi", "requests", "0", "2.31.0", "CVE-2023-32681", "medium", 6.1,
        "Requests leaks Proxy-Authorization header to destination on redirect",
        cwe="CWE-200",
    ),
    DemoAdvisory(
        "pypi", "cryptography", "0", "42.0.0", "CVE-2023-50782", "high", 7.5,
        "pyca/cryptography Bleichenbacher timing oracle in RSA PKCS#1 v1.5 decryption",
        cwe="CWE-208",
    ),
    DemoAdvisory(
        "pypi", "flask", "0", "2.3.2", "CVE-2023-30861", "high", 7.5,
        "Flask session cookie disclosed to other clients via a caching proxy",
        cwe="CWE-539",
    ),
    DemoAdvisory(
        "pypi", "werkzeug", "0", "2.2.3", "CVE-2023-25577", "high", 7.5,
        "Werkzeug multipart form-data parsing denial of service",
        cwe="CWE-400",
    ),
    DemoAdvisory(
        "pypi", "jinja2", "0", "3.1.3", "CVE-2024-22195", "medium", 5.4,
        "Jinja2 cross-site scripting via the xmlattr filter with attacker-controlled keys",
        cwe="CWE-79",
    ),
    DemoAdvisory(
        "pypi", "certifi", "0", "2023.7.22", "CVE-2023-37920", "high", 7.5,
        "certifi trusted a compromised e-Tugra root certificate authority",
        cwe="CWE-345",
    ),
)

# The demo deliberately includes semver@7.5.2 as a clean package. This sentinel
# gives the deterministic demo DB package-level coverage without making that
# exact version vulnerable.
DEMO_CLEAN_COVERAGE_SENTINELS: tuple[DemoAdvisory, ...] = (
    DemoAdvisory(
        "npm",
        "semver",
        "0",
        "7.5.0",
        "DEMO-CLEAN-semver",
        "unknown",
        0.0,
        "Non-matching coverage sentinel for clean demo package semver@7.5.2",
        source="demo-clean-sentinel",
    ),
)


def seed_demo_advisories(conn: sqlite3.Connection) -> None:
    """Insert deterministic demo advisory rows into an initialized DB."""

    for advisory in (*DEMO_ADVISORIES, *DEMO_CLEAN_COVERAGE_SENTINELS):
        conn.execute(
            """
            INSERT OR REPLACE INTO vulns(
                id, summary, severity, cvss_score, fixed_version, cwe_ids, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                advisory.vuln_id,
                advisory.summary,
                advisory.severity,
                advisory.cvss_score,
                advisory.fixed,
                advisory.cwe,
                advisory.source,
            ),
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO affected(
                vuln_id, ecosystem, package_name, introduced, fixed, last_affected
            ) VALUES (?, ?, ?, ?, ?, '')
            """,
            (
                advisory.vuln_id,
                advisory.ecosystem,
                advisory.package,
                advisory.introduced,
                advisory.fixed,
            ),
        )
        if advisory.is_kev:
            conn.execute(
                """
                INSERT OR REPLACE INTO kev_entries(
                    cve_id, date_added, due_date, product, vendor_project
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    advisory.vuln_id,
                    "2023-09-27",
                    "2023-10-04",
                    advisory.package,
                    advisory.ecosystem,
                ),
            )
    conn.commit()
