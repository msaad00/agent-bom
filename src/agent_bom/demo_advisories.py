"""Curated advisory evidence for the bundled demo inventory.

These rows are intentionally narrow and are used only for
``agent-bom agents --demo``. They keep the first-run demo deterministic when a
developer or CI machine has no local vulnerability DB, while still exercising
the same SQLite lookup and version-range parser used by real scans.
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
    source: str = "demo-advisory"


DEMO_ADVISORIES: tuple[DemoAdvisory, ...] = (
    DemoAdvisory("npm", "express", "0", "4.19.2", "GHSA-rv95-896h-c2vc", "medium", 5.3, "express open redirect advisory"),
    DemoAdvisory("npm", "node-fetch", "0", "3.1.1", "GHSA-r683-j2x4-v87g", "high", 8.8, "node-fetch exposure advisory"),
    DemoAdvisory("npm", "jsonwebtoken", "0", "9.0.0", "GHSA-8cf7-32gw-wr33", "high", 7.6, "jsonwebtoken signature validation advisory"),
    DemoAdvisory("npm", "axios", "0", "1.6.0", "GHSA-jr5f-v2jv-69x6", "high", 7.5, "axios CSRF credential disclosure advisory"),
    DemoAdvisory("pypi", "flask", "0", "2.3.2", "GHSA-m2qf-hxjv-5gpq", "high", 7.5, "Flask cookie parsing advisory"),
    DemoAdvisory("pypi", "werkzeug", "0", "2.2.3", "GHSA-q34m-jh98-gwm2", "high", 7.5, "Werkzeug multipart parsing advisory"),
    DemoAdvisory("pypi", "requests", "0", "2.32.0", "GHSA-j8r2-6x86-q33q", "medium", 5.3, "Requests credential leakage advisory"),
    DemoAdvisory("pypi", "cryptography", "0", "41.0.3", "PYSEC-2023-254", "high", 7.5, "cryptography OpenSSL advisory"),
    DemoAdvisory("pypi", "pillow", "0", "9.0.1", "GHSA-8vj2-vxx3-667w", "critical", 9.8, "Pillow buffer overflow advisory"),
    DemoAdvisory("pypi", "jinja2", "0", "3.1.5", "GHSA-gmj6-6f8f-6699", "medium", 8.8, "Jinja2 sandbox escape advisory"),
    DemoAdvisory("pypi", "certifi", "0", "2023.7.22", "GHSA-xqr8-7jwr-rhp7", "high", 7.5, "certifi trust store advisory"),
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
                id, summary, severity, cvss_score, fixed_version, source
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                advisory.vuln_id,
                advisory.summary,
                advisory.severity,
                advisory.cvss_score,
                advisory.fixed,
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
    conn.commit()
