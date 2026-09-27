"""Bundled demo data must not ship advisories their upstream has withdrawn.

`scan --demo --offline` reported CVE-2022-23529 (jsonwebtoken) as HIGH although
GHSA-27h2-hvpr-p74q was withdrawn on 2023-01-27 and OSV no longer serves it.
"""

from __future__ import annotations

from agent_bom.demo_advisories import DEMO_ADVISORIES
from agent_bom.demo_estate.showcase_graph import SHOWCASE_PACKAGES

# Withdrawn upstream (OSV `withdrawn` / GitHub advisory `withdrawn_at`).
WITHDRAWN_ADVISORY_IDS = frozenset({"CVE-2022-23529", "GHSA-27h2-hvpr-p74q"})


def test_demo_advisories_exclude_withdrawn_ids() -> None:
    assert not {advisory.vuln_id for advisory in DEMO_ADVISORIES} & WITHDRAWN_ADVISORY_IDS


def test_showcase_graph_excludes_withdrawn_ids() -> None:
    assert not {row[1] for row in SHOWCASE_PACKAGES.values()} & WITHDRAWN_ADVISORY_IDS


def test_demo_jsonwebtoken_uses_the_live_replacement_advisory() -> None:
    """jsonwebtoken <9.0.0 keeps a real HIGH: CVE-2022-23539 (GHSA-8cf7-32gw-wr33, CVSS 3.1 8.1)."""
    rows = [a for a in DEMO_ADVISORIES if a.package == "jsonwebtoken"]
    assert [(a.vuln_id, a.severity, a.cvss_score, a.fixed) for a in rows] == [("CVE-2022-23539", "high", 8.1, "9.0.0")]
    assert SHOWCASE_PACKAGES["jsonwebtoken@8.5.1"][1:] == ("CVE-2022-23539", "high", 8.1)
