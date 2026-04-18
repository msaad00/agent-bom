"""Demo inventory accuracy guardrail.

The README, GIF, and product screenshots are captured against
``DEMO_INVENTORY``. If a future change swaps in a package@version that the
local vuln DB cannot match to a real advisory, the published screenshots
become misleading — finding labels that map to nothing real.

This test pins the contract: every package in the demo inventory must
either resolve to at least one real entry in the bundled offline DB, or be
explicitly listed in the no-known-vulns allowlist below. The allowlist
exists so the demo can include intentionally-clean packages alongside the
vulnerable ones (e.g. to show that not everything is on fire).
"""

from __future__ import annotations

import pytest

from agent_bom.db.lookup import lookup_package
from agent_bom.db.schema import open_existing_db_readonly
from agent_bom.demo import DEMO_INVENTORY

# Packages that the demo intentionally ships at a known-clean version. Add
# entries here only after manually confirming that the version genuinely
# has no published advisories — never to silence a regression.
#
# Confirmed clean via `agent-bom check <name>@<version> --ecosystem <eco>`:
# - semver@7.5.2: paired with vulnerable axios@1.4.0 in the demo to show
#   that not every dependency is on fire.
NO_KNOWN_VULNS_ALLOWLIST: set[tuple[str, str, str]] = {
    ("npm", "semver", "7.5.2"),
}


def _all_demo_packages() -> list[tuple[str, str, str]]:
    pkgs: list[tuple[str, str, str]] = []
    for agent in DEMO_INVENTORY.get("agents", []):
        for server in agent.get("mcp_servers", []):
            for pkg in server.get("packages", []):
                pkgs.append((pkg["ecosystem"], pkg["name"], pkg["version"]))
    return pkgs


@pytest.fixture(scope="module")
def vuln_db():
    try:
        conn = open_existing_db_readonly()
    except FileNotFoundError:
        pytest.skip("Local vuln DB not present in this environment")
    yield conn
    conn.close()


def test_demo_packages_have_real_advisories(vuln_db) -> None:
    """Every vulnerable demo package must resolve to a real advisory.

    Prevents the README mesh / blast-radius screenshots from claiming CVEs
    against package versions that have no published vulnerability — the
    exact 'we showed something fake' regression class.
    """
    missing: list[tuple[str, str, str]] = []
    for eco, name, version in _all_demo_packages():
        if (eco, name, version) in NO_KNOWN_VULNS_ALLOWLIST:
            continue
        vulns = lookup_package(vuln_db, eco, name, version)
        if not vulns:
            missing.append((eco, name, version))
    assert not missing, (
        "Demo inventory lists packages with NO real advisories — published "
        "screenshots would claim CVEs that do not exist. Either pin a "
        "genuinely-vulnerable version or add to NO_KNOWN_VULNS_ALLOWLIST: "
        f"{missing}"
    )


def test_demo_inventory_has_critical_or_high_for_screenshot_paths(vuln_db) -> None:
    """The hero blast-radius story needs at least one CRITICAL or HIGH.

    Without any high-severity finding the README hero loses its punch and
    operators cannot tell the screenshot is real. This test fails closed if
    a future demo refactor accidentally drops to medium+only inventory.
    """
    severities: list[str] = []
    for eco, name, version in _all_demo_packages():
        for v in lookup_package(vuln_db, eco, name, version):
            severity = (v.severity or "").upper()
            if severity:
                severities.append(severity)
    high_or_above = {s for s in severities if s in {"HIGH", "CRITICAL"}}
    assert high_or_above, (
        "Demo inventory yields no HIGH or CRITICAL findings — the README blast-radius story needs at least one to remain credible."
    )
