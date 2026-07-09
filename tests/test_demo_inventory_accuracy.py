"""Demo inventory accuracy guardrail.

The README, GIF, and product screenshots are captured against
``DEMO_INVENTORY``. If a future change swaps in a package@version that the
local vuln DB cannot match to a real advisory, the published screenshots
become misleading — finding labels that map to nothing real.

This test pins the contract: every package in the demo inventory must
either resolve to at least one expected advisory-backed range, or be
explicitly listed in the no-known-vulns allowlist below. The allowlist
exists so the demo can include intentionally-clean packages alongside the
vulnerable ones (e.g. to show that not everything is on fire).
"""

from __future__ import annotations

import pytest

from agent_bom.db.lookup import lookup_package
from agent_bom.db.schema import init_db
from agent_bom.demo import DEMO_INVENTORY
from agent_bom.demo_advisories import seed_demo_advisories

# Packages that the demo intentionally ships at a known-clean version. Add
# entries here only after manually confirming that the version genuinely
# has no published advisories — never to silence a regression.
#
# Confirmed clean via `agent-bom check <name>@<version> --ecosystem <eco>`:
# - semver@7.5.2: paired with vulnerable axios@1.4.0 in the demo to show
#   that not every dependency is on fire.
#
# Intentional malicious/typosquat sample (flagged by the typosquat heuristic,
# not by a CVE advisory — so it correctly resolves to no advisory row):
# - reqeusts@2.99.0: typosquat of "requests"; demonstrates the
#   malicious-package differentiator. See test_typosquat_package_is_flagged.
NO_KNOWN_VULNS_ALLOWLIST: set[tuple[str, str, str]] = {
    ("npm", "semver", "7.5.2"),
    ("pypi", "reqeusts", "2.99.0"),
}


def _all_demo_packages() -> list[tuple[str, str, str]]:
    pkgs: list[tuple[str, str, str]] = []
    for agent in DEMO_INVENTORY.get("agents", []):
        for server in agent.get("mcp_servers", []):
            for pkg in server.get("packages", []):
                pkgs.append((pkg["ecosystem"], pkg["name"], pkg["version"]))
    return pkgs


@pytest.fixture(scope="module")
def vuln_db(tmp_path_factory):
    """Seed only the demo contract rows so the guard is independent of ~/.agent-bom."""
    db_path = tmp_path_factory.mktemp("demo-vuln-db") / "vulns.db"
    conn = init_db(db_path)
    seed_demo_advisories(conn)

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


def test_demo_inventory_has_at_least_two_criticals() -> None:
    """The estate ships a couple of genuine CRITICALs (PyYAML + LangChain RCE)."""
    from agent_bom.demo_advisories import DEMO_ADVISORIES

    demo_pkgs = {(eco, name) for eco, name, _ in _all_demo_packages()}
    criticals = {
        adv.vuln_id
        for adv in DEMO_ADVISORIES
        if adv.severity == "critical" and (adv.ecosystem, adv.package) in demo_pkgs
    }
    assert len(criticals) >= 2, f"expected >=2 critical advisories on demo packages, got {criticals}"


def test_typosquat_package_is_flagged() -> None:
    """The intentional typosquat sample must trip the malicious-package heuristic."""
    from agent_bom.malicious import check_typosquat

    assert ("pypi", "reqeusts", "2.99.0") in _all_demo_packages(), "typosquat sample missing from demo inventory"
    assert check_typosquat("reqeusts", "pypi") == "requests"
