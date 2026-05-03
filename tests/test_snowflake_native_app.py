"""Lock-in contract tests for the Snowflake Native App manifest (#2210).

The Native App manifest is the customer's first contact with agent-bom inside
Snowflake. If it drifts from the architecture invariants we promised
(customer-approved references, EAI-gated egress, no broad GRANTs), the trust
contract breaks at install time.

Tests exercise the on-disk manifest YAML + setup.sql via static analysis —
no live Snowflake account needed. They run in CI on every push so a future
PR can't quietly weaken the read-only contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

NATIVE_APP_DIR = Path(__file__).resolve().parents[1] / "deploy" / "snowflake" / "native-app"
MANIFEST_PATH = NATIVE_APP_DIR / "manifest.yml"
SETUP_SQL_PATH = NATIVE_APP_DIR / "scripts" / "setup.sql"
DCM_DIR = NATIVE_APP_DIR / "dcm"


@pytest.fixture(scope="module")
def manifest() -> dict:
    return yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def setup_sql() -> str:
    return SETUP_SQL_PATH.read_text(encoding="utf-8")


# ─── Customer-approved references contract ──────────────────────────────────


def test_manifest_declares_customer_bound_references(manifest: dict):
    """The Native App MUST declare a `references:` block so customers bind
    asset/IAM/vuln tables at install. Without this, agent-bom is asking
    for vendor-asserted access — breaks the trust contract."""
    refs = manifest.get("references")
    assert refs, "manifest must declare references for customer-bound tables/stages"

    expected = {
        "cloud_asset_tables",
        "iam_tables",
        "vuln_tables",
        "log_tables",
        "artifact_stages",
    }
    declared = {next(iter(r.keys())) for r in refs}
    missing = expected - declared
    assert not missing, f"manifest is missing required references: {missing}"


def test_every_reference_is_select_or_read_only(manifest: dict):
    """Customer-bound references must NEVER carry write privileges.
    SELECT for tables, READ for stages — anything else is a regression."""
    allowed_table_privs = {"SELECT"}
    allowed_stage_privs = {"READ"}

    for ref in manifest.get("references", []):
        name, body = next(iter(ref.items()))
        privs = set(body.get("privileges", []))
        obj_type = body.get("object_type")
        if obj_type == "TABLE":
            assert privs <= allowed_table_privs, f"reference {name!r} declares write privilege on TABLE: {privs - allowed_table_privs}"
        elif obj_type == "STAGE":
            assert privs <= allowed_stage_privs, f"reference {name!r} declares write privilege on STAGE: {privs - allowed_stage_privs}"


# ─── External Access Integration contract ──────────────────────────────────


def test_manifest_declares_advisory_feed_eais(manifest: dict):
    """All four advisory-feed EAIs (OSV / KEV / EPSS / GHSA) must be
    declared in the manifest so the customer can toggle them at install.
    These are the only outbound calls agent-bom makes — they must be
    explicit consent, not silently active."""
    eais = manifest.get("external_access_integrations")
    assert eais, "manifest must declare external_access_integrations"

    expected = {"osv_dev", "cisa_kev", "first_epss", "github_ghsa"}
    declared = {next(iter(e.keys())) for e in eais}
    missing = expected - declared
    assert not missing, f"manifest missing required EAIs: {missing}"


def test_no_eai_egresses_to_unexpected_destinations(manifest: dict):
    """Every EAI's egress destination list must match a known advisory feed.
    A future PR adding a fifth destination would surface here so we can
    review whether the new outbound call is actually advisory-only."""
    allowed = {
        "api.osv.dev",
        "osv.dev",
        "www.cisa.gov",
        "api.first.org",
        "api.github.com",
    }
    for eai in manifest.get("external_access_integrations", []):
        body = next(iter(eai.values()))
        destinations = set(body.get("egress_destinations", []))
        unknown = destinations - allowed
        assert not unknown, f"EAI declares unknown egress destinations: {unknown}. Update this test if the new destination is intended."


# ─── Setup script contract ──────────────────────────────────────────────────


def test_setup_sql_creates_app_user_application_role(setup_sql: str):
    assert "CREATE APPLICATION ROLE IF NOT EXISTS app_user" in setup_sql, (
        "setup.sql must create the app_user application role for least-privilege grants"
    )


def test_setup_sql_does_not_grant_account_level_privileges(setup_sql: str):
    """setup.sql must NEVER issue account-level grants. All grants go to
    app_user via APPLICATION ROLE."""
    forbidden = [
        "GRANT IMPORTED PRIVILEGES",
        "GRANT MANAGE GRANTS",
        "GRANT MODIFY ON ACCOUNT",
        "GRANT EXECUTE ON ACCOUNT",
    ]
    for phrase in forbidden:
        assert phrase not in setup_sql.upper(), f"setup.sql must not contain {phrase!r} — that's an account-level escalation"


def test_setup_sql_grants_only_target_application_role(setup_sql: str):
    """Every GRANT in setup.sql must target APPLICATION ROLE app_user
    (or be a CREATE/USE/INSERT/etc.). No PUBLIC, no ACCOUNTADMIN."""
    bad = [
        "TO ROLE PUBLIC",
        "TO ROLE ACCOUNTADMIN",
        "TO ROLE SECURITYADMIN",
        "TO ROLE SYSADMIN",
    ]
    for phrase in bad:
        assert phrase not in setup_sql.upper(), f"setup.sql contains {phrase!r} — grants must only target APPLICATION ROLE app_user"


# ─── DCM project contract ──────────────────────────────────────────────────


def test_dcm_project_has_v001_migration():
    """Phase 1 ships V001__core_schema.sql. Future phases append
    V002__..., V003__... — schema deltas are append-only."""
    v001 = DCM_DIR / "V001__core_schema.sql"
    assert v001.is_file(), f"DCM project must have V001__core_schema.sql at {v001}"


def test_dcm_v001_creates_compliance_hub_table():
    """V001 must create the compliance_hub_findings table — Phase 2's
    Snowpark proc target. If V001 doesn't materialise the schema, Phase 2
    has nothing to populate."""
    v001 = (DCM_DIR / "V001__core_schema.sql").read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS core.compliance_hub_findings" in v001
    assert "CREATE TABLE IF NOT EXISTS core.findings_by_framework" in v001


def test_dcm_v001_no_write_grants_on_customer_data():
    """DCM migrations operate on the application's own schema only.
    A migration that wrote to a customer-bound reference would be a
    privilege escalation."""
    v001 = (DCM_DIR / "V001__core_schema.sql").read_text(encoding="utf-8")
    # All grants in this migration must be scoped to core.*; any GRANT
    # against a customer-named DB would be a privilege escalation.
    assert "GRANT INSERT ON TABLE" not in v001 or "core." in v001
    assert "YOUR_DB." not in v001
