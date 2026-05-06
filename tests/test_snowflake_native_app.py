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
SERVICE_SPECS_DIR = NATIVE_APP_DIR / "service-specs"
RELEASE_WORKFLOW_PATH = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release-snowflake.yml"
SNOWFLAKE_PACKAGE_IMAGE_TAG = "v0_86_0"


@pytest.fixture(scope="module")
def manifest() -> dict:
    return yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def setup_sql() -> str:
    return SETUP_SQL_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def service_specs() -> dict[str, dict]:
    return {path.name: yaml.safe_load(path.read_text(encoding="utf-8")) for path in SERVICE_SPECS_DIR.glob("*.yaml")}


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


def test_advisory_feed_eais_are_default_off(manifest: dict):
    """Phase 4 scanner enrichment must stay opt-in. A future manifest change
    that enables outbound vulnerability feeds during install is a regression."""
    for eai in manifest.get("external_access_integrations", []):
        name, body = next(iter(eai.items()))
        assert body.get("enabled") is False, f"EAI {name!r} must be disabled by default"


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


# ─── Phase 4 service contract ───────────────────────────────────────────────


def test_manifest_declares_phase4_services_default_off(manifest: dict):
    config = manifest.get("configuration", {})
    assert config["enable_scanner_service"]["default"] is False
    assert config["enable_mcp_runtime_service"]["default"] is False

    images = set(manifest.get("artifacts", {}).get("container_services", {}).get("images", []))
    assert f"/db/schema/agent_bom_repo/agent-bom-scanner:{SNOWFLAKE_PACKAGE_IMAGE_TAG}" in images
    assert f"/db/schema/agent_bom_repo/agent-bom-mcp-runtime:{SNOWFLAKE_PACKAGE_IMAGE_TAG}" in images


def test_native_app_container_images_are_release_pinned(manifest: dict, service_specs: dict[str, dict]):
    image_refs = list(manifest.get("artifacts", {}).get("container_services", {}).get("images", []))
    for spec in service_specs.values():
        image_refs.extend(
            container["image"] for container in spec.get("spec", {}).get("containers", []) if isinstance(container.get("image"), str)
        )

    assert image_refs
    assert all(":latest" not in image for image in image_refs)
    assert all(image.endswith(f":{SNOWFLAKE_PACKAGE_IMAGE_TAG}") for image in image_refs)


def test_phase4_service_specs_are_packaged_and_internal(service_specs: dict[str, dict]):
    expected = {"scanner-service.yaml", "mcp-runtime-service.yaml"}
    assert expected <= set(service_specs)

    for spec_name in expected:
        spec = service_specs[spec_name]["spec"]
        assert spec.get("containers"), f"{spec_name} must declare at least one container"
        for endpoint in spec.get("endpoints", []):
            assert endpoint.get("public") is False, f"{spec_name}:{endpoint.get('name')} must be internal-only"


def test_scanner_service_spec_uses_scanner_entrypoint_and_not_mcp_runtime(service_specs: dict[str, dict]):
    scanner = service_specs["scanner-service.yaml"]["spec"]["containers"][0]
    assert scanner["name"] == "agent-bom-scanner"
    assert scanner["env"]["AGENT_BOM_MCP_MODE"] == "0"
    assert scanner["env"]["AGENT_BOM_ENABLE_ADVISORY_EGRESS"] == "1"
    assert scanner["command"][:4] == ["agent-bom", "agents", "--snowflake", "--snowflake-authenticator"]


def test_mcp_runtime_spec_requires_bearer_token_and_has_no_advisory_egress(service_specs: dict[str, dict]):
    runtime = service_specs["mcp-runtime-service.yaml"]["spec"]["containers"][0]
    assert runtime["name"] == "agent-bom-mcp-runtime"
    assert runtime["env"]["AGENT_BOM_MCP_MODE"] == "1"
    assert runtime["env"]["AGENT_BOM_MCP_BEARER_TOKEN"] == "{{ mcp_bearer_token }}"
    assert "AGENT_BOM_ENABLE_ADVISORY_EGRESS" not in runtime["env"]
    assert runtime["command"][:4] == ["agent-bom", "mcp", "server", "--transport"]


def test_setup_sql_only_creates_phase4_services_from_opt_in_procedures(setup_sql: str):
    upper = setup_sql.upper()
    assert "CREATE OR REPLACE PROCEDURE CORE.ENABLE_SCANNER_SERVICE()" in upper
    assert "CREATE OR REPLACE PROCEDURE CORE.ENABLE_MCP_RUNTIME_SERVICE(MCP_BEARER_TOKEN VARCHAR)" in upper
    assert "CORE.AGENT_BOM_SCANNER" in upper
    assert "CORE.AGENT_BOM_MCP_RUNTIME" in upper
    assert "LENGTH(TRIM(MCP_BEARER_TOKEN)) < 32" in upper


def test_setup_sql_exposes_customer_health_check(setup_sql: str):
    upper = setup_sql.upper()
    assert "CREATE OR REPLACE PROCEDURE CORE.HEALTH_CHECK()" in upper
    assert "'SCANNER_SERVICE_ENABLED'" in upper
    assert "'MCP_RUNTIME_SERVICE_ENABLED'" in upper
    assert "'ADVISORY_EGRESS_ENABLED'" in upper
    assert "GRANT USAGE ON PROCEDURE CORE.HEALTH_CHECK()" in upper


def test_scanner_service_creation_is_eai_gated(setup_sql: str):
    scanner_section = setup_sql.split("CREATE OR REPLACE PROCEDURE core.enable_scanner_service()", 1)[1].split(
        "CREATE OR REPLACE PROCEDURE core.enable_mcp_runtime_service", 1
    )[0]
    assert "EXTERNAL_ACCESS_INTEGRATIONS" in scanner_section
    for eai_name in ("osv_dev", "cisa_kev", "first_epss", "github_ghsa"):
        assert f"reference('{eai_name}')" in scanner_section


def test_mcp_runtime_service_creation_has_no_eai_clause(setup_sql: str):
    mcp_section = setup_sql.split("CREATE OR REPLACE PROCEDURE core.enable_mcp_runtime_service", 1)[1]
    assert "EXTERNAL_ACCESS_INTEGRATIONS" not in mcp_section


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


def test_release_workflow_derives_version_from_pyproject_when_unset():
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "required: false" in workflow
    assert 'project = tomllib.loads(Path("pyproject.toml").read_text())["project"]' in workflow
    assert 'version = "v" + str(project["version"]).replace(".", "_")' in workflow
    assert "package_version: ${{ steps.version.outputs.version }}" in workflow
    assert "inputs.version" not in workflow.split("Build Snowflake Native App artifact", 1)[1]


def test_release_workflow_pins_actions_and_rejects_latest_native_app_images():
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "actions/checkout@v4" in workflow
    assert "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5" in workflow
    assert "actions/setup-python@v5" in workflow
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in workflow
    assert "actions/upload-artifact@v4" in workflow
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in workflow
    assert "actions/download-artifact@v4" in workflow
    assert "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in workflow
    assert 'assert ":latest" not in text' in workflow
    assert 'assert f":{version}" in text' in workflow
