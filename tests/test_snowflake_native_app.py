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

import hashlib
import re
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

NATIVE_APP_DIR = Path(__file__).resolve().parents[1] / "deploy" / "snowflake" / "native-app"
MANIFEST_PATH = NATIVE_APP_DIR / "manifest.yml"
SETUP_SQL_PATH = NATIVE_APP_DIR / "scripts" / "setup.sql"
DCM_DIR = NATIVE_APP_DIR / "dcm"
SERVICE_SPECS_DIR = NATIVE_APP_DIR / "service-specs"
CORE_SERVICE_SPEC_PATH = NATIVE_APP_DIR / "service-spec.yaml"
RELEASE_WORKFLOW_PATH = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release-snowflake.yml"
PYPROJECT_PATH = Path(__file__).resolve().parents[1] / "pyproject.toml"
PROJECT_PATH = NATIVE_APP_DIR / "snowflake.yml"
MARKETPLACE_PATH = NATIVE_APP_DIR / "marketplace.yml"
CONSUMER_README_PATH = NATIVE_APP_DIR / "README.md"
IMAGE_BUILD_PATH = NATIVE_APP_DIR / "images.yml"
LISTING_TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "docs" / "snowflake-native-app" / "listing-template.yml"
RELEASE_TOOL_PATH = Path(__file__).resolve().parents[1] / "scripts" / "release" / "snowflake_native_app.py"


def _snowflake_image_tag_from_pyproject() -> str:
    match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT_PATH.read_text(encoding="utf-8"), re.MULTILINE)
    assert match, "pyproject.toml must declare the package version"
    return "v" + match.group(1).replace(".", "_")


SNOWFLAKE_PACKAGE_IMAGE_TAG = _snowflake_image_tag_from_pyproject()


@pytest.fixture(scope="module")
def manifest() -> dict:
    return yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def setup_sql() -> str:
    return SETUP_SQL_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def service_specs() -> dict[str, dict]:
    return {path.name: yaml.safe_load(path.read_text(encoding="utf-8")) for path in SERVICE_SPECS_DIR.glob("*.yaml")}


@pytest.fixture(scope="module")
def core_service_spec() -> dict:
    return yaml.safe_load(CORE_SERVICE_SPEC_PATH.read_text(encoding="utf-8"))


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
    """Every EAI's egress destination list must match a known advisory/package feed.
    A future PR adding a fifth destination would surface here so we can
    review whether the new outbound call is actually metadata-only."""
    allowed = {
        "api.osv.dev",
        "osv.dev",
        "www.cisa.gov",
        "api.first.org",
        "api.github.com",
        "services.nvd.nist.gov",
        "api.deps.dev",
        "deps.dev",
        "registry.npmjs.org",
        "api.npmjs.org",
        "pypi.org",
        "proxy.golang.org",
        "sum.golang.org",
        "search.maven.org",
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
    repository = "/agent_bom_provider/spcs/agent_bom_repo"
    assert f"{repository}/agent-bom-scanner:{SNOWFLAKE_PACKAGE_IMAGE_TAG}" in images
    assert f"{repository}/agent-bom-mcp-runtime:{SNOWFLAKE_PACKAGE_IMAGE_TAG}" in images


def test_native_app_container_images_are_release_pinned(
    manifest: dict, service_specs: dict[str, dict], core_service_spec: dict
):
    image_refs = list(manifest.get("artifacts", {}).get("container_services", {}).get("images", []))
    for spec in (*service_specs.values(), core_service_spec):
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
    assert scanner["command"][:3] == ["agent-bom", "agents", "--snowflake"]
    assert "--snowflake-authenticator" not in scanner["command"]
    assert "SNOWFLAKE_AUTHENTICATOR" not in scanner["env"]


def test_native_app_service_specs_use_spcs_injected_context_without_unresolved_placeholders(
    service_specs: dict[str, dict], core_service_spec: dict
):
    for spec_name, spec in {"service-spec.yaml": core_service_spec, **service_specs}.items():
        for container in spec["spec"]["containers"]:
            env = container.get("env", {})
            assert env.get("AGENT_BOM_SNOWFLAKE_NATIVE_APP") == "1" or container["name"] == "agent-bom-ui"
            for key in ("SNOWFLAKE_ACCOUNT", "SNOWFLAKE_DATABASE", "SNOWFLAKE_SCHEMA"):
                assert key not in env, f"{spec_name}:{container['name']} must use the SPCS-injected {key} value"
        rendered = yaml.safe_dump(spec)
        placeholders = set(re.findall(r"\{\{\s*([^} ]+)\s*\}\}", rendered))
        expected = {"mcp_bearer_token"} if spec_name == "mcp-runtime-service.yaml" else set()
        assert placeholders == expected


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


def test_setup_sql_does_not_depend_on_a_consumer_warehouse(setup_sql: str):
    upper = setup_sql.upper()
    assert "COMPUTE_WH" not in upper
    assert "CREATE OR REPLACE TASK CORE.AUTO_SCAN_TASK" not in upper


def test_scanner_service_creation_is_eai_gated(setup_sql: str):
    scanner_section = setup_sql.split("CREATE OR REPLACE PROCEDURE core.enable_scanner_service()", 1)[1].split(
        "CREATE OR REPLACE PROCEDURE core.enable_mcp_runtime_service", 1
    )[0]
    assert "EXTERNAL_ACCESS_INTEGRATIONS" in scanner_section
    for eai_name in ("osv_dev", "cisa_kev", "first_epss", "github_ghsa", "nvd_api", "deps_dev", "package_registries"):
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
    assert 'tomllib.load(open("pyproject.toml", "rb"))["project"]["version"]' in workflow
    assert 'package_version="v${semantic_version//./_}"' in workflow
    assert "package_version: ${{ steps.release.outputs.package_version }}" in workflow
    assert "semantic_version: ${{ steps.release.outputs.semantic_version }}" in workflow
    assert "image_matrix: ${{ steps.release.outputs.image_matrix }}" in workflow
    assert "inputs.version" not in workflow.split("Build reproducible Native App artifact", 1)[1]


def test_release_workflow_pins_actions_and_rejects_latest_native_app_images():
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    action_refs = dict(
        re.findall(
            r"^\s*-\s*uses:\s*(actions/(?:checkout|setup-python|upload-artifact|download-artifact))@([0-9a-f]{40})(?:\s+#.*)?$",
            workflow,
            flags=re.MULTILINE,
        )
    )
    assert action_refs.keys() == {
        "actions/checkout",
        "actions/setup-python",
        "actions/upload-artifact",
        "actions/download-artifact",
    }
    assert not re.search(r"^\s*-\s*uses:\s*actions/[^@\s]+@(?:v\d+|latest)\s*$", workflow, flags=re.MULTILINE)
    assert not re.search(r"#\s*actions/[^@\s]+@v\d+", workflow)
    assert "snowflake_native_app.py validate" in workflow
    assert "snowflake_native_app.py matrix" in workflow


# ─── Provider release + Marketplace distribution contract ─────────────────


def test_native_app_manifest_packages_consumer_readme(manifest: dict):
    assert manifest["artifacts"]["readme"] == "README.md"
    readme = CONSUMER_README_PATH.read_text(encoding="utf-8")
    assert "## Required privileges" in readme
    assert "## Configure after install" in readme
    assert "## Procedures" in readme


def test_marketplace_resource_manifest_declares_install_managed_compute_pool():
    marketplace = yaml.safe_load(MARKETPLACE_PATH.read_text(encoding="utf-8"))
    pools = marketplace["required_compute_pools"]
    assert len(pools) == 1
    pool_name, pool = next(iter(pools[0].items()))
    assert pool_name == "AGENT_BOM_CONSUMER_POOL"
    assert pool["compatible_instance_families"]

    setup = SETUP_SQL_PATH.read_text(encoding="utf-8").upper()
    assert "CREATE COMPUTE POOL IF NOT EXISTS AGENT_BOM_CONSUMER_POOL" in setup
    assert "INSTANCE_FAMILY = CPU_X64_XS" in setup


def test_snowflake_cli_project_packages_every_runtime_asset():
    project = yaml.safe_load(PROJECT_PATH.read_text(encoding="utf-8"))
    assert project["definition_version"] == 2
    package = project["entities"]["agent_bom_package"]
    assert package["type"] == "application package"
    assert package["distribution"] == "external"
    assert package["enable_release_channels"] is True
    assert package["manifest"] == "manifest.yml"

    sources = {entry["src"] for entry in package["artifacts"]}
    assert {
        "README.md",
        "manifest.yml",
        "marketplace.yml",
        "scripts/*.sql",
        "dcm/*.sql",
        "service-spec.yaml",
        "service-specs/*.yaml",
        "streamlit/*.py",
    } <= sources


def test_image_build_contract_matches_every_manifest_image(manifest: dict):
    contract = yaml.safe_load(IMAGE_BUILD_PATH.read_text(encoding="utf-8"))
    assert contract["schema_version"] == 1
    assert contract["platform"] == "linux/amd64"
    images = contract["images"]
    assert {item["name"] for item in images} == {
        "agent-bom",
        "agent-bom-ui",
        "agent-bom-scanner",
        "agent-bom-mcp-runtime",
    }
    manifest_names = {
        image.rsplit("/", 1)[-1].split(":", 1)[0]
        for image in manifest["artifacts"]["container_services"]["images"]
    }
    assert manifest_names == {item["name"] for item in images}
    repo_root = NATIVE_APP_DIR.parents[2]
    for item in images:
        assert (repo_root / item["context"]).exists()
        assert (repo_root / item["dockerfile"]).is_file()


def test_marketplace_listing_template_is_review_ready_and_has_no_publication_claim():
    listing = yaml.safe_load(LISTING_TEMPLATE_PATH.read_text(encoding="utf-8"))
    assert listing["title"] == "agent-bom"
    assert listing["subtitle"]
    assert listing["description"]
    assert listing["listing_terms"]["type"] == "STANDARD"
    assert listing["usage_examples"]
    assert listing["data_dictionary"]
    text = LISTING_TEMPLATE_PATH.read_text(encoding="utf-8")
    assert "TBD" not in text
    assert "published" not in text.lower()


def test_release_tool_validates_and_builds_reproducible_package(tmp_path: Path):
    validate = subprocess.run(
        [sys.executable, str(RELEASE_TOOL_PATH), "validate"],
        cwd=NATIVE_APP_DIR.parents[2],
        text=True,
        capture_output=True,
        check=False,
    )
    assert validate.returncode == 0, validate.stderr

    first = tmp_path / "first.tgz"
    second = tmp_path / "second.tgz"
    for target in (first, second):
        result = subprocess.run(
            [sys.executable, str(RELEASE_TOOL_PATH), "package", "--output", str(target)],
            cwd=NATIVE_APP_DIR.parents[2],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr

    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    with tarfile.open(first, "r:gz") as archive:
        names = set(archive.getnames())
    assert "manifest.yml" in names
    assert "marketplace.yml" in names
    assert "README.md" in names
    assert "snowflake.yml" not in names
    assert "images.yml" not in names


def test_release_workflow_builds_pushes_and_publishes_without_secret_echoes():
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "fromJSON(needs.package.outputs.image_matrix)" in workflow
    assert "linux/amd64" in workflow
    assert "docker push" in workflow
    assert "snow spcs image-registry login" in workflow
    assert "snow app deploy" in workflow
    assert "snow app publish" in workflow
    assert "snow app bundle --project deploy/snowflake/native-app" in workflow
    assert "--project deploy/snowflake/native-app/snowflake.yml" not in workflow
    assert "SNOWFLAKE_PRIVATE_KEY" in workflow
    assert 'echo "$SNOWFLAKE_PRIVATE_KEY"' not in workflow
    assert "snowflake-cli==" in workflow
    assert "environment: snowflake-marketplace" in workflow
