"""Fail-closed contracts for the packaged AWS/EKS credential bootstrap."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLATFORM_DIR = ROOT / "deploy" / "terraform" / "platform-eks"
MAIN = (PLATFORM_DIR / "main.tf").read_text(encoding="utf-8")
VARIABLES = (PLATFORM_DIR / "variables.tf").read_text(encoding="utf-8")
TFVARS_EXAMPLE = (PLATFORM_DIR / "terraform.tfvars.example").read_text(encoding="utf-8")
README = (PLATFORM_DIR / "README.md").read_text(encoding="utf-8")
BASELINE_OUTPUTS = (ROOT / "deploy" / "terraform" / "aws" / "baseline" / "outputs.tf").read_text(encoding="utf-8")

RUNTIME_SECRET_NAMES = (
    "app_db_secret_name",
    "maintenance_db_secret_name",
    "auth_secret_name",
)


def _variable_names() -> list[str]:
    return re.findall(r'^variable\s+"([^"]+)"\s*\{', VARIABLES, flags=re.MULTILINE)


def _variable_block(name: str) -> str:
    header = f'variable "{name}"'
    start = VARIABLES.find(header)
    assert start >= 0, f"missing Terraform variable {name}"
    following = re.search(r'^variable\s+"', VARIABLES[start + len(header) :], flags=re.MULTILINE)
    end = len(VARIABLES) if following is None else start + len(header) + following.start()
    return VARIABLES[start:end]


def _balanced_hcl_block(text: str, header: str) -> str:
    start = text.find(header)
    assert start >= 0, f"missing HCL block {header}"
    brace = text.find("{", start + len(header))
    assert brace >= 0, f"HCL block {header} has no body"

    depth = 0
    quoted = False
    escaped = False
    for index in range(brace, len(text)):
        char = text[index]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError(f"unterminated HCL block {header}")


def _secret_block(name_suffix: str) -> str:
    match = re.search(rf'nameSuffix\s*=\s*"{re.escape(name_suffix)}"', MAIN)
    assert match is not None, f"missing ExternalSecret values entry {name_suffix}"
    start = match.start()
    next_match = re.search(r'nameSuffix\s*=\s*"', MAIN[match.end() :])
    next_entry = -1 if next_match is None else match.end() + next_match.start()
    end = len(MAIN) if next_entry < 0 else next_entry
    return MAIN[start:end]


def _dsn_template(env_name: str) -> str:
    matches = re.findall(rf'{re.escape(env_name)}\s*=\s*"((?:\\.|[^"])*)"', MAIN)
    assert len(matches) == 1, f"expected exactly one {env_name} DSN template, got {len(matches)}"
    return matches[0].replace('\\"', '"')


@pytest.mark.parametrize("name", RUNTIME_SECRET_NAMES)
def test_platform_eks_requires_existing_nonempty_secret_names(name: str) -> None:
    """Runtime and auth Secrets Manager entries are operator-owned inputs."""
    block = _variable_block(name)

    assert re.search(r"^\s*type\s*=\s*string\s*$", block, flags=re.MULTILINE)
    assert not re.search(r"^\s*default\s*=", block, flags=re.MULTILINE)
    assert "validation {" in block
    assert f'trimspace(var.{name}) != ""' in block

    example = re.search(rf'^{re.escape(name)}\s*=\s*"([^"]+)"\s*$', TFVARS_EXAMPLE, flags=re.MULTILINE)
    assert example is not None, f"terraform.tfvars.example must show {name}"
    assert example.group(1).strip()


def test_platform_eks_disables_unused_baseline_secret_containers() -> None:
    """The integrated platform must consume existing secrets, not create empty ones."""
    baseline = _balanced_hcl_block(MAIN, 'module "baseline"')

    assert re.search(r"^\s*create_db_url_secret\s*=\s*false\s*$", baseline, flags=re.MULTILINE)
    assert re.search(r"^\s*create_auth_secret\s*=\s*false\s*$", baseline, flags=re.MULTILINE)
    assert "module.baseline.db_url_secret_name" not in MAIN
    assert "module.baseline.auth_secret_name" not in MAIN


def test_standalone_baseline_hint_is_workload_only_and_role_separated() -> None:
    hint = _balanced_hcl_block(BASELINE_OUTPUTS, 'output "helm_values_hint"')

    assert "externalSecrets:" in hint
    assert "enabled: false" in hint
    assert "postgresSecrets:" in hint
    assert "appSecretRef:" in hint
    assert "maintenanceSecretRef:" in hint
    assert "adminSecretRef:" in hint
    assert "remoteRef:" not in hint
    assert "RDS" not in hint or "master" not in hint


def test_platform_forwards_unique_final_snapshot_identifier() -> None:
    baseline = _balanced_hcl_block(MAIN, 'module "baseline"')
    variable = _variable_block("db_final_snapshot_identifier")

    assert 'default     = ""' in variable
    assert "db_final_snapshot_identifier = var.db_final_snapshot_identifier" in baseline
    assert "db_final_snapshot_identifier" in TFVARS_EXAMPLE


def test_platform_eks_opens_rds_only_to_explicit_cluster_sources() -> None:
    """Created nodes are wired automatically; referenced clusters fail closed."""
    baseline = _balanced_hcl_block(MAIN, 'module "baseline"')
    validation = _balanced_hcl_block(MAIN, 'resource "terraform_data" "platform_input_validation"')

    assert "module.eks[0].node_security_group_id" in MAIN
    assert "db_allowed_security_group_ids = local.resolved_db_allowed_security_group_ids" in baseline
    assert re.search(r"db_allowed_cidr_blocks\s*=\s*var\.db_allowed_cidr_blocks", baseline)
    assert "var.create_cluster" in validation
    assert "var.db_allowed_security_group_ids" in validation
    assert "var.db_allowed_cidr_blocks" in validation
    assert "referenced EKS clusters require" in validation
    assert "terraform_data.platform_input_validation" in baseline


def test_existing_cluster_example_names_an_rds_network_source() -> None:
    """The reference-cluster example must not lead to an unreachable database."""
    assert "db_allowed_security_group_ids" in TFVARS_EXAMPLE
    assert "db_allowed_cidr_blocks" in VARIABLES
    assert "db_allowed_security_group_ids" in VARIABLES


@pytest.mark.parametrize(
    ("suffix", "env_name", "remote_secret"),
    (
        ("control-plane-db", "AGENT_BOM_POSTGRES_URL", "app_db_secret_name"),
        (
            "control-plane-maintenance",
            "AGENT_BOM_POSTGRES_MAINTENANCE_URL",
            "maintenance_db_secret_name",
        ),
        ("control-plane-admin", "ALEMBIC_DATABASE_URL", None),
    ),
)
def test_platform_eks_composes_three_distinct_database_identities(
    suffix: str,
    env_name: str,
    remote_secret: str | None,
) -> None:
    """App, maintenance, and migration/admin DSNs cannot share authority."""
    block = _secret_block(suffix)

    assert env_name in block
    assert block.count('secretKey = "username"') == 1
    assert block.count('secretKey = "password"') == 1
    if remote_secret is None:
        assert block.count("key      = module.baseline.db_secret_name") == 2
    else:
        assert block.count(f"key      = var.{remote_secret}") == 2
        assert "module.baseline.db_secret_name" not in block


def test_rds_master_secret_is_admin_only() -> None:
    """The RDS-managed master credential may feed migration, never runtime."""
    admin = _secret_block("control-plane-admin")

    assert admin.count("module.baseline.db_secret_name") == 2
    assert MAIN.count("module.baseline.db_secret_name") == 3
    assert "module.baseline.db_secret_name" not in _secret_block("control-plane-db")
    assert "module.baseline.db_secret_name" not in _secret_block("control-plane-maintenance")


def test_workloads_receive_only_the_database_identities_they_need() -> None:
    """Runtime, migration, and backup consumers keep separate secret projections."""
    workload_values = _balanced_hcl_block(MAIN, "workload_values =")
    postgres = _balanced_hcl_block(workload_values, "postgresSecrets =")
    api = _balanced_hcl_block(workload_values, "api =")
    migrations = _balanced_hcl_block(workload_values, "migrations =")
    backup = _balanced_hcl_block(workload_values, "backup =")

    assert "local.control_plane_secret_names.app" in postgres
    assert "local.control_plane_secret_names.maintenance" in postgres
    assert "local.control_plane_secret_names.admin" in postgres
    assert "local.control_plane_secret_names.auth" in api
    assert "local.control_plane_secret_names.admin" not in api
    assert "envFrom = []" in migrations
    assert "local.control_plane_secret_names.auth" not in migrations
    assert "envFrom = []" in backup
    assert "local.control_plane_secret_names.app" not in backup
    assert "local.control_plane_secret_names.admin" not in backup


@pytest.mark.parametrize(
    "env_name",
    ("AGENT_BOM_POSTGRES_URL", "AGENT_BOM_POSTGRES_MAINTENANCE_URL", "ALEMBIC_DATABASE_URL"),
)
def test_external_secret_dsns_urlencode_reserved_userinfo(env_name: str) -> None:
    """Reserved username/password characters must not corrupt a Postgres URI."""
    template = _dsn_template(env_name)
    escaped_username = '{{ .username | urlquery | replace "+" "%20" }}'
    escaped_password = '{{ .password | urlquery | replace "+" "%20" }}'
    assert escaped_username in template
    assert escaped_password in template
    assert "sslmode=require" in template

    username = "ops+tenant@example.com"
    password = "p@ss:/?#%&+ space"
    rendered = template.replace(escaped_username, quote(username, safe=""))
    rendered = rendered.replace(escaped_password, quote(password, safe=""))
    rendered = rendered.replace("${module.baseline.db_endpoint}", "db.internal")
    rendered = rendered.replace("${module.baseline.db_port}", "5432")
    rendered = rendered.replace("${module.baseline.db_name}", "agent_bom")

    parsed = urlsplit(rendered)
    assert parsed.scheme == "postgresql"
    assert parsed.hostname == "db.internal"
    assert parsed.port == 5432
    assert parsed.path == "/agent_bom"
    assert unquote(parsed.username or "") == username
    assert unquote(parsed.password or "") == password
    assert parsed.query == "sslmode=require"


def test_rotation_generation_forces_sync_reconcile_migration_and_rollout() -> None:
    generation = _variable_block("runtime_credentials_generation")
    assert "default" not in generation
    assert "^[A-Za-z0-9._-]{1,63}$" in generation

    sync_values = _balanced_hcl_block(MAIN, "external_secret_values =")
    barrier = _balanced_hcl_block(MAIN, 'resource "terraform_data" "control_plane_secrets_ready"')
    workload_values = _balanced_hcl_block(MAIN, "workload_values =")
    assert sync_values.count("var.runtime_credentials_generation") >= 4
    assert sync_values.count('refreshPolicy = "OnChange"') == 4
    assert "agent-bom.com/credentials-generation" in sync_values
    assert "var.runtime_credentials_generation" in barrier
    assert "jsonpath" in barrier
    assert "agent-bom\\.com/credentials-generation" in MAIN
    assert "podAnnotations" in workload_values
    assert "var.runtime_credentials_generation" in workload_values
    assert "teardownHooks = { enabled = false }" in workload_values


def test_each_apply_refreshes_rds_managed_admin_before_migration() -> None:
    admin = _secret_block("control-plane-admin")
    barrier = _balanced_hcl_block(MAIN, 'resource "terraform_data" "control_plane_secrets_ready"')

    assert "admin_refresh_nonce = sha256(timestamp())" in MAIN
    assert '"force-sync" = local.admin_refresh_nonce' in admin
    assert '"agent-bom.com/admin-refresh-nonce"' in admin
    assert "local.admin_refresh_nonce" in barrier
    assert "ADMIN_REFRESH_NONCE" in barrier
    assert "agent-bom\\.com/admin-refresh-nonce" in MAIN


def test_platform_requires_external_secrets_prerequisites_before_sync() -> None:
    prerequisites = _variable_block("external_secrets_prerequisites_ready")
    validation = _balanced_hcl_block(MAIN, 'resource "terraform_data" "platform_input_validation"')
    assert "default     = false" in prerequisites
    assert "var.external_secrets_prerequisites_ready" in validation
    assert "External Secrets Operator" in validation


def test_auth_bundle_cannot_override_dedicated_database_identities() -> None:
    workload_values = _balanced_hcl_block(MAIN, "workload_values =")
    api = _balanced_hcl_block(workload_values, "api =")
    postgres = _balanced_hcl_block(workload_values, "postgresSecrets =")
    assert "local.control_plane_secret_names.auth" in api
    assert "local.control_plane_secret_names.app" not in api
    assert "local.control_plane_secret_names.maintenance" not in api
    assert "appSecretRef" in postgres and "maintenanceSecretRef" in postgres


def test_secret_sync_has_an_explicit_readiness_barrier_before_workloads() -> None:
    """Creating an ExternalSecret CR is not equivalent to reconciling its target."""
    sync_release = _balanced_hcl_block(MAIN, 'resource "helm_release" "control_plane_secrets"')
    barrier = _balanced_hcl_block(MAIN, 'resource "terraform_data" "control_plane_secrets_ready"')
    workload_release = _balanced_hcl_block(MAIN, 'resource "helm_release" "control_plane"')
    secret_names = _balanced_hcl_block(MAIN, "control_plane_secret_names =")

    assert "yamlencode(local.secret_sync_values)" in sync_release
    assert "helm_release.control_plane_secrets" in barrier
    assert "mktemp" in barrier
    assert "trap" in barrier and "rm -f" in barrier
    assert "aws eks update-kubeconfig" in barrier
    assert "--kubeconfig" in barrier
    assert re.search(r"kubectl\b.*?\bwait\b", barrier)
    assert "--for=condition=Ready" in barrier
    assert '"secret/$external_secret"' in MAIN
    for logical_name, suffix in (
        ("app", "control-plane-db"),
        ("maintenance", "control-plane-maintenance"),
        ("admin", "control-plane-admin"),
        ("auth", "control-plane-auth"),
    ):
        assert suffix in secret_names
        assert f"local.control_plane_secret_names.{logical_name}" in barrier

    assert "terraform_data.control_plane_secrets_ready" in workload_release
    assert "yamlencode(local.workload_values)" in workload_release


def test_secret_sync_and_workload_values_cannot_reopen_the_hook_race() -> None:
    """Only the bootstrap release renders ExternalSecrets; workloads consume targets."""
    sync_values = _balanced_hcl_block(MAIN, "secret_sync_values =")
    workload_values = _balanced_hcl_block(MAIN, "workload_values =")

    assert re.search(r"enabled\s*=\s*false", sync_values)
    assert "externalSecrets = merge(local.external_secret_values" in sync_values
    assert re.search(r"enabled\s*=\s*true", sync_values)
    assert re.search(r"syncOnly\s*=\s*true", sync_values)

    assert re.search(r"enabled\s*=\s*true", workload_values)
    assert re.search(r"externalSecrets\s*=\s*\{.*?enabled\s*=\s*false", workload_values, flags=re.DOTALL)
    assert "migrations =" in workload_values


def test_platform_eks_inputs_never_accept_database_secret_values() -> None:
    """Terraform state may contain secret names, but never raw DB credentials."""
    forbidden_input = re.compile(r"(^|_)(password|postgres_url|maintenance_url|alembic_database_url|database_url)($|_)")

    assert not [name for name in _variable_names() if forbidden_input.search(name)]
    assert 'data "aws_secretsmanager_secret_version"' not in MAIN
    assert 'resource "aws_secretsmanager_secret_version"' not in MAIN
    assert "secret_string" not in MAIN


def test_readme_documents_the_fail_closed_bootstrap_order() -> None:
    """Operators see credential, reconciliation, migration, then runtime order."""
    assert "## Secure bootstrap" in README
    bootstrap = README.split("## Secure bootstrap", maxsplit=1)[1]
    normalized = bootstrap.lower()

    required_markers = (
        "1. create three json secrets",
        "2. put only those three secret names",
        "waits until all four externalsecrets",
        "3. after the barrier passes",
        "the api and backup workloads start only after it succeeds",
    )
    positions = [normalized.index(marker) for marker in required_markers]
    assert positions == sorted(positions)

    for name in RUNTIME_SECRET_NAMES:
        assert name in bootstrap
    assert "report `Ready`" in bootstrap
    assert "target Kubernetes Secrets exist" in bootstrap
    assert "RDS-managed master" in README
    assert "ALEMBIC_DATABASE_URL" in README
    assert "Terraform state" in README
    assert "there is no secret to populate by hand" not in README
