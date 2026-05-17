"""Tests for dbt project security scanning."""

from __future__ import annotations

from pathlib import Path

from agent_bom.iac import scan_iac_with_context
from agent_bom.iac.dbt_security import scan_dbt_file


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _rule_ids(root: Path) -> set[str]:
    return {finding.rule_id for finding in scan_iac_with_context(root).findings}


def test_profiles_yml_detects_credentials_tls_and_password_auth(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "profiles.yml",
        """
prod:
  target: prod
  outputs:
    prod:
      type: snowflake
      account: example
      user: svc_dbt
      password: hardcoded-password
      require_ssl: false
      uri: postgres://dbt:secret@example.com/warehouse
""",
    )

    findings = scan_dbt_file(path)
    rule_ids = {finding.rule_id for finding in findings}

    assert {"DBT-SEC-001", "DBT-SEC-002", "DBT-SEC-003", "DBT-SEC-004"} <= rule_ids
    assert all(finding.category == "dbt" for finding in findings)


def test_dbt_project_detects_clean_targets_dispatch_version_and_grant_hook(tmp_path: Path) -> None:
    _write(
        tmp_path / "dbt_project.yml",
        """
name: demo
clean-targets:
  - ../outside
dispatch:
  - macro_namespace: dbt
    search_order: ["evil_pkg", "dbt"]
models:
  demo:
    +post-hook: "GRANT ALL ON SCHEMA analytics TO ROLE analyst"
""",
    )

    assert {"DBT-SEC-005", "DBT-SEC-006", "DBT-SEC-007", "DBT-SEC-013"} <= _rule_ids(tmp_path)


def test_packages_yml_detects_unpinned_and_untrusted_packages(tmp_path: Path) -> None:
    _write(
        tmp_path / "packages.yml",
        """
packages:
  - package: dbt-labs/dbt_utils
  - git: git://example.invalid/private/dbt_pkg.git
    revision: main
  - git: ssh://git@example.com/team/pkg.git
    revision: 8fe13c4ab29d
""",
    )

    rule_ids = _rule_ids(tmp_path)

    assert "DBT-SEC-008" in rule_ids
    assert "DBT-SEC-009" in rule_ids
    assert "DBT-SEC-010" in rule_ids


def test_models_and_macros_detect_dynamic_sql_and_secret_logging(tmp_path: Path) -> None:
    _write(tmp_path / "dbt_project.yml", "name: demo\nrequire-dbt-version: ['>=1.7.0', '<2.0.0']\n")
    _write(
        tmp_path / "models" / "orders.sql",
        """
select * from {{ var('table_name') }}
where id in ({{ run_query("select id from " ~ var('table_name')) }})
{{ log(env_var('API_TOKEN'), info=True) }}
select '{{ env_var("WAREHOUSE_PASSWORD") }}'
""",
    )

    assert {"DBT-SEC-011", "DBT-SEC-012", "DBT-SEC-014", "DBT-SEC-015"} <= _rule_ids(tmp_path)


def test_ci_and_seed_checks_are_routed_through_iac_directory_scan(tmp_path: Path) -> None:
    _write(tmp_path / "dbt_project.yml", "name: demo\nrequire-dbt-version: ['>=1.7.0', '<2.0.0']\n")
    _write(
        tmp_path / ".github" / "workflows" / "dbt.yml",
        """
name: dbt
jobs:
  build:
    steps:
      - run: dbt run --target prod
""",
    )
    _write(tmp_path / "seeds" / "customers.csv", "email,ssn,name\nalice@example.com,111-22-3333,Alice\n")

    result = scan_iac_with_context(tmp_path)
    rule_ids = {finding.rule_id for finding in result.findings}
    dbt_verdict = next(verdict for verdict in result.verdicts if verdict.scanner_id == "dbt")

    assert {"DBT-SEC-016", "DBT-SEC-017", "DBT-SEC-018"} <= rule_ids
    assert dbt_verdict.status == "ran"
    assert dbt_verdict.files_scanned == 3
