from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_snowflake_pov_runbook_names_current_and_roadmap_surfaces() -> None:
    body = (ROOT / "site-docs" / "deployment" / "snowflake-pov.md").read_text()

    for required in (
        "Snowflake/Cortex operator-pull inventory",
        "Snowflake Postgres",
        "AGENT_BOM_POSTGRES_URL",
        "examples/operator_pull/snowflake_inventory_adapter.py",
        "--fail-on-severity high",
        "Draft PR remediation",
        "Roadmap",
        "Candidate until smoke-tested",
    ):
        assert required in body


def test_snowflake_operator_pull_adapter_has_existing_smoke_coverage() -> None:
    test_body = (ROOT / "tests" / "test_operator_pull_azure_gcp_adapters.py").read_text()
    adapter_body = (ROOT / "examples" / "operator_pull" / "snowflake_inventory_adapter.py").read_text()

    assert "test_snowflake_operator_pull_adapter_cli_writes_scope_zero_inventory" in test_body
    assert "--discovery-method" in adapter_body
    assert "operator_pushed_inventory" in adapter_body
    assert "examples/operator_pull/snowflake_inventory_adapter.py" in adapter_body
