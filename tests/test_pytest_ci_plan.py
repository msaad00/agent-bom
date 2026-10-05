from __future__ import annotations

from pathlib import Path

import pytest

from scripts.pytest_ci_plan import discover_test_files, plan_shards, select_targeted_tests


def _write(path: Path, lines: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x\n" * lines, encoding="utf-8")


@pytest.mark.parametrize(
    "source", ["src/agent_bom/security.py", "src/agent_bom/redaction/payload.py", "src/agent_bom/redaction/cloud_coordinates.py"]
)
def test_redaction_edits_select_identity_and_traversal_contracts(tmp_path, source):
    expected = sorted(tmp_path / "tests" / name for name in ("test_scan_export_perf.py", "test_cloud_coordinate_redaction.py"))
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize("source", ["src/agent_bom/parsers/new_module.py", "src/agent_bom/removed_module.py", "docs/PRODUCT_METRICS.json"])
def test_module_and_metric_edits_select_snapshot_contract(tmp_path, source):
    expected = tmp_path / "tests/test_product_metrics_snapshot.py"
    _write(expected, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [expected]


@pytest.mark.parametrize(
    "source", ["src/agent_bom/sbom.py", "src/agent_bom/parsers/sbom_context.py", "src/agent_bom/cli/agents/_discovery.py"]
)
def test_sbom_import_edits_select_cli_and_scope_contracts(tmp_path, source):
    expected = sorted(
        tmp_path / "tests" / name for name in ("test_cli_check.py", "test_sbom_scan_scope.py", "test_sbom_cloud_roundtrip.py")
    )
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize("source", ["pyproject.toml", "uv.lock", ".pre-commit-config.yaml", "Makefile", ".github/workflows/ci.yml"])
def test_dependency_and_checker_changes_select_pin_agreement(tmp_path: Path, source: str) -> None:
    contract = tmp_path / "tests/test_toolchain_pin_agreement.py"
    _write(contract, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)

    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [contract]


def test_shard_plan_is_deterministic_disjoint_and_complete(tmp_path: Path) -> None:
    for index, lines in enumerate((200, 150, 120, 90, 70, 50, 30, 20, 10)):
        _write(tmp_path / f"group_{index % 3}" / f"test_{index}.py", lines)

    files = discover_test_files(tmp_path)
    first = plan_shards(files, total=4)
    second = plan_shards(files, total=4)

    assert first == second
    assert {path for shard in first for path in shard} == set(files)
    assert sum(len(shard) for shard in first) == len(files)

    loads = [sum(path.stat().st_size for path in shard) for shard in first]
    largest = max(path.stat().st_size for path in files)
    assert max(loads) - min(loads) <= largest


def test_targeted_tests_include_changed_tests_and_source_name_matches(tmp_path: Path) -> None:
    direct = tmp_path / "tests" / "test_direct.py"
    matching = tmp_path / "tests" / "db" / "test_local_analytics.py"
    unrelated = tmp_path / "tests" / "test_other.py"
    for path in (direct, matching, unrelated):
        _write(path, 1)

    selected = select_targeted_tests(
        changed_files=[Path("tests/test_direct.py"), Path("src/agent_bom/db/local_analytics.py")],
        root=tmp_path,
    )

    assert selected == [matching, direct]


def test_ast_edits_select_characterization_and_console_reconciliation(tmp_path: Path) -> None:
    expected = sorted(tmp_path / "tests" / name for name in ("test_ast_analysis_characterization.py", "test_console_reconciliation.py"))
    for path in [*expected, tmp_path / "tests/test_other.py"]:
        _write(path, 1)
    for source in (
        "src/agent_bom/ast_analyzer.py",
        "src/agent_bom/ast_python_analysis.py",
        "src/agent_bom/ast/js_ts/facade.py",
        "tests/fixtures/analysis_characterization/multilang/server.ts",
        "tests/fixtures/analysis_characterization_golden.json",
    ):
        assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


def test_route_and_shared_auth_edits_always_select_mounted_operation_matrix(tmp_path: Path) -> None:
    from scripts.pytest_ci_plan import AUTHORIZATION_CONTRACTS, AUTHORIZATION_SOURCES

    expected = sorted(tmp_path / path for path in AUTHORIZATION_CONTRACTS)
    for path in expected:
        _write(path, 1)
    for source in [*AUTHORIZATION_SOURCES, "src/agent_bom/api/routes/new_surface.py"]:
        assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


def test_tenant_worker_edits_select_scheduler_and_persistence_callers(tmp_path):
    names = (
        "test_connection_scheduler.py",
        "test_side_scan_scheduler.py",
        "test_auto_correlation_scheduler.py",
        "test_scan_jobs_active_gauge.py",
        "test_graph_persistence_characterization.py",
        "test_tenant_dispatch_boundaries.py",
    )
    expected = sorted(tmp_path / "tests" / name for name in names)
    for path in expected:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom/api/tenant_worker.py")], root=tmp_path) == expected


def test_mcp_registration_edits_select_tool_contracts(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_mcp_tool_output_contract.py",
            "test_mcp_strict_args.py",
            "test_deployment.py",
            "test_stats_alignment.py",
            "test_fleet_scan.py",
        )
    )
    for path in expected:
        _write(path, 1)
    for source in (
        "src/agent_bom/mcp_tools/endpoint_connectors.py",
        "src/agent_bom/mcp_tools/new_tools.py",
        "src/agent_bom/mcp_tools/__init__.py",
        "src/agent_bom/mcp_server.py",
        "src/agent_bom/mcp_server_metadata.py",
        "src/agent_bom/mcp_server_specialized.py",
        "src/agent_bom/mcp_strict_args.py",
    ):
        assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected
    assert select_targeted_tests(changed_files=[Path("src/agent_bom/cloud/aws.py")], root=tmp_path) == []


def test_tenant_worker_edits_cover_each_dispatch_surface(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / path
        for path in (
            "tests/test_report_worker_recovery.py",
            "tests/test_report_jobs_postgres.py",
            "tests/test_distributed_scan_queue.py",
            "tests/test_exports_api.py",
            "tests/api/test_api_scan_worker_tenant_binding.py",
        )
    )
    for path in [*expected, tmp_path / "tests/test_other.py"]:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom/api/tenant_worker.py")], root=tmp_path) == expected


def test_gateway_modules_select_cross_surface_enforcement_contracts(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_gateway_server.py",
            "test_gateway_firewall.py",
            "test_gateway_relay_lifecycle.py",
            "test_gateway_audit_delivery.py",
            "api/test_api_gateway.py",
            "api/test_gateway_runtime_acceptance.py",
        )
    )
    for path in expected:
        _write(path, 1)
    _write(tmp_path / "tests/test_other.py", 1)
    for source in (
        "src/agent_bom/gateway_server.py",
        "src/agent_bom/runtime/gateway_relay.py",
        "src/agent_bom/runtime/gateway_settings.py",
        "src/agent_bom/api/gateway_auth.py",
        "src/agent_bom/api/gateway_request.py",
        "src/agent_bom/api/gateway_context.py",
        "src/agent_bom/runtime/risk_conditions.py",
        "src/agent_bom/api/gateway_rate_limit.py",
        "src/agent_bom/api/gateway_policy.py",
        "src/agent_bom/runtime/gateway_policy_reload.py",
        "src/agent_bom/runtime/trace_metadata.py",
    ):
        assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


def test_report_projection_edits_select_builder_store_and_runtime_contracts(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_graph_builder.py",
            "test_graph_projection_contracts.py",
            "test_runtime_incident_feedback.py",
            "graph/test_store_backed_unified_graph.py",
        )
    )
    for path in expected:
        _write(path, 1)
    for module in ("builder", "package_projection", "runtime_projection", "projection_support", "ports"):
        assert select_targeted_tests(changed_files=[Path(f"src/agent_bom/graph/{module}.py")], root=tmp_path) == expected


def test_shared_judgments_select_caller_parity(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_transitive.py",
            "test_version_utils.py",
            "test_compliance_narrative.py",
            "test_credential_policy_kernel.py",
            "test_graph_nhi_governance.py",
            "test_shared_semantic_hygiene.py",
        )
    )
    for path in expected:
        _write(path, 1)
    for name in ("packages", "severity", "timestamps"):
        assert select_targeted_tests(changed_files=[Path(f"src/agent_bom/core/{name}.py")], root=tmp_path) == expected


def test_delegation_sources_select_lifecycle_and_authority_contracts(tmp_path):
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_delegation_identity_authority.py",
            "test_governance_abac_delegation.py",
            "test_agent_identity_lifecycle.py",
            "test_identity_governance_3687.py",
        )
    )
    for path in expected:
        _write(path, 1)
    for source in ("delegation_token.py", "delegation_service.py", "agent_identity_store.py", "routes/identities.py"):
        assert select_targeted_tests(changed_files=[Path("src/agent_bom/api") / source], root=tmp_path) == expected


def test_jit_grant_changes_select_store_lifecycle_and_runtime_callers(tmp_path):
    names = (
        "test_jit_grant_tenant_boundary.py",
        "test_identity_policy_tenant_boundary.py",
        "test_device_posture.py",
        "test_nhi_lifecycle_enforcement.py",
        "test_durable_store_default.py",
        "test_graph_governance_overlay.py",
        "test_agent_identity_lifecycle.py",
    )
    expected = sorted(tmp_path / "tests" / name for name in names)
    for path in expected:
        _write(path, 1)
    for source in ("identity_grants.py", "identity_policies.py", "agent_identity_store.py", "postgres_agent_identity.py"):
        assert select_targeted_tests(changed_files=[Path("src/agent_bom/api") / source], root=tmp_path) == expected


def test_shared_sql_changes_select_finding_and_storage_contracts(tmp_path):
    names = (
        "test_findings_sql_read_contract.py",
        "test_finding_lifecycle.py",
        "test_finding_sla_lifecycle.py",
        "test_postgres_ledger_scan_filter.py",
        "test_overview.py",
        "test_findings_sql_backfill.py",
        "test_hub_ingest_atomic.py",
        "test_storage_sql.py",
        "test_tenant_quota_store.py",
        "test_tenant_graph_retention_store.py",
    )
    expected = sorted(tmp_path / "tests" / name for name in names)
    for path in expected:
        _write(path, 1)
    for source in (
        "storage/sql.py",
        "storage/finding_reads.py",
        "storage/finding_payloads.py",
        "compliance_hub_store.py",
        "postgres_compliance_hub.py",
    ):
        assert select_targeted_tests(changed_files=[Path("src/agent_bom/api") / source], root=tmp_path) == expected


def test_job_storage_changes_select_tenant_lifecycle_and_correlation_callers(tmp_path: Path) -> None:
    expected = [
        tmp_path / "tests/api/test_api_tenant_isolation.py",
        tmp_path / "tests/test_agent_lifecycle_history.py",
        tmp_path / "tests/test_auto_correlation_scheduler.py",
    ]
    for path in [*expected, tmp_path / "tests/test_other.py"]:
        _write(path, 1)
    for source in ["store.py", "stores.py", "postgres_job_store.py", "scan_queue.py", "storage/jobs.py", "storage/job_cache.py"]:
        assert select_targeted_tests(changed_files=[Path("src/agent_bom/api") / source], root=tmp_path) == sorted(expected)


@pytest.mark.parametrize(
    "source",
    ["push_evidence.py", "push_models.py", "correlation_cohort_ingest.py", "finding_collection.py", "routes/observability.py"],
)
def test_push_edits_select_tenant_summary_and_ingest_contracts(tmp_path: Path, source: str) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "api/test_api_tenant_isolation.py",
            "api/test_push_evidence_hardening.py",
            "api/test_push_replacement_scope.py",
            "api/test_correlation_cohort_push_ingest.py",
            "test_ingest_idempotency.py",
            "test_findings_push.py",
        )
    )
    for path in [*expected, tmp_path / "tests/test_unrelated.py"]:
        _write(path, 1)
    assert select_targeted_tests(changed_files=[Path("src/agent_bom/api") / source], root=tmp_path) == expected


def test_graph_storage_edits_include_startup_and_writer_contracts(tmp_path: Path) -> None:
    expected = sorted(
        tmp_path / "tests" / name
        for name in (
            "test_graph_wal_startup.py",
            "test_graph_writer_admission.py",
            "test_graph_bootstrap_cost.py",
            "test_graph_initialization_lock.py",
            "test_graph_store_streamed_persistence.py",
        )
    )
    for path in expected:
        _write(path, 1)
    _write(tmp_path / "tests/test_unrelated.py", 1)
    for source in (
        "src/agent_bom/db/graph_store.py",
        "src/agent_bom/db/graph_bootstrap.py",
        "src/agent_bom/db/graph_revision.py",
        "src/agent_bom/db/graph_write_admission.py",
        "src/agent_bom/api/graph_store.py",
        "src/agent_bom/storage/sqlite_wal.py",
    ):
        assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


@pytest.mark.parametrize(
    "source",
    [
        "src/agent_bom/api/inventory_service.py",
        "src/agent_bom/api/routes/inventory_assets.py",
        "src/agent_bom/api/routes/graph.py",
        "src/agent_bom/api/neptune_graph.py",
    ],
)
def test_inventory_graph_edits_select_backend_support_contract(tmp_path, source):
    expected = tmp_path / "tests/test_neptune_unsupported_501.py"
    _write(expected, 1)
    assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == [expected]
