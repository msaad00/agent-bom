from __future__ import annotations

from pathlib import Path

from scripts.pytest_ci_plan import discover_test_files, plan_shards, select_targeted_tests


def _write(path: Path, lines: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x\n" * lines, encoding="utf-8")


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


def test_route_and_shared_auth_edits_always_select_mounted_operation_matrix(tmp_path: Path) -> None:
    from scripts.pytest_ci_plan import AUTHORIZATION_CONTRACTS, AUTHORIZATION_SOURCES

    expected = sorted(tmp_path / path for path in AUTHORIZATION_CONTRACTS)
    for path in expected:
        _write(path, 1)
    for source in [*AUTHORIZATION_SOURCES, "src/agent_bom/api/routes/new_surface.py"]:
        assert select_targeted_tests(changed_files=[Path(source)], root=tmp_path) == expected


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
