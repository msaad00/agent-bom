#!/usr/bin/env python3
"""Build deterministic, exhaustive pytest plans for CI.

The PR suite is split by test-file byte weight.  Every file is assigned to
exactly one shard, while the largest files are greedily spread across runners.
The changed-domain selector is intentionally conservative: it includes tests
changed directly and tests whose basename matches a changed source/script
module.  Cross-surface smoke tests are added by the workflow itself.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable

AUTHORIZATION_SOURCES = frozenset(
    {
        "src/agent_bom/rbac.py",
        "src/agent_bom/api/auth.py",
        "src/agent_bom/api/middleware.py",
        "src/agent_bom/api/route_policy.py",
        "src/agent_bom/api/session_authorization.py",
        "src/agent_bom/api/stream_authorization.py",
        "src/agent_bom/api/sse_authorization.py",
        "src/agent_bom/api/websocket_auth.py",
        "src/agent_bom/api/tenancy.py",
        "src/agent_bom/api/tenant_worker.py",
        "src/agent_bom/api/routes/proxy.py",
    }
)
AUTHORIZATION_CONTRACTS = (
    "tests/test_tenant_worker.py",
    "tests/test_tenant_dispatch_boundaries.py",
    "tests/test_postgres_maintenance_pool.py",
    "tests/test_runtime_source_auth_contract.py",
    "tests/test_api_route_policy.py",
    "tests/api/test_operation_scope_coverage.py",
    "tests/api/test_session_authorization_backends.py",
    "tests/api/test_auth_scope_boundaries.py",
    "tests/api/test_auth_contract_matrix.py",
    "tests/api/test_stream_authorization.py",
    "tests/test_websocket_auth_fails_closed.py",
)
MCP_TOOL_CONTRACTS = (
    "tests/test_mcp_operator_registration.py",
    "tests/test_mcp_catalog_drift.py",
    "tests/test_regression_quality.py",
    "tests/test_deployment.py",
    "tests/test_stats_alignment.py",
    "tests/test_fleet_scan.py",
    "tests/test_mcp_tool_output_contract.py",
    "tests/test_mcp_strict_args.py",
)
GRAPH_PROJECTION_SOURCES = frozenset(
    {
        "src/agent_bom/graph/builder.py",
        "src/agent_bom/graph/package_projection.py",
        "src/agent_bom/graph/runtime_projection.py",
        "src/agent_bom/graph/projection_support.py",
        "src/agent_bom/graph/ports.py",
        "src/agent_bom/graph/identity_nodes.py",
        "src/agent_bom/graph/authorization_evidence.py",
        "src/agent_bom/graph/cloud_rbac.py",
        "src/agent_bom/graph/nhi_governance.py",
        "src/agent_bom/graph/build_input.py",
        "src/agent_bom/graph/build_indexes.py",
        "src/agent_bom/graph/build_analysis.py",
        "src/agent_bom/graph/agent_projection.py",
        "src/agent_bom/graph/credential_projection.py",
        "src/agent_bom/graph/blast_projection.py",
        "src/agent_bom/graph/benchmark_projection.py",
        "src/agent_bom/graph/resource_aliases.py",
        "src/agent_bom/graph/finding_projection.py",
        "src/agent_bom/graph/training_projection.py",
    }
)

SHARED_JUDGMENT_SOURCES = frozenset(
    {
        "src/agent_bom/core/packages.py",
        "src/agent_bom/core/severity.py",
        "src/agent_bom/core/timestamps.py",
    }
)
SHARED_JUDGMENT_PREFIXES = (
    "test_shared_semantic_hygiene",
    "test_version_utils",
    "test_transitive",
    "test_compliance_nist_catalog",
    "test_compliance_unrated_false_pass",
    "test_compliance_narrative",
    "test_credential_expiry",
    "test_credential_policy",
    "test_graph_nhi_governance",
    "test_nhi_governance_aws_gcp_parity",
)


def discover_test_files(root: Path) -> list[Path]:
    """Return every pytest module below *root* in stable path order."""
    return sorted(path for path in root.rglob("test_*.py") if path.is_file())


def plan_shards(files: Iterable[Path], *, total: int) -> list[list[Path]]:
    """Assign all files once using deterministic largest-first balancing."""
    if total < 1:
        raise ValueError("total shards must be positive")

    shards: list[list[Path]] = [[] for _ in range(total)]
    loads = [0] * total
    weighted = sorted(files, key=lambda path: (-path.stat().st_size, path.as_posix()))
    for path in weighted:
        index = min(range(total), key=lambda candidate: (loads[candidate], candidate))
        shards[index].append(path)
        loads[index] += path.stat().st_size

    return [sorted(shard) for shard in shards]


def select_targeted_tests(*, changed_files: Iterable[Path], root: Path) -> list[Path]:
    """Select directly changed tests and basename matches for source modules."""
    test_root = root / "tests"
    available = discover_test_files(test_root)
    selected: set[Path] = set()

    for changed in changed_files:
        normalized = Path(changed.as_posix().removeprefix("./"))
        if normalized.as_posix().startswith("src/agent_bom/") or normalized.as_posix().startswith("docs/PRODUCT_METRICS."):
            selected.update(candidate for candidate in available if candidate.name == "test_product_metrics_snapshot.py")
        if normalized.as_posix() == "src/agent_bom/security.py" or normalized.as_posix().startswith("src/agent_bom/redaction/"):
            selected.update(
                candidate for candidate in available if candidate.name in {"test_scan_export_perf.py", "test_cloud_coordinate_redaction.py"}
            )
        if normalized.as_posix() in {
            "src/agent_bom/sbom.py",
            "src/agent_bom/parsers/sbom_context.py",
            "src/agent_bom/cli/agents/_discovery.py",
        }:
            selected.update(
                candidate
                for candidate in available
                if candidate.name in {"test_cli_check.py", "test_sbom_scan_scope.py", "test_sbom_cloud_roundtrip.py"}
            )
        if normalized.as_posix() in {"pyproject.toml", "uv.lock", ".pre-commit-config.yaml", "Makefile", ".github/workflows/ci.yml"}:
            selected.update(candidate for candidate in available if candidate.name == "test_toolchain_pin_agreement.py")
        if normalized.as_posix().startswith(("src/agent_bom/ast/", "src/agent_bom/ast_", "tests/fixtures/analysis_characterization")):
            selected.update(
                candidate
                for candidate in available
                if candidate.name in {"test_ast_analysis_characterization.py", "test_console_reconciliation.py"}
            )
        if normalized.as_posix().startswith("src/agent_bom/api/storage/") or normalized.as_posix() in {
            "src/agent_bom/api/compliance_hub_store.py",
            "src/agent_bom/api/postgres_compliance_hub.py",
        }:
            selected.update(
                candidate
                for candidate in available
                if "findings" in candidate.stem
                or candidate.stem
                in {
                    "test_ingest_idempotency",
                    "test_finding_sla_lifecycle",
                    "test_postgres_integration",
                    "test_postgres_ledger_scan_filter",
                    "test_api_surface_0943",
                    "test_read_path_compliance_hub",
                    "test_delta_stream",
                    "test_report_jobs",
                    "test_finding_cursor",
                    "test_overview_cve_counts",
                    "test_finding_lifecycle",
                    "test_reconcile_absent_chunking",
                    "test_bounded_retention_window",
                    "test_audit_followup_post3624",
                    "test_overview",
                }
                or candidate.stem.startswith(
                    ("test_hub_", "test_compliance_hub", "test_storage_sql", "test_tenant_quota_store", "test_tenant_graph_retention_store")
                )
            )
        if normalized.as_posix() in {
            "src/agent_bom/api/store.py",
            "src/agent_bom/api/stores.py",
            "src/agent_bom/api/postgres_job_store.py",
            "src/agent_bom/api/scan_queue.py",
            "src/agent_bom/api/storage/jobs.py",
            "src/agent_bom/api/storage/job_cache.py",
            "src/agent_bom/api/storage/jobs_schema.py",
        }:
            selected.update(
                candidate
                for candidate in available
                if any(
                    word in candidate.stem
                    for word in (
                        "job",
                        "scan",
                        "overview",
                        "posture",
                        "batch",
                        "store",
                        "distributed",
                        "ingest",
                        "reconcil",
                        "hardening",
                        "lifecycle",
                        "correlation",
                        "tenant",
                    )
                )
            )
        if normalized.as_posix().startswith("src/agent_bom/db/graph_") or normalized.as_posix() in {
            "src/agent_bom/api/graph_store.py",
            "src/agent_bom/storage/sqlite_wal.py",
        }:
            selected.update(
                root / "tests" / name
                for name in (
                    "test_graph_wal_startup.py",
                    "test_graph_writer_admission.py",
                    "test_graph_bootstrap_cost.py",
                    "test_graph_initialization_lock.py",
                    "test_graph_store_streamed_persistence.py",
                )
                if root / "tests" / name in available
            )
        if normalized.as_posix() in GRAPH_PROJECTION_SOURCES:
            selected.update(
                candidate for candidate in available if "graph" in candidate.stem or candidate.stem == "test_runtime_incident_feedback"
            )
        if (
            normalized.as_posix().startswith("src/agent_bom/mcp_tools/")
            or normalized.as_posix().startswith("src/agent_bom/mcp_server")
            or normalized.as_posix() == "src/agent_bom/mcp_strict_args.py"
        ):
            selected.update(root / path for path in MCP_TOOL_CONTRACTS if root / path in available)
        if normalized.as_posix() in AUTHORIZATION_SOURCES or normalized.as_posix().startswith("src/agent_bom/api/routes/"):
            selected.update(root / path for path in AUTHORIZATION_CONTRACTS if root / path in available)
        if normalized.as_posix() in {
            "src/agent_bom/api/delegation_token.py",
            "src/agent_bom/api/delegation_service.py",
            "src/agent_bom/api/agent_identity_store.py",
            "src/agent_bom/api/identity_grants.py",
            "src/agent_bom/api/identity_policies.py",
            "src/agent_bom/api/postgres_agent_identity.py",
            "src/agent_bom/api/routes/identities.py",
        }:
            selected.update(
                root / path
                for path in (
                    "tests/test_delegation_identity_authority.py",
                    "tests/test_governance_abac_delegation.py",
                    "tests/test_agent_identity_lifecycle.py",
                    "tests/test_identity_governance_3687.py",
                    "tests/test_jit_grant_tenant_boundary.py",
                    "tests/test_identity_policy_tenant_boundary.py",
                    "tests/test_device_posture.py",
                    "tests/test_nhi_lifecycle_enforcement.py",
                    "tests/test_durable_store_default.py",
                    "tests/test_graph_governance_overlay.py",
                )
                if root / path in available
            )
        if normalized.as_posix() == "src/agent_bom/api/tenant_worker.py":
            selected.update(
                candidate
                for candidate in available
                if candidate.stem.startswith(
                    (
                        "test_report_",
                        "test_api_scan_worker_",
                        "test_distributed_scan_queue",
                        "test_exports_api",
                        "test_connection_scheduler",
                        "test_side_scan_scheduler",
                        "test_auto_correlation_scheduler",
                        "test_scan_jobs_active_gauge",
                        "test_graph_persistence",
                    )
                )
            )
        if normalized.as_posix().startswith(
            ("src/agent_bom/gateway", "src/agent_bom/runtime/gateway_", "src/agent_bom/api/gateway_")
        ) or normalized.as_posix() in {"src/agent_bom/runtime/trace_metadata.py", "src/agent_bom/runtime/risk_conditions.py"}:
            selected.update(candidate for candidate in available if candidate.stem.startswith(("test_gateway", "test_api_gateway")))
        if normalized.as_posix() in {"src/agent_bom/runtime/trace_metadata.py", "src/agent_bom/runtime/risk_conditions.py"}:
            selected.update(candidate for candidate in available if candidate.stem.startswith("test_proxy"))
        if normalized.as_posix() in SHARED_JUDGMENT_SOURCES:
            selected.update(candidate for candidate in available if candidate.stem.startswith(SHARED_JUDGMENT_PREFIXES))
        if normalized.as_posix() in {
            "src/agent_bom/api/inventory_service.py",
            "src/agent_bom/api/routes/inventory_assets.py",
            "src/agent_bom/api/routes/graph.py",
            "src/agent_bom/api/neptune_graph.py",
        }:
            selected.update(candidate for candidate in available if candidate.name == "test_neptune_unsupported_501.py")
        direct = root / normalized
        if normalized.parts and normalized.parts[0] == "tests" and direct in available:
            selected.add(direct)

        if normalized.suffix != ".py" or normalized.name == "__init__.py":
            continue
        if not normalized.parts or normalized.parts[0] not in {"src", "scripts"}:
            continue

        expected = f"test_{normalized.stem}"
        selected.update(candidate for candidate in available if candidate.stem == expected or candidate.stem.startswith(f"{expected}_"))

    return sorted(selected)


def _display(path: Path, *, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    shard = subparsers.add_parser("shard", help="print one deterministic test shard")
    shard.add_argument("--index", type=int, required=True, help="zero-based shard index")
    shard.add_argument("--total", type=int, required=True, help="total shard count")
    shard.add_argument("--root", type=Path, default=Path("tests"), help="test root")

    targeted = subparsers.add_parser("targeted", help="print tests related to changed files")
    targeted.add_argument("--root", type=Path, default=Path("."), help="repository root")
    targeted.add_argument("changed_files", nargs="*", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    cwd = Path.cwd().resolve()
    if args.command == "shard":
        if args.index < 0 or args.index >= args.total:
            raise SystemExit(f"shard index {args.index} is outside 0..{args.total - 1}")
        files = discover_test_files(args.root.resolve())
        selected = plan_shards(files, total=args.total)[args.index]
    else:
        selected = select_targeted_tests(changed_files=args.changed_files, root=args.root.resolve())

    for path in selected:
        print(_display(path.resolve(), base=cwd))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
