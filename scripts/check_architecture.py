#!/usr/bin/env python3
"""Ratchet Python size/complexity and layering debt; enforce hard layer boundaries.

Hard rules (always zero): core imports only core, api/ never imports the CLI,
plus the targeted service boundaries in ``boundary_errors``.

Ratcheted per file (existing counts may only shrink, new files start at zero):
``graph_api_imports`` (graph/ -> api), ``api_imports`` (any other non-api
module -> api), ``deferred_imports`` (imports inside function bodies, not
counting optional-extra SDKs that must stay lazy) and ``raw_env_reads``
(``os.environ.get`` / ``os.getenv`` / ``os.environ[...]`` reads outside the
typed settings owners in ``SETTINGS_OWNERS``).

``broad_except`` counts, per file, every ``except Exception``, ``except
BaseException`` and bare ``except:`` handler (including tuples that contain
one), whether the handler swallows, logs or re-raises: the count is the
handler, not its body. Like import debt it is budgeted repo-wide, so splitting
a module can move handlers into new files, but the total may only shrink and
any new broad handler must be paid for by removing one. A handler that genuinely must be broad (a plugin boundary, a top-level
worker loop) carries ``# broad-except: <reason>`` on its ``except`` line and is
not counted; at most ``MAX_ANNOTATED_BROAD_EXCEPTS`` per file, and the reason
must be a real sentence fragment, so the marker cannot become a blanket waiver.
Upstream failures belong in ``agent_bom.core.errors`` types instead.

The import-graph contract (domain modules never import upward, no module-level
cycle, the largest runtime SCC only shrinks) lives in ``check_import_graph.py``
and runs as part of this check.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

try:
    from scripts.check_import_graph import check as check_import_graph
except ModuleNotFoundError:  # run as ``python scripts/check_architecture.py``
    from check_import_graph import check as check_import_graph

LIMITS = {
    "file_lines": 600,
    "function_lines": 80,
    "complexity": 15,
    "deferred_imports": 0,
    "api_imports": 0,
    "graph_api_imports": 0,
    "raw_env_reads": 0,
    "broad_except": 0,
}
SETTINGS_OWNERS = frozenset({"config.py", "core/settings.py"})
MAX_ANNOTATED_BROAD_EXCEPTS = 3
BROAD_EXCEPT_MARKER = re.compile(r"#\s*broad-except:\s*(?P<reason>\S.*)$")
_BROAD_EXCEPTION_NAMES = frozenset({"Exception", "BaseException"})
# Top-level import names that ship only in optional extras (pyproject
# optional-dependencies) or are probed at runtime. Importing them inside a
# function keeps a base install working, so they do not count as deferred debt.
OPTIONAL_EXTRA_MODULES = frozenset(
    {
        "PIL",
        "aiohttp",
        "alembic",
        "azure",
        "boto3",
        "botocore",
        "databricks",
        "dotenv",
        "fastapi",
        "google",
        "googleapiclient",
        "gremlin_python",
        "huggingface_hub",
        "litellm",
        "mlflow",
        "networkx",
        "numpy",
        "onelogin",
        "openai",
        "opentelemetry",
        "prompt_toolkit",
        "psycopg",
        "psycopg_pool",
        "pyarrow",
        "pyiceberg",
        "pytesseract",
        "scipy",
        "smithery",
        "snowflake",
        "sqlalchemy",
        "sse_starlette",
        "starlette",
        "uvicorn",
        "wandb",
        "watchdog",
        "zstandard",
    }
)
BASELINE = Path("scripts/architecture-baseline.json")
OWNED_FUNCTIONS = {
    "require_explicit_tenant_id": "core/tenancy.py",
    "tenant_bound_context": "api/tenant_worker.py",
    "normalize_severity": "core/severity.py",
    "severity_display_bucket": "core/severity.py",
    "severity_policy_rank": "core/severity.py",
    "cvss_to_severity": "core/cvss.py",
    "parse_cvss_vector": "core/cvss.py",
    "normalize_package_name": "core/packages.py",
    "canonical_package_identity": "core/packages.py",
    "canonical_package_key": "core/packages.py",
    "encode_go_module_path": "core/packages.py",
    "_go_encode_module": "core/packages.py",
    "evaluated_control_status": "core/severity.py",
    "parse_identity_timestamp": "core/timestamps.py",
    "normalize_version": "core/versions/validation.py",
    "compare_version_order": "core/versions/ordering.py",
    "classify_credential_record": "core/credential_policy.py",
    "credential_governance_summary": "core/credential_policy.py",
    "build_control_plane_audit_sink": "runtime/gateway_audit.py",
    "build_local_gateway_audit_sink": "runtime/gateway_audit_local.py",
    "inject_jsonrpc_trace_meta": "runtime/trace_metadata.py",
    "_authenticate_gateway_request": "api/gateway_auth.py",
    "_request_groups": "api/gateway_request.py",
    "_build_gateway_rate_limit_store": "api/gateway_rate_limit.py",
    "_evaluate_control_plane_bundle": "api/gateway_policy.py",
    "_conditional_access_fail_closed": "api/gateway_policy.py",
    "_open_drift_violates_tool": "api/gateway_policy.py",
    "_package_evidence": "graph/package_projection.py",
    "project_agents": "graph/agent_projection.py",
    "project_credentials": "graph/credential_projection.py",
    "project_blast_radius": "graph/blast_projection.py",
    "project_benchmarks": "graph/benchmark_projection.py",
    "apply_build_analysis": "graph/build_analysis.py",
    "_resolve_cloud_resource_node_id": "graph/resource_aliases.py",
    "_model_node_id": "graph/training_projection.py",
    "_resolve_skill_audit_target_ids": "graph/finding_projection.py",
    "_resolve_affected_server_ids": "graph/package_projection.py",
    "_add_agentic_identity_graph_projections": "graph/runtime_projection.py",
    "_add_runtime_incident_feedback": "graph/runtime_projection.py",
    "_agent_node_id": "graph/projection_support.py",
    "evaluate_risk_conditions": "runtime/risk_conditions.py",
    "authorized_context_headers": "api/gateway_context.py",
    "forward_authorized_request": "api/gateway_forward.py",
}

TENANT_DISPATCH_ADAPTERS = frozenset(
    f"api/{name}.py"
    for name in (
        "auto_correlation",
        "connection_scheduler",
        "graph_persistence",
        "scan_job_reconciliation",
        "scheduler",
        "side_scan_scheduler",
    )
)


def function_spans(tree: ast.AST, prefix: str = "") -> list[tuple[str, int, int]]:
    result = []
    for node in ast.iter_child_nodes(tree):
        name = getattr(node, "name", None)
        qualified = f"{prefix}.{name}".strip(".") if name else prefix
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result.append((qualified, node.lineno, node.end_lineno or node.lineno))
        result.extend(function_spans(node, qualified))
    return result


def _import_modules(path: str, node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if not isinstance(node, ast.ImportFrom):
        return []
    module = node.module or ""
    if node.level:
        package = ["agent_bom", *Path(path).parts[:-1]]
        module = ".".join([*package[: len(package) - node.level + 1], module]).rstrip(".")
    return [module, *(f"{module}.{alias.name}" for alias in node.names)]


def _imports_package(modules: list[str], package: str) -> bool:
    return any(module == package or module.startswith(f"{package}.") for module in modules)


def _counts_as_deferred(node: ast.Import | ast.ImportFrom) -> bool:
    if isinstance(node, ast.ImportFrom):
        return bool(node.level) or (node.module or "").split(".")[0] not in OPTIONAL_EXTRA_MODULES
    return any(alias.name.split(".")[0] not in OPTIONAL_EXTRA_MODULES for alias in node.names)


def _import_statements(statements: list[ast.stmt], in_function: bool = False) -> Iterator[tuple[ast.Import | ast.ImportFrom, bool]]:
    # Imports are statements, so only statement bodies are walked, not expressions.
    for statement in statements:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            yield statement, in_function
            continue
        nested = in_function or isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        blocks = [getattr(statement, field, None) for field in ("body", "orelse", "finalbody")]
        blocks += [child.body for child in [*getattr(statement, "handlers", []), *getattr(statement, "cases", [])]]
        for block in blocks:
            if isinstance(block, list):
                yield from _import_statements(block, nested)


def layer_metrics(path: str, tree: ast.Module) -> dict[str, int]:
    """Per-file layering debt, counted in import statements."""
    metric = "graph_api_imports" if path.startswith("graph/") else "api_imports"
    metrics = {"deferred_imports": 0, metric: 0}
    for node, in_function in _import_statements(tree.body):
        metrics["deferred_imports"] += in_function and _counts_as_deferred(node)
        metrics[metric] += not path.startswith("api/") and _imports_package(_import_modules(path, node), "agent_bom.api")
    return {name: value for name, value in metrics.items() if value}


def raw_env_reads(path: str, tree: ast.Module) -> int:
    """Reads of the process environment that bypass the typed settings layer."""
    if path in SETTINGS_OWNERS:
        return 0
    os_names: set[str] = set()
    environ_names: set[str] = set()
    getenv_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            os_names.update(alias.asname or "os" for alias in node.names if alias.name == "os")
        elif isinstance(node, ast.ImportFrom) and node.module == "os" and not node.level:
            environ_names.update(alias.asname or alias.name for alias in node.names if alias.name == "environ")
            getenv_names.update(alias.asname or alias.name for alias in node.names if alias.name == "getenv")

    def is_os(expr: ast.expr) -> bool:
        return isinstance(expr, ast.Name) and expr.id in os_names

    def is_environ(expr: ast.expr) -> bool:
        if isinstance(expr, ast.Name):
            return expr.id in environ_names
        return isinstance(expr, ast.Attribute) and expr.attr == "environ" and is_os(expr.value)

    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            count += (
                isinstance(func, ast.Attribute)
                and ((func.attr == "get" and is_environ(func.value)) or (func.attr == "getenv" and is_os(func.value)))
            ) or (isinstance(func, ast.Name) and func.id in getenv_names)
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            count += is_environ(node.value)
    return count


def _is_broad_handler(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    names = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(isinstance(name, ast.Name) and name.id in _BROAD_EXCEPTION_NAMES for name in names)


def broad_except_counts(tree: ast.AST, lines: list[str]) -> tuple[int, int]:
    """Return ``(unannotated, annotated)`` broad exception handlers in a module."""
    unannotated = annotated = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler) or not _is_broad_handler(node):
            continue
        marker = BROAD_EXCEPT_MARKER.search(lines[node.lineno - 1]) if node.lineno <= len(lines) else None
        if marker and len(marker.group("reason").strip()) >= 10:
            annotated += 1
        else:
            unannotated += 1
    return unannotated, annotated


def boundary_errors(path: str, tree: ast.AST) -> list[str]:
    errors = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if path in {"core/credential_policy.py", "graph/nhi_governance.py"} and node.name == "_parse_timestamp":
                errors.append(f"{path}:{line}: identity timestamp parsing belongs in core/timestamps.py")
            if path == "output/compliance_narrative.py" and node.name == "_control_status":
                errors.append(f"{path}:{line}: mapped-finding status belongs in core/severity.py")
            owner = OWNED_FUNCTIONS.get(node.name)
            if owner and path != owner:
                errors.append(f"{path}:{line}: {node.name} belongs in {owner}")
        if isinstance(node, ast.ClassDef) and node.name == "GraphStoreProtocol" and path != "graph/ports.py":
            errors.append(f"{path}:{line}: GraphStoreProtocol belongs in graph/ports.py")
        modules = _import_modules(path, node)
        if path.startswith("api/") and _imports_package(modules, "agent_bom.cli"):
            errors.append(f"{path}:{line}: api must not import the CLI; move shared logic below both layers")
        for module in modules:
            if path.startswith("mcp_tools/operator/") and module in {"agent_bom.mcp_server", "agent_bom.mcp_server_operator_tools"}:
                errors.append(f"{path}:{line}: operator registrations must receive server bindings")
            if path in TENANT_DISPATCH_ADAPTERS and module.rsplit(".", 1)[-1] in {"set_current_tenant", "reset_current_tenant"}:
                errors.append(f"{path}:{line}: tenant dispatch must use api/tenant_worker.py to suspend maintenance authority")
            if path == "runtime/risk_conditions.py" and (
                module == "agent_bom.proxy_policy" or module == "agent_bom.api" or module.startswith("agent_bom.api.")
            ):
                errors.append(f"{path}:{line}: risk conditions must not import policy orchestration or API adapters")
            if path.startswith(("runtime/gateway_", "api/gateway_")) and module == "agent_bom.gateway_server":
                errors.append(f"{path}:{line}: gateway services must not import their HTTP composition root")
            if path == "runtime/gateway_relay.py" and (
                module == "agent_bom.gateway_server" or module == "agent_bom.api" or module.startswith("agent_bom.api.")
            ):
                errors.append(f"{path}:{line}: upstream relay must not import HTTP application or API adapters")
            if path == "runtime/gateway_policy_reload.py" and (
                module == "agent_bom.api" or module.startswith("agent_bom.api.") or module == "agent_bom.gateway_server"
            ):
                errors.append(f"{path}:{line}: policy reload state must receive adapters through typed callables")

            if path in {"graph/ports.py", "graph/correlation_service.py"} and (
                module == "agent_bom.api"
                or module.startswith("agent_bom.api.")
                or module == "agent_bom.db"
                or module.startswith("agent_bom.db.")
            ):
                errors.append(f"{path}:{line}: graph services and ports must not import storage adapters")
            if path in {
                "graph/package_projection.py",
                "graph/runtime_projection.py",
                "graph/projection_support.py",
                "graph/agent_projection.py",
                "graph/credential_projection.py",
                "graph/blast_projection.py",
                "graph/benchmark_projection.py",
                "graph/finding_projection.py",
                "graph/training_projection.py",
                "graph/resource_aliases.py",
                "graph/build_indexes.py",
                "graph/build_input.py",
                "graph/build_analysis.py",
            } and (module == "agent_bom.graph.builder" or module == "agent_bom.api" or module.startswith("agent_bom.api.")):
                errors.append(f"{path}:{line}: report projections must not import builder orchestration or API adapters")
            if path == "api/graph_persistence.py" and module in {
                "agent_bom.api.pipeline",
                "agent_bom.api.server",
                "agent_bom.api.stores",
            }:
                errors.append(f"{path}:{line}: graph persistence must receive its store factory, not import orchestration")
            if path.startswith("graph/") and module == "agent_bom.api.credential_expiry":
                errors.append(f"{path}:{line}: graph credential decisions must not import the API adapter")
            if path.startswith("core/") and (
                module == "agent_bom"
                or (module.startswith("agent_bom.") and module != "agent_bom.core" and not module.startswith("agent_bom.core."))
            ):
                errors.append(f"{path}:{line}: core must not depend on {module}")
    return errors


def measure(root: Path) -> tuple[dict[str, dict[str, int]], list[str]]:
    source = root / "src" / "agent_bom"
    metrics: dict[str, dict[str, int]] = {}
    errors = []
    locations: dict[tuple[str, int], str] = {}
    # The source tree contains no generated Python modules; browser bundles and
    # generated JSON/schema/SDK artifacts are outside this Python-only gate.
    for path in sorted(source.rglob("*.py")):
        relative = path.relative_to(source).as_posix()
        text = path.read_text()
        tree = ast.parse(text, filename=str(path))
        lines = text.splitlines()
        metrics[relative] = {"file_lines": len(lines), **layer_metrics(relative, tree)}
        broad, annotated = broad_except_counts(tree, lines)
        if broad:
            metrics[relative]["broad_except"] = broad
        if annotated > MAX_ANNOTATED_BROAD_EXCEPTS:
            errors.append(f"{relative}: {annotated} '# broad-except:' handlers exceed {MAX_ANNOTATED_BROAD_EXCEPTS}; catch specific errors")
        if env_reads := raw_env_reads(relative, tree):
            metrics[relative]["raw_env_reads"] = env_reads
        errors.extend(boundary_errors(relative, tree))
        for name, start, end in function_spans(tree):
            key = f"{relative}::{name}"
            metrics[key] = {"function_lines": end - start + 1}
            locations[(str(path.resolve()), start)] = key
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--select",
            "C901",
            "--ignore-noqa",
            "--config",
            "lint.mccabe.max-complexity=15",
            "--output-format",
            "json",
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if run.returncode not in (0, 1):
        raise RuntimeError("Ruff complexity measurement failed")
    for item in json.loads(run.stdout):
        match = re.search(r"\((\d+) > \d+\)", item["message"])
        if not match:
            raise RuntimeError("Unrecognized Ruff complexity diagnostic")
        key = locations[(item["filename"], item["location"]["row"])]
        metrics[key]["complexity"] = int(match.group(1))
    return metrics, errors


# Import-direction debt is budgeted per category, not per file, so splitting a
# large module can move its imports into new files without growing the total.
BUDGETED_METRICS = frozenset({"deferred_imports", "api_imports", "graph_api_imports", "broad_except"})


def regressions(metrics: dict[str, dict[str, int]], baseline: dict[str, dict[str, int]]) -> list[str]:
    errors = [
        f"{key}: {metric} {value} exceeds {max(LIMITS[metric], baseline.get(key, {}).get(metric, 0))}"
        for key, values in metrics.items()
        for metric, value in values.items()
        if metric not in BUDGETED_METRICS and value > max(LIMITS[metric], baseline.get(key, {}).get(metric, 0))
    ]
    for metric in sorted(BUDGETED_METRICS):
        total = sum(values.get(metric, 0) for values in metrics.values())
        budget = sum(values.get(metric, 0) for values in baseline.values())
        if total > budget:
            errors.append(f"{metric}: total {total} exceeds budget {budget}")
    return errors


def debt(metrics: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    return {
        key: {metric: value for metric, value in values.items() if value > LIMITS[metric]}
        for key, values in metrics.items()
        if any(value > LIMITS[metric] for metric, value in values.items())
    }


def baseline_growth(
    current: dict[str, dict[str, int]],
    previous: dict[str, dict[str, int]],
    ratcheted_metrics: set[str] | None = None,
) -> list[str]:
    """An edited allowance cannot bypass the source ratchet.

    A metric missing from the trusted baseline's ``limits`` is a category being
    introduced: it is recorded once at today's values and ratchets afterwards.
    """
    if ratcheted_metrics is not None:
        current = restrict_metrics(current, ratcheted_metrics)
    return regressions(current, previous)


def restrict_metrics(metrics: dict[str, dict[str, int]], names: set[str]) -> dict[str, dict[str, int]]:
    return {
        key: kept for key, values in metrics.items() if (kept := {metric: value for metric, value in values.items() if metric in names})
    }


def trusted_baseline(root: Path, ref: str) -> dict | None:
    # A missing commit is an error; a missing file permits the initial rollout.
    subprocess.run(["git", "cat-file", "-e", f"{ref}^{{commit}}"], cwd=root, check=True, capture_output=True)
    exists = subprocess.run(["git", "cat-file", "-e", f"{ref}:{BASELINE.as_posix()}"], cwd=root, capture_output=True)
    if exists.returncode:
        return None
    content = subprocess.check_output(["git", "show", f"{ref}:{BASELINE.as_posix()}"], cwd=root, text=True)
    return json.loads(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-baseline", action="store_true", help="record initial debt or ratchet it downward; never approve growth")
    parser.add_argument("--base-ref", help="trusted base commit used to reject increased baseline allowances")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    path = root / BASELINE
    metrics, errors = measure(root)
    if path.exists():
        stored = json.loads(path.read_text())
        baseline = stored["debt"]
        # Writing may record a category the stored baseline has never tracked;
        # every category it already tracks still has to hold its ratchet.
        checked = restrict_metrics(metrics, set(stored.get("limits", LIMITS))) if args.write_baseline else metrics
        errors.extend(regressions(checked, baseline))
        if args.base_ref:
            previous = trusted_baseline(root, args.base_ref)
            if previous is not None:
                errors.extend(baseline_growth(baseline, previous["debt"], set(previous.get("limits", {}))))
    elif not args.write_baseline:
        errors.append("Architecture baseline missing; initialize with --write-baseline")
    graph_errors, graph = check_import_graph(root, args.base_ref, args.write_baseline)
    errors.extend(graph_errors)
    if errors:
        print("\n".join(errors))
        return 1
    if args.write_baseline:
        path.write_text(json.dumps({"limits": LIMITS, "debt": debt(metrics)}, indent=2, sort_keys=True) + "\n")
    print(
        f"Architecture boundaries and ratchet passed ({len(debt(metrics))} existing debt entries; "
        f"largest import SCC {graph['max_scc']} of {graph['modules']} modules)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
