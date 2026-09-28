#!/usr/bin/env python3
"""Ratchet Python size/complexity debt and enforce the shared-kernel boundary."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

LIMITS = {"file_lines": 600, "function_lines": 80, "complexity": 15}
BASELINE = Path("scripts/architecture-baseline.json")
OWNED_FUNCTIONS = {
    "require_explicit_tenant_id": "core/tenancy.py",
    "normalize_severity": "core/severity.py",
    "severity_display_bucket": "core/severity.py",
    "severity_policy_rank": "core/severity.py",
    "cvss_to_severity": "core/cvss.py",
    "parse_cvss_vector": "core/cvss.py",
    "normalize_package_name": "core/packages.py",
    "canonical_package_identity": "core/packages.py",
    "canonical_package_key": "core/packages.py",
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
}


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


def boundary_errors(path: str, tree: ast.AST) -> list[str]:
    errors = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            owner = OWNED_FUNCTIONS.get(node.name)
            if owner and path != owner:
                errors.append(f"{path}:{node.lineno}: {node.name} belongs in {owner}")
        for module in _import_modules(path, node):
            if path.startswith(("runtime/gateway_", "api/gateway_")) and module == "agent_bom.gateway_server":
                errors.append(f"{path}:{node.lineno}: gateway services must not import their HTTP composition root")
            if path == "runtime/gateway_relay.py" and (
                module == "agent_bom.gateway_server" or module == "agent_bom.api" or module.startswith("agent_bom.api.")
            ):
                errors.append(f"{path}:{node.lineno}: upstream relay must not import HTTP application or API adapters")
            if path == "api/graph_persistence.py" and module in {
                "agent_bom.api.pipeline",
                "agent_bom.api.server",
                "agent_bom.api.stores",
            }:
                errors.append(f"{path}:{node.lineno}: graph persistence must receive its store factory, not import orchestration")
            if path.startswith("graph/") and module == "agent_bom.api.credential_expiry":
                errors.append(f"{path}:{node.lineno}: graph credential decisions must not import the API adapter")
            if path.startswith("core/") and (
                module == "agent_bom"
                or (module.startswith("agent_bom.") and module != "agent_bom.core" and not module.startswith("agent_bom.core."))
            ):
                errors.append(f"{path}:{node.lineno}: core must not depend on {module}")
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
        metrics[relative] = {"file_lines": len(text.splitlines())}
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


def regressions(metrics: dict[str, dict[str, int]], baseline: dict[str, dict[str, int]]) -> list[str]:
    return [
        f"{key}: {metric} {value} exceeds {max(LIMITS[metric], baseline.get(key, {}).get(metric, 0))}"
        for key, values in metrics.items()
        for metric, value in values.items()
        if value > max(LIMITS[metric], baseline.get(key, {}).get(metric, 0))
    ]


def debt(metrics: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    return {
        key: {metric: value for metric, value in values.items() if value > LIMITS[metric]}
        for key, values in metrics.items()
        if any(value > LIMITS[metric] for metric, value in values.items())
    }


def baseline_growth(current: dict[str, dict[str, int]], previous: dict[str, dict[str, int]]) -> list[str]:
    """An edited allowance cannot bypass the source ratchet."""
    return regressions(current, previous)


def trusted_baseline(root: Path, ref: str) -> dict[str, dict[str, int]] | None:
    # A missing commit is an error; a missing file permits the initial rollout.
    subprocess.run(["git", "cat-file", "-e", f"{ref}^{{commit}}"], cwd=root, check=True, capture_output=True)
    exists = subprocess.run(["git", "cat-file", "-e", f"{ref}:{BASELINE.as_posix()}"], cwd=root, capture_output=True)
    if exists.returncode:
        return None
    content = subprocess.check_output(["git", "show", f"{ref}:{BASELINE.as_posix()}"], cwd=root, text=True)
    return json.loads(content)["debt"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-baseline", action="store_true", help="record initial debt or ratchet it downward; never approve growth")
    parser.add_argument("--base-ref", help="trusted base commit used to reject increased baseline allowances")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    path = root / BASELINE
    metrics, errors = measure(root)
    if path.exists():
        baseline = json.loads(path.read_text())["debt"]
        errors.extend(regressions(metrics, baseline))
        if args.base_ref:
            previous = trusted_baseline(root, args.base_ref)
            if previous is not None:
                errors.extend(baseline_growth(baseline, previous))
    elif not args.write_baseline:
        errors.append("Architecture baseline missing; initialize with --write-baseline")
    if errors:
        print("\n".join(errors))
        return 1
    if args.write_baseline:
        path.write_text(json.dumps({"limits": LIMITS, "debt": debt(metrics)}, indent=2, sort_keys=True) + "\n")
    print(f"Architecture boundaries and ratchet passed ({len(debt(metrics))} existing debt entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
