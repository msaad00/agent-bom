"""Versioned, repository-grounded cloud benchmark implementation manifests.

Official benchmark denominators are intentionally unset until a licensed or
otherwise authoritative control catalog is checked into the repository. The
implemented counts below are tied to the named code registries; they are not
coverage percentages.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path
from typing import Any, Final

MANIFEST_SCHEMA_VERSION: Final = 1


def _manifest(
    *,
    name: str,
    version: str,
    benchmark_type: str,
    registry: str,
    control_ids: tuple[str, ...],
    authoritative_source: str,
    manual_control_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "benchmark_name": name,
        "benchmark_version": version,
        "benchmark_type": benchmark_type,
        "implemented_control_count": len(control_ids),
        "implementation_registry": registry,
        "authoritative_source": authoritative_source,
        "authoritative_source_version": version,
        "authoritative_source_access": "reference_url_only",
        "authoritative_catalog_repository_provenance": False,
        "automated_control_ids": sorted(set(control_ids) - set(manual_control_ids)),
        "manual_control_ids": list(manual_control_ids),
        "unsupported_control_ids": None,
        "unsupported_control_ids_reason": "Unknown until an authoritative versioned control catalog is repository-provenanced.",
        "official_control_count": None,
        "coverage_percentage": None,
        "coverage_note": "Official denominator not repository-provenanced; percentage intentionally unpublished.",
    }


def _registry_ids(filename: str, *variables: str) -> tuple[str, ...]:
    """Read the explicit check-function registries into stable control IDs."""
    tree = ast.parse((Path(__file__).with_name(filename)).read_text())
    ids: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            if node.value is None:
                continue
            value = node.value
        else:
            continue
        if not any(isinstance(item, ast.Name) and item.id in variables for item in targets):
            continue
        if not isinstance(value, (ast.List, ast.Tuple)):
            continue
        for item in value.elts:
            if isinstance(item, ast.Tuple) and any(isinstance(target, ast.Name) and target.id == "all_checks" for target in targets):
                check_id = item.elts[0]
                if isinstance(check_id, ast.Constant) and isinstance(check_id.value, str):
                    ids.append(check_id.value)
                continue
            fn = item.elts[1] if isinstance(item, ast.Tuple) else item
            if isinstance(fn, ast.Name) and fn.id.startswith("_check_"):
                ids.append(fn.id.removeprefix("_check_").replace("_", "."))
    return tuple(ids)


CLOUD_BENCHMARK_MANIFESTS: Final[dict[str, dict[str, Any]]] = {
    "aws": _manifest(
        name="CIS AWS Foundations",
        version="3.0",
        benchmark_type="cis",
        registry="agent_bom.cloud.aws_cis_benchmark:_CHECKS+_SPECIAL_CHECKS",
        control_ids=_registry_ids("aws_cis_benchmark.py", "_CHECKS", "_SPECIAL_CHECKS"),
        authoritative_source="https://www.cisecurity.org/benchmark/amazon_web_services",
        manual_control_ids=("1.3",),
    ),
    "gcp": _manifest(
        name="CIS Google Cloud Platform Foundation",
        version="3.0",
        benchmark_type="cis",
        registry="agent_bom.cloud.gcp_cis_benchmark:run_benchmark.all_checks",
        control_ids=_registry_ids("gcp_cis_benchmark.py", "all_checks"),
        authoritative_source="https://www.cisecurity.org/benchmark/google_cloud_computing_platform",
        manual_control_ids=("1.2", "1.3"),
    ),
    "azure": _manifest(
        name="CIS Microsoft Azure Foundations",
        version="3.0",
        benchmark_type="cis",
        registry="agent_bom.cloud.azure_cis_benchmark:run_benchmark.all_checks",
        control_ids=_registry_ids("azure_cis_benchmark.py", "all_checks"),
        authoritative_source="https://www.cisecurity.org/benchmark/azure",
        manual_control_ids=(
            "1.3",
            "1.4",
            "1.6",
            "1.8",
            "1.9",
            "1.10",
            "1.11",
            "1.12",
            "1.13",
            "1.14",
            "1.16",
            "1.17",
            "1.18",
            "1.19",
            "1.20",
            "1.21",
            "1.22",
        ),
    ),
    "snowflake": _manifest(
        name="CIS Snowflake Foundations",
        version="1.0",
        benchmark_type="cis",
        registry="agent_bom.cloud.snowflake_cis_benchmark:run_benchmark.all_checks",
        control_ids=_registry_ids("snowflake_cis_benchmark.py", "all_checks"),
        authoritative_source="https://www.cisecurity.org/benchmark/snowflake",
    ),
    "databricks": _manifest(
        name="Databricks Security Best Practices",
        version="1.0",
        benchmark_type="vendor_best_practices",
        registry="agent_bom.cloud.databricks_security:_ALL_CHECKS",
        control_ids=_registry_ids("databricks_security.py", "_ALL_CHECKS"),
        authoritative_source="https://docs.databricks.com/en/security/index.html",
    ),
}


def benchmark_manifest(provider: str) -> dict[str, Any]:
    """Return an independent manifest safe to expose in report JSON."""
    return deepcopy(CLOUD_BENCHMARK_MANIFESTS[provider])
