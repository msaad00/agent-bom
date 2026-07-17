import ast
from pathlib import Path

from agent_bom.cloud.aws_cis_benchmark import CISBenchmarkReport
from agent_bom.cloud.azure_cis_benchmark import AzureCISReport
from agent_bom.cloud.benchmark_manifests import CLOUD_BENCHMARK_MANIFESTS, MANIFEST_SCHEMA_VERSION
from agent_bom.cloud.databricks_security import DatabricksSecurityReport
from agent_bom.cloud.gcp_cis_benchmark import GCPCISReport
from agent_bom.cloud.snowflake_cis_benchmark import SnowflakeCISReport

ROOT = Path(__file__).parent.parent / "src" / "agent_bom" / "cloud"


def _registry_count(filename: str, variable: str) -> int:
    tree = ast.parse((ROOT / filename).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == variable:
            assert isinstance(node.value, (ast.List, ast.Tuple))
            return len(node.value.elts)
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == variable for target in node.targets):
            assert isinstance(node.value, (ast.List, ast.Tuple))
            return len(node.value.elts)
    raise AssertionError(f"registry {variable} not found in {filename}")


def test_provider_manifests_are_versioned_and_do_not_invent_denominators():
    assert MANIFEST_SCHEMA_VERSION == 1
    assert set(CLOUD_BENCHMARK_MANIFESTS) == {"aws", "azure", "gcp", "snowflake", "databricks"}
    for manifest in CLOUD_BENCHMARK_MANIFESTS.values():
        assert manifest["manifest_schema_version"] == 1
        assert manifest["implementation_registry"]
        assert manifest["authoritative_source"].startswith("https://")
        assert manifest["authoritative_source_version"] == manifest["benchmark_version"]
        assert manifest["authoritative_source_access"] == "reference_url_only"
        assert manifest["authoritative_catalog_repository_provenance"] is False
        assert set(manifest["automated_control_ids"]).isdisjoint(manifest["manual_control_ids"])
        assert len(manifest["automated_control_ids"]) + len(manifest["manual_control_ids"]) == manifest["implemented_control_count"]
        assert manifest["unsupported_control_ids"] is None
        assert "Unknown" in manifest["unsupported_control_ids_reason"]
        assert manifest["official_control_count"] is None
        assert manifest["coverage_percentage"] is None


def test_databricks_manifest_is_vendor_best_practices_not_cis():
    manifest = CLOUD_BENCHMARK_MANIFESTS["databricks"]
    assert manifest["benchmark_type"] == "vendor_best_practices"
    assert "CIS" not in manifest["benchmark_name"]


def test_active_operator_surfaces_do_not_describe_databricks_as_cis():
    repository = ROOT.parent.parent.parent
    surfaces = (
        repository / "docs" / "ARCHITECTURE.md",
        repository / "integrations" / "docker-mcp-registry" / "tools.json",
        repository / "ui" / "components" / "cis-benchmark-detail.tsx",
        repository / "ui" / "components" / "framework-coverage-panel.tsx",
    )
    for surface in surfaces:
        text = surface.read_text()
        assert "CIS benchmark checks against a cloud account (AWS, Azure, GCP, Snowflake, Databricks)" not in text
        assert "AWS / Azure / GCP / Snowflake / Databricks checks behind CIS" not in text
        assert "Cloud CIS benchmarks (AWS / Azure / GCP / Snowflake / Databricks)" not in text


def test_implemented_counts_match_code_registries():
    counts = {
        "aws": _registry_count("aws_cis_benchmark.py", "_CHECKS") + _registry_count("aws_cis_benchmark.py", "_SPECIAL_CHECKS"),
        "gcp": _registry_count("gcp_cis_benchmark.py", "all_checks"),
        "azure": _registry_count("azure_cis_benchmark.py", "all_checks"),
        "snowflake": _registry_count("snowflake_cis_benchmark.py", "all_checks"),
        "databricks": _registry_count("databricks_security.py", "_ALL_CHECKS"),
    }
    assert counts == {provider: manifest["implemented_control_count"] for provider, manifest in CLOUD_BENCHMARK_MANIFESTS.items()}


def test_every_provider_report_exposes_manifest_and_unknown_denominator():
    reports = {
        "aws": CISBenchmarkReport(),
        "azure": AzureCISReport(),
        "gcp": GCPCISReport(),
        "snowflake": SnowflakeCISReport(),
        "databricks": DatabricksSecurityReport(),
    }
    for provider, report in reports.items():
        exposed = report.to_dict()["benchmark_manifest"]
        assert exposed == CLOUD_BENCHMARK_MANIFESTS[provider]
        assert exposed["official_control_count"] is None
        assert exposed["coverage_percentage"] is None
