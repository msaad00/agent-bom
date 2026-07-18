"""Import-contract tests for evacuated CLI agents and scanners init modules."""

from __future__ import annotations

import importlib
import inspect

import pytest

AGENTS_PATCH_TARGETS = (
    "discover_all",
    "emit_dry_run_plan",
    "extract_packages",
    "resolve_all_versions_sync",
    "scan",
    "scan_agents_sync",
)

AGENTS_PUBLIC_HELPERS = (
    "_build_self_scan_inventory",
    "_expand_docker_mcp_packages",
)

SCANNERS_PUBLIC_SYMBOLS = (
    "BATCH_DELAY_SECONDS",
    "ECOSYSTEM_MAP",
    "IncompleteScanError",
    "MAX_CONCURRENT_REQUESTS",
    "ScanOptions",
    "ScannerExecutionState",
    "ScannerFailureMode",
    "ScannerPhase",
    "ScannerRegistration",
    "_AI_FRAMEWORK_PACKAGES",
    "_HOP_RISK_FACTORS",
    "_NON_OSV_ECOSYSTEMS",
    "_bump_scan_perf",
    "_db_covered_ecosystems",
    "_db_ecosystems_for_package",
    "_enrich_results_if_needed",
    "_get_api_semaphore",
    "_get_scan_cache",
    "_include_unfixed_enabled",
    "_is_valid_fix_version",
    "_is_version_affected",
    "_local_vuln_to_vulnerability",
    "_osv_ecosystems_for_package",
    "_parse_cvss4_vector",
    "_scan_packages_db_conn",
    "_scan_packages_local_db",
    "_strip_extras",
    "_suppress_unfixed_os_advisories",
    "advisory_id_severity_fallback",
    "build_vulnerabilities",
    "builtin_scanner_registrations",
    "compliance_mode",
    "create_client",
    "consume_scan_performance",
    "consume_scan_warnings",
    "cvss_to_severity",
    "deduplicate_packages",
    "default_scan_options",
    "expand_blast_radius_hops",
    "get_scanner_registration",
    "list_registered_scanners",
    "offline_mode",
    "parse_cvss_vector",
    "parse_fixed_version",
    "parse_osv_severity",
    "prefer_local_db",
    "query_osv_batch",
    "record_coverage_warning",
    "record_scan_warning",
    "register_scanner",
    "request_with_retry",
    "reset_scan_performance",
    "reset_scan_warnings",
    "scan_agents",
    "scan_agents_sync",
    "scan_agents_with_enrichment",
    "scan_packages",
    "scanner_registry_summary",
    "scanner_registry_warnings",
    "set_include_unfixed",
    "set_offline_mode",
    "severity_from_label",
)


@pytest.mark.parametrize("symbol", AGENTS_PATCH_TARGETS + AGENTS_PUBLIC_HELPERS)
def test_cli_agents_init_exports_patch_and_public_symbols(symbol: str) -> None:
    agents = importlib.import_module("agent_bom.cli.agents")
    assert hasattr(agents, symbol), f"missing agent_bom.cli.agents.{symbol}"


@pytest.mark.parametrize("symbol", SCANNERS_PUBLIC_SYMBOLS)
def test_scanners_init_exports_public_symbols(symbol: str) -> None:
    scanners = importlib.import_module("agent_bom.scanners")
    assert hasattr(scanners, symbol), f"missing agent_bom.scanners.{symbol}"


def test_cli_agents_init_is_reexport_only() -> None:
    agents_init = importlib.import_module("agent_bom.cli.agents")
    scan_cmd = importlib.import_module("agent_bom.cli.agents.scan_cmd")

    assert agents_init.scan is scan_cmd.scan
    assert agents_init.scan.callback is scan_cmd.scan.callback
    assert inspect.getsourcefile(agents_init.scan.callback) == inspect.getsourcefile(scan_cmd.scan.callback)


def test_scanners_init_is_reexport_only() -> None:
    scanners = importlib.import_module("agent_bom.scanners")
    package_scan = importlib.import_module("agent_bom.scanners.package_scan")

    assert scanners.scan_packages is package_scan.scan_packages
    assert scanners.ECOSYSTEM_MAP is package_scan.ECOSYSTEM_MAP
    assert inspect.getsourcefile(scanners.scan_packages) == inspect.getsourcefile(package_scan.scan_packages)
