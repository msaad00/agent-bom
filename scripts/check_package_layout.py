#!/usr/bin/env python3
"""Freeze the flat top-level module set under src/agent_bom/*.py.

New modules must land in a package (api/, graph/, runtime/, cloud/, mcp_tools/,
etc.) — not as another peer of the historical flat namespace. This check snapshots
the allowlisted basenames so the landfill cannot grow silently.

Exit 0 when the tree matches the allowlist; exit 1 with a clear message otherwise.
The allowlist only shrinks: moving a legacy module into a package removes its
entry. ``docs/CODE_MAP.md`` tells contributors where new code goes.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "src" / "agent_bom"

# Snapshot of top-level basenames at introduction of this guard.
# To add a module: move it under a package instead, or (rare) update this list
# with an explicit PR rationale that the flat namespace is unavoidable.
ALLOWED_TOP_LEVEL_MODULES: frozenset[str] = frozenset(
    {
        "__init__.py",
        # Required at the package root for `python -m agent_bom`.
        "__main__.py",
        "a2a_auth_posture.py",
        "accuracy_baseline.py",
        "advisory_ids.py",
        "advisory_sources.py",
        "agent_identity.py",
        "agent_manifest.py",
        "ai_enrich.py",
        "ai_schemas.py",
        "analytics_contract.py",
        "analytics_retention.py",
        "asset_provenance.py",
        "asset_tracker.py",
        "ast_analyzer.py",
        "ast_csharp.py",
        "ast_go.py",
        "ast_java.py",
        "ast_js_ts.py",
        "ast_models.py",
        "ast_php.py",
        "ast_python_analysis.py",
        "ast_ruby.py",
        "ast_rust.py",
        "ast_signal_utils.py",
        "ast_source_mask.py",
        "ast_swift.py",
        "ast_symbol_reach_guards.py",
        "async_stdin.py",
        "atlas.py",
        "atlas_fetch.py",
        "audit_integrity.py",
        "audit_replay.py",
        "autodiscover.py",
        "backpressure.py",
        "baseline.py",
        "canonical_ids.py",
        "capabilities.py",
        "checksums.py",
        "ci_detect.py",
        "cis_controls.py",
        "client.py",
        "cloud_sdk_freshness.py",
        "cmmc.py",
        "compliance_coverage.py",
        "compliance_hub.py",
        "compliance_hub_ingest.py",
        "compliance_nist_catalog.py",
        "compliance_utils.py",
        "config.py",
        "constants.py",
        "context_graph.py",
        "correlate.py",
        "cost_model.py",
        "coverage.py",
        "cpe_match.py",
        "cross_env_correlation.py",
        "cwe_impact.py",
        "data_boundaries.py",
        "database_evidence.py",
        "delivery.py",
        "delta_stream.py",
        "demo.py",
        "demo_advisories.py",
        "deploy_k8s_cleanup.py",
        "deploy_profiles.py",
        "deploy_teardown.py",
        "deployment_probe.py",
        "deps_dev.py",
        "device_posture.py",
        "discovery_envelope.py",
        "ecosystems.py",
        "effective_reach.py",
        "endpoint_onboarding.py",
        "enforcement.py",
        "enrichment.py",
        "enrichment_posture.py",
        "entitlements.py",
        "eu_ai_act.py",
        "event_normalization.py",
        "exec_score.py",
        "exploitability.py",
        "extensions.py",
        "fedramp.py",
        "filesystem.py",
        "finding.py",
        "finding_runtime_evidence.py",
        "finding_scope.py",
        "findings_push.py",
        "firewall.py",
        "firewall_client.py",
        "fleet_scan.py",
        "floating_refs.py",
        "framework_catalog.py",
        "framework_mapping.py",
        "gateway.py",
        "gateway_policy_templates.py",
        "gateway_server.py",
        "gateway_upstreams.py",
        "github_actions.py",
        "glama.py",
        "governance.py",
        "graph_backend.py",
        "graph_schema.py",
        "guard.py",
        "hardware_evidence.py",
        "history.py",
        "http_client.py",
        "ignores.py",
        "image.py",
        "integrity.py",
        "intel_fetch.py",
        "intel_lookup.py",
        "inventory.py",
        "iso_27001.py",
        "js_ts_ast.py",
        "jupyter.py",
        "k8s.py",
        "k8s_transport.py",
        "langfuse_otel.py",
        "license_file_scanner.py",
        "license_policy.py",
        "logging_config.py",
        "maestro.py",
        "malicious.py",
        "mcp_auth_posture.py",
        "mcp_blocklist.py",
        "mcp_errors.py",
        "mcp_hardening.py",
        "mcp_introspect.py",
        "mcp_official_registry.py",
        "mcp_registry_text.py",
        "mcp_scan_attestation.py",
        "mcp_server.py",
        "mcp_server_catalog.py",
        "mcp_server_entrypoint.py",
        "mcp_server_factory.py",
        "mcp_server_helpers.py",
        "mcp_server_metadata.py",
        "mcp_server_operator_tools.py",
        "mcp_server_runtime.py",
        "mcp_server_runtime_catalog.py",
        "mcp_server_scan.py",
        "mcp_server_specialized.py",
        "mcp_server_ticketing_tools.py",
        "mcp_strict_args.py",
        "mcp_tenant.py",
        "mcp_tool_rules.py",
        "mitre_attack.py",
        "mitre_coverage.py",
        "mitre_fetch.py",
        "model_advisories.py",
        "model_files.py",
        "model_hash.py",
        "model_pickle_scan.py",
        "models.py",
        "nist_800_53.py",
        "nist_ai_rmf.py",
        "nist_csf.py",
        "observe_enforce.py",
        "oci_parser.py",
        "orchestration.py",
        "os_advisory.py",
        "otel_ingest.py",
        "owasp.py",
        "owasp_agentic.py",
        "owasp_mcp.py",
        "package_utils.py",
        "pci_dss.py",
        "permissions.py",
        "platform_invariants.py",
        "plugin_activation.py",
        "plugin_entrypoints.py",
        "policy.py",
        "posture.py",
        "posture_streaming.py",
        "project_config.py",
        "proxy.py",
        "proxy_audit.py",
        "proxy_configure.py",
        "proxy_policy.py",
        "proxy_sandbox.py",
        "proxy_scanner.py",
        "push.py",
        "python_agents.py",
        "rbac.py",
        "reachability_cve.py",
        "red_team.py",
        "red_team_governance.py",
        "red_team_llm.py",
        "registry.py",
        "registry_enrichment.py",
        "remediate.py",
        "remediation.py",
        "remediation_apply.py",
        "remediation_commands.py",
        "repo_auto_detect.py",
        "repo_scan.py",
        "resolver.py",
        "risk_analyzer.py",
        "routing.py",
        "runtime_blueprints.py",
        "runtime_correlation.py",
        "runtime_smoke_mcp.py",
        "samples.py",
        "sast.py",
        "sbom.py",
        "sbom_attestation.py",
        "scan_cache.py",
        "scan_contract.py",
        "scan_delta.py",
        "scan_enrichment.py",
        "scorecard.py",
        "sdk.py",
        "secret_scanner.py",
        "security.py",
        "security_eval_scorecard.py",
        "self_posture.py",
        "shield.py",
        "sidecar_injector.py",
        "skill_bundles.py",
        "skill_intel.py",
        "skills_catalog.py",
        "skills_policy.py",
        "skills_service.py",
        "smithery.py",
        "snyk.py",
        "soc2.py",
        "suppression_rules.py",
        "symbol_reach_triage.py",
        "terraform.py",
        "toxic_combos.py",
        "trace_connectors.py",
        "trace_content.py",
        "transitive.py",
        "traversal.py",
        "trust_score.py",
        "version_utils.py",
        "vex.py",
        "vuln_compliance.py",
        "vuln_freshness.py",
        "watch.py",
    }
)


# Prefix -> owning subpackage, used only to make the failure message concrete.
# The full "where does my code go" guide is docs/CODE_MAP.md.
PACKAGE_HINTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("mcp_",), "mcp_tools/"),
    (("proxy", "gateway", "firewall", "runtime", "shield"), "runtime/"),
    (("graph",), "graph/"),
    (("api_", "route"), "api/"),
    (("cli_", "command"), "cli/"),
    (("aws", "azure", "gcp", "cloud"), "cloud/"),
    (("iac", "terraform", "helm", "k8s", "dockerfile"), "iac/"),
    (("identity", "nhi", "okta", "entra"), "identity/"),
    (("parse", "lockfile", "manifest"), "parsers/"),
    (("scan", "advisory", "osv", "cve"), "scanners/"),
    (("output", "format", "report", "sarif"), "output/"),
    (("discover",), "discovery/"),
    (("ast_", "sast"), "ast/"),
    (("severity", "cvss", "version", "tenan"), "core/"),
)
CODE_MAP = "docs/CODE_MAP.md"


def suggest_package(module: str) -> str:
    """Return the subpackage a new top-level module most likely belongs in."""
    name = module.lower()
    for prefixes, package in PACKAGE_HINTS:
        if any(name.startswith(prefix) for prefix in prefixes):
            return f"src/agent_bom/{package}"
    return f"the owning subpackage listed in {CODE_MAP}"


def check(pkg: Path = PKG, allowed: frozenset[str] = ALLOWED_TOP_LEVEL_MODULES) -> tuple[int, list[str]]:
    """Compare ``pkg/*.py`` with the allowlist; return (exit code, message lines)."""
    if not pkg.is_dir():
        return 2, [f"error: package root missing: {pkg}"]
    present = {p.name for p in pkg.glob("*.py")}
    unexpected = sorted(present - allowed)
    missing = sorted(allowed - present)
    if unexpected:
        lines = ["error: new top-level module(s) under src/agent_bom/. The flat namespace is frozen; add code to a subpackage instead:"]
        lines += [f"  + {name}  -> try {suggest_package(name)}" for name in unexpected]
        lines.append(f"See {CODE_MAP} for which subpackage owns what. Ask in the PR if none fits.")
        return 1, lines
    if missing:
        lines = [
            "error: allowlisted top-level module(s) removed without updating "
            "scripts/check_package_layout.py (delete from ALLOWED_TOP_LEVEL_MODULES "
            "in the same PR that removes the file):"
        ]
        lines += [f"  - {name}" for name in missing]
        return 1, lines
    return 0, [f"ok: {len(present)} top-level src/agent_bom/*.py modules (frozen)"]


def main() -> int:
    code, lines = check()
    print("\n".join(lines), file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
