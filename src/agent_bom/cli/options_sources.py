"""Scan option groups for sources, output, and scan policy controls."""

from __future__ import annotations

import click

from agent_bom.cli.options_helpers import _apply


def input_options(fn):
    """Project directory, config, inventory, SBOM, images, filesystem."""
    return _apply(
        [
            click.option("--project", "-p", type=click.Path(exists=True), help="Project directory to scan"),
            click.option("--config-dir", type=click.Path(exists=True), help="Custom agent config directory to scan"),
            click.option("--inventory", type=str, default=None, help="Inventory file (JSON or CSV). Use '-' for stdin."),
            click.option(
                "--sbom",
                "sbom_file",
                type=click.Path(exists=True),
                help="Existing SBOM file to ingest (CycloneDX or SPDX JSON from Syft/Grype/Trivy)",
            ),
            click.option(
                "--sbom-name",
                "sbom_name",
                default=None,
                metavar="NAME",
                help="Label for the SBOM resource (e.g. 'prod-api-01', 'nginx:1.25'). Auto-detected from SBOM metadata if omitted.",
            ),
            click.option(
                "--image",
                "images",
                multiple=True,
                metavar="IMAGE",
                help="Docker image to scan (e.g. nginx:1.25). Repeatable for multiple images.",
            ),
            click.option(
                "--image-tar",
                "image_tars",
                multiple=True,
                metavar="TAR",
                help="OCI image tarball to scan without Docker/Syft/Grype (e.g. image.tar from 'docker save'). Repeatable.",
            ),
            click.option(
                "--filesystem",
                "filesystem_paths",
                multiple=True,
                type=click.Path(exists=True),
                metavar="PATH",
                help="Filesystem directory or tar archive to scan for packages via Syft (e.g. mounted VM disk snapshot). Repeatable.",
            ),
            click.option(
                "--correlate",
                "correlate_log",
                type=click.Path(exists=True),
                default=None,
                metavar="AUDIT_LOG",
                help="Cross-reference scan results with proxy audit log (JSONL) to identify which vulnerable tools were actually called.",
            ),
            click.option(
                "--self-scan",
                "self_scan",
                is_flag=True,
                default=False,
                help="Scan agent-bom's own installed dependencies for vulnerabilities.",
            ),
            click.option(
                "--demo", is_flag=True, default=False, help="Run a demo scan with bundled inventory containing known-vulnerable packages."
            ),
            click.option(
                "--external-scan",
                "external_scan_path",
                type=click.Path(exists=True),
                default=None,
                help="Path to Trivy, Grype, or Syft JSON output. Ingests findings and adds blast radius analysis.",
            ),
            click.option(
                "--os-packages",
                "os_packages",
                is_flag=True,
                default=False,
                help="Scan the host OS for installed system packages (dpkg/rpm/apk) and check them for CVEs.",
            ),
        ]
    )(fn)


def output_options(fn):
    """Output path, format, display controls, telemetry endpoints."""
    return _apply(
        [
            click.option("--output", "-o", type=str, help="Output file path (use '-' for stdout)"),
            click.option(
                "--open",
                "open_report",
                is_flag=True,
                default=False,
                help="Auto-open HTML/graph-html report in default browser after generation",
            ),
            click.option(
                "--format",
                "-f",
                "output_format",
                type=click.Choice(
                    [
                        "console",
                        "json",
                        "html",
                        "pdf",
                        "sarif",
                        "cyclonedx",
                        "spdx",
                        "junit",
                        "csv",
                        "markdown",
                        "plain",
                        "text",
                        "prometheus",
                        "graph",
                        "graph-html",
                        "mermaid",
                        "svg",
                        "badge",
                    ]
                ),
                default="console",
                help=(
                    "Output format.\n\n"
                    "Core: console (default, colored terminal), json, html, pdf, sarif (GitHub/GitLab Security tab), cyclonedx (SBOM).\n"
                    "SBOM: spdx (alternate SBOM standard).\n"
                    "CI/CD: junit (JUnit XML for Jenkins/GitLab/Azure DevOps), csv (spreadsheet/SIEM), markdown (PR comments/wiki).\n"
                    "Plain: plain (no color, for piping/logging) — alias: text.\n"
                    "Monitoring: prometheus (Prometheus exposition format).\n"
                    "Visualization: mermaid, graph-html (interactive), svg.\n"
                    "Other: graph (raw graph JSON), badge (single-line status)."
                ),
            ),
            click.option(
                "--mermaid-mode",
                type=click.Choice(["supply-chain", "attack-flow", "lifecycle"]),
                default="supply-chain",
                help="Mermaid diagram mode: supply-chain (full hierarchy), attack-flow (CVE blast radius), or lifecycle (gantt timeline)",
            ),
            click.option(
                "--push-gateway",
                "push_gateway",
                default=None,
                metavar="URL",
                help="Prometheus Pushgateway URL to push metrics after scan (e.g. http://localhost:9091)",
            ),
            click.option(
                "--otel-endpoint",
                "otel_endpoint",
                default=None,
                metavar="URL",
                help="OpenTelemetry OTLP/HTTP collector endpoint (e.g. http://localhost:4318). Requires pip install 'agent-bom[otel]'",
            ),
            click.option(
                "--verbose",
                "-v",
                is_flag=True,
                help="Full output — dependency tree, all findings, severity chart, threat frameworks, debug logging",
            ),
            click.option(
                "--log-level",
                "log_level",
                type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
                default=None,
                help="Set log level (overrides --verbose). Env: AGENT_BOM_LOG_LEVEL",
            ),
            click.option("--log-json", "log_json", is_flag=True, help="Emit structured JSON logs to stderr (for SIEM ingestion)"),
            click.option("--log-file", "log_file", type=click.Path(), default=None, help="Write JSON logs to file"),
            click.option("--no-color", is_flag=True, help="Disable colored output (useful for piping, CI logs, accessibility)"),
            click.option("--quiet", "-q", is_flag=True, help="Suppress all output except results (for scripting)"),
            click.option(
                "--exclude-unfixable",
                is_flag=True,
                default=False,
                help="Exclude findings with no available fix from SARIF output (reduces GitHub Security tab noise)",
            ),
            click.option(
                "--fixable-only",
                "fixable_only",
                is_flag=True,
                default=False,
                help="Show only vulnerabilities with available fixes.",
            ),
            click.option(
                "--posture",
                is_flag=True,
                default=False,
                help="Show a concise 5-line workstation posture summary.",
            ),
        ]
    )(fn)


def scan_control_options(fn):
    """Scan behavior: dry-run, skip flags, depth, presets."""
    return _apply(
        [
            click.option("--dry-run", is_flag=True, help="Show what files and APIs would be accessed without scanning, then exit 0"),
            click.option(
                "--offline",
                is_flag=True,
                envvar="AGENT_BOM_OFFLINE",
                help="Scan only against local DB — skip all network calls. Use after 'db update'.",
            ),
            click.option("--no-scan", is_flag=True, help="Skip vulnerability scanning (inventory only)"),
            click.option(
                "--blast-radius-depth",
                type=int,
                default=1,
                show_default=True,
                metavar="N",
                help=(
                    "Multi-hop blast radius depth (1-5). Traces agent-to-agent delegation chains "
                    "through shared MCP servers. Higher values reveal transitive risk but increase "
                    "analysis time. Default 1 = direct impact only."
                ),
            ),
            click.option("--no-tree", is_flag=True, help="Skip dependency tree output"),
            click.option("--transitive", is_flag=True, help="Resolve transitive dependencies for npx/uvx packages"),
            click.option("--max-depth", type=int, default=3, help="Maximum depth for transitive dependency resolution"),
            click.option(
                "--preset",
                type=click.Choice(["ci", "enterprise", "quick"]),
                default=None,
                help=(
                    "Scan preset: ci (quiet, json, fail-on-critical), enterprise (enrich, introspect,"
                    " transitive, verify-integrity, verify-instructions), quick (no transitive, no enrich)"
                ),
            ),
        ]
    )(fn)


def enrichment_options(fn):
    """NVD, EPSS, KEV, Scorecard, deps.dev, license, Snyk."""
    return _apply(
        [
            click.option(
                "--enrich",
                is_flag=True,
                help="Enrich findings with NVD, EPSS, CISA KEV, and OpenSSF Scorecard data for resolvable repos",
            ),
            click.option("--compliance", is_flag=True, help="Tag findings with compliance frameworks (OWASP, NIST, CIS, ISO, SOC2, CMMC)"),
            click.option(
                "--auto-update-db/--no-auto-update-db",
                "auto_update_db",
                default=True,
                envvar="AGENT_BOM_AUTO_UPDATE_DB",
                show_default=True,
                help="Auto-refresh local vuln DB if stale (>7 days). --no-auto-update-db to disable.",
            ),
            click.option(
                "--db-source",
                "db_sources",
                type=str,
                default=None,
                envvar="AGENT_BOM_DB_SOURCES",
                help="Comma-separated DB sources to sync before scanning (e.g. nvd,ghsa,osv,epss,kev).",
            ),
            click.option("--nvd-api-key", envvar="NVD_API_KEY", help="NVD API key for higher rate limits"),
            click.option(
                "--scorecard",
                "scorecard_flag",
                is_flag=True,
                help="Force OpenSSF Scorecard enrichment even without --enrich",
            ),
            click.option(
                "--deps-dev",
                "deps_dev",
                is_flag=True,
                help="Use deps.dev for transitive dependency resolution and license enrichment (all ecosystems)",
            ),
            click.option(
                "--license-check",
                "license_check",
                is_flag=True,
                help="Evaluate package licenses against compliance policy (block GPL/AGPL, warn copyleft)",
            ),
            click.option("--snyk", "snyk_flag", is_flag=True, help="Enrich vulnerabilities with Snyk intelligence (requires SNYK_TOKEN)"),
            click.option(
                "--snyk-token", default=None, envvar="SNYK_TOKEN", metavar="KEY", help="Snyk API token (or set SNYK_TOKEN env var)"
            ),
            click.option(
                "--snyk-org", default=None, envvar="SNYK_ORG_ID", metavar="ORG", help="Snyk organization ID (or set SNYK_ORG_ID env var)"
            ),
        ]
    )(fn)


def vex_options(fn):
    """OpenVEX document loading and generation."""
    return _apply(
        [
            click.option(
                "--vex",
                "vex_path",
                type=click.Path(exists=True),
                default=None,
                metavar="PATH",
                help="Apply a VEX document (OpenVEX JSON) to suppress resolved vulnerabilities",
            ),
            click.option(
                "--generate-vex",
                "generate_vex_flag",
                is_flag=True,
                help="Auto-generate a VEX document from scan results (KEV → affected, rest → under_investigation)",
            ),
            click.option(
                "--vex-output",
                "vex_output_path",
                type=str,
                default=None,
                metavar="PATH",
                help="Write generated VEX document to this file (default: agent-bom.vex.json)",
            ),
            click.option(
                "--ignore-file",
                "ignore_file",
                type=click.Path(),
                default=None,
                metavar="PATH",
                help=(
                    "Path to ignore/allowlist file (default: .agent-bom-ignore.yaml). "
                    "Suppress known false positives by CVE ID, package, or finding type."
                ),
            ),
        ]
    )(fn)


def policy_options(fn):
    """Failure thresholds, policy files, baselines, history."""
    return _apply(
        [
            click.option(
                "--fail-on-severity",
                type=click.Choice(["critical", "high", "medium", "low"]),
                help="Exit 1 if vulnerabilities of this severity or higher are found",
            ),
            click.option(
                "--warn-on",
                "warn_on_severity",
                type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False),
                default=None,
                help=(
                    "Warn (exit 0) when findings at or above this severity exist. "
                    "Use with --fail-on-severity for two-tier CI gates (e.g. --warn-on medium --fail-on-severity critical)."
                ),
            ),
            click.option("--fail-on-kev", is_flag=True, help="Exit 1 if any finding appears in CISA KEV (must use --enrich)"),
            click.option("--fail-if-ai-risk", is_flag=True, help="Exit 1 if an AI framework package with credentials has vulnerabilities"),
            click.option("--save", "save_report", is_flag=True, help="Save this scan to ~/.agent-bom/history/ for future diffing"),
            click.option("--baseline", type=click.Path(exists=True), help="Path to a baseline report JSON to diff against current scan"),
            click.option(
                "--delta",
                "delta_mode",
                is_flag=True,
                default=False,
                help=(
                    "Delta mode: report only new findings vs baseline (--baseline). "
                    "Exit code is based on new findings only — pre-existing are suppressed. "
                    "Use in CI to surface only what the current PR introduced."
                ),
            ),
            click.option("--policy", type=click.Path(exists=True), help="Policy file (JSON/YAML) with declarative security rules"),
        ]
    )(fn)
