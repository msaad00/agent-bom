"""Scanning tools — scan, check, code_scan implementations."""

from __future__ import annotations

import json
import logging
import re

from mcp.server.fastmcp.exceptions import ToolError

from agent_bom.graph.severity import normalize_severity, severity_at_or_above
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


def normalize_check_package_spec(package: str, version: str | None = None) -> tuple[str, str]:
    """Parse MCP/CLI check input into ``(name, version)``.

    Accepts embedded ``name@version``, pip specifiers (``name==1.0``), and an
    optional separate ``version`` argument for agent discoverability.
    """
    spec = package.strip()
    if "@" not in spec:
        _specifier = re.split(r"(===|==|~=|!=|>=|<=|>|<)", spec, maxsplit=1)
        if len(_specifier) == 3:
            spec = f"{_specifier[0].strip()}@{_specifier[2].strip()}"
    if "@" in spec and not spec.startswith("@"):
        name, parsed_version = spec.rsplit("@", 1)
    elif spec.startswith("@") and spec.count("@") > 1:
        last_at = spec.rindex("@")
        name, parsed_version = spec[:last_at], spec[last_at + 1 :]
    else:
        name, parsed_version = spec, "latest"

    explicit_version = (version or "").strip()
    if explicit_version:
        if parsed_version not in ("latest", "") and parsed_version != explicit_version:
            raise ToolError(
                f"Conflicting versions for {name!r}: package embeds {parsed_version!r} "
                f"but version argument is {explicit_version!r}. Use one source."
            )
        parsed_version = explicit_version
    return name, parsed_version


async def _version_published(name: str, version: str, ecosystem: str, client) -> bool:
    """Return True if an exact package version is published (404 → not published).

    Fails open (returns True) on network/other errors and for ecosystems without
    a cheap per-version endpoint, so a transient failure never turns a genuine
    clean result into a false "unknown".
    """
    from urllib.parse import quote

    try:
        if ecosystem == "pypi":
            resp = await client.get(f"https://pypi.org/pypi/{quote(name)}/{quote(version)}/json")
        elif ecosystem == "npm":
            resp = await client.get(f"https://registry.npmjs.org/{quote(name, safe='@/')}/{quote(version)}")
        else:
            return True
        return resp.status_code == 200
    except Exception:  # noqa: BLE001 — best-effort existence check; fail open
        return True


async def scan_impl(
    *,
    config_path: str | None = None,
    repo_url: str | None = None,
    image: str | None = None,
    sbom_path: str | None = None,
    package: str | None = None,
    enrich: bool = False,
    offline: bool = True,
    scorecard: bool = False,
    transitive: bool = False,
    verify_integrity: bool = False,
    fail_severity: str | None = None,
    warn_severity: str | None = None,
    auto_update_db: bool = False,
    db_sources: str | None = None,
    output_format: str = "json",
    policy: dict | None = None,
    _run_scan_pipeline,
    _truncate_response,
) -> str:
    """Implementation of the scan tool.

    When ``repo_url`` is supplied, the public repository is shallow-cloned into
    a bounded temp directory, scanned statically (no repo code is executed),
    and the temp directory is always removed afterwards. ``repo_url`` and
    ``config_path`` are mutually exclusive.
    """
    from contextlib import AsyncExitStack

    async with AsyncExitStack() as _repo_cleanup:
        if repo_url is not None and str(repo_url).strip():
            if config_path is not None and str(config_path).strip():
                raise ToolError("Provide either repo_url or config_path, not both")
            from agent_bom.repo_scan import RepoScanError, clone_repository_async

            try:
                # The blocking `git clone` runs in a worker thread (see
                # clone_repository_async), so a slow/tarpit repo cannot freeze the
                # event loop and the MCP tool timeout stays effective.
                cloned_dir = await _repo_cleanup.enter_async_context(
                    clone_repository_async(repo_url, token_env="AGENT_BOM_REPO_SCAN_TOKEN")
                )
            except RepoScanError as exc:
                raise ToolError(sanitize_error(exc)) from exc
            # Route the cloned working tree through the existing local-directory
            # discovery path. The temp dir is removed when this block exits.
            config_path = str(cloned_dir)

        return await _scan_impl_inner(
            config_path=config_path,
            image=image,
            sbom_path=sbom_path,
            package=package,
            enrich=enrich,
            offline=offline,
            scorecard=scorecard,
            transitive=transitive,
            verify_integrity=verify_integrity,
            fail_severity=fail_severity,
            warn_severity=warn_severity,
            auto_update_db=auto_update_db,
            db_sources=db_sources,
            output_format=output_format,
            policy=policy,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )
    raise ToolError("scan failed before producing a result")


async def _scan_impl_inner(
    *,
    config_path: str | None = None,
    image: str | None = None,
    sbom_path: str | None = None,
    package: str | None = None,
    enrich: bool = False,
    offline: bool = True,
    scorecard: bool = False,
    transitive: bool = False,
    verify_integrity: bool = False,
    fail_severity: str | None = None,
    warn_severity: str | None = None,
    auto_update_db: bool = False,
    db_sources: str | None = None,
    output_format: str = "json",
    policy: dict | None = None,
    _run_scan_pipeline,
    _truncate_response,
) -> str:
    """Run the scan pipeline against an already-resolved local target."""
    try:
        from agent_bom.models import AIBOMReport
        from agent_bom.output import to_json

        pre_warnings: list[str] = []
        if offline and enrich:
            enrich = False
            pre_warnings.append("Enrichment skipped because offline mode was requested")
        if offline and scorecard:
            scorecard = False
            pre_warnings.append("OpenSSF Scorecard enrichment skipped because offline mode was requested")
        if offline and verify_integrity:
            verify_integrity = False
            pre_warnings.append("Package integrity verification skipped because offline mode was requested")
        if package is not None:
            package = package.strip()
            if not package:
                raise ToolError("package must not be empty")
            if len(package) > 256:
                raise ToolError("package must be 256 characters or fewer")

        # Auto-refresh stale DB before scanning only when explicitly requested.
        if auto_update_db and not offline:
            try:
                from agent_bom.db.schema import db_freshness_days
                from agent_bom.db.sync import sync_db

                freshness = db_freshness_days()
                source_list = [s.strip() for s in db_sources.split(",")] if db_sources else None
                if freshness is None or freshness >= 1 or source_list:
                    sync_db(sources=source_list)
            except Exception as exc:
                logger.warning("Auto DB refresh failed: %s", exc)
                pre_warnings.append(f"Auto DB refresh skipped: {sanitize_error(exc)}")
        elif auto_update_db and offline:
            pre_warnings.append("Auto DB refresh skipped because offline mode was requested")

        agents, blast_radii, scan_warnings, scan_sources = await _run_scan_pipeline(
            config_path,
            image,
            sbom_path,
            package,
            enrich,
            transitive=transitive,
            offline=offline,
        )
        scan_warnings = [*pre_warnings, *scan_warnings]
        if not agents:
            result: dict[str, object] = {
                "status": "no_agents_found",
                "agents": [],
                "vulnerabilities": [],
                "blast_radius": [],
                "blast_radii": [],
                "warnings": scan_warnings,
            }
            return _truncate_response(json.dumps(result))
        from agent_bom.vex import active_blast_radii

        active_findings = active_blast_radii(blast_radii)

        # Integrity verification
        if verify_integrity:
            from agent_bom.http_client import create_client
            from agent_bom.integrity import verify_package_integrity

            async with create_client(timeout=15.0) as client:
                for agent in agents:
                    for server in agent.mcp_servers:
                        for pkg in server.packages:
                            try:
                                integrity_result = await verify_package_integrity(pkg, client)
                                if integrity_result:
                                    pkg.integrity = integrity_result
                            except Exception as exc:
                                logger.debug("Integrity check failed for %s: %s", pkg.name, exc)

        # OpenSSF Scorecard enrichment
        if scorecard:
            try:
                from agent_bom.http_client import create_client
                from agent_bom.resolver import enrich_supply_chain_metadata
                from agent_bom.scorecard import enrich_packages_with_scorecard

                all_pkgs = [p for a in agents for s in a.mcp_servers for p in s.packages]
                if all_pkgs:
                    async with create_client(timeout=15.0) as client:
                        await enrich_supply_chain_metadata(all_pkgs, client)
                    await enrich_packages_with_scorecard(all_pkgs)
            except Exception as exc:
                logger.debug("Scorecard enrichment failed: %s", exc)

        report = AIBOMReport(agents=agents, blast_radii=blast_radii, scan_sources=scan_sources)

        # Format selection
        if output_format == "sarif":
            from agent_bom.output.sarif import to_sarif

            sarif_result = to_sarif(report)
            return _truncate_response(json.dumps(sarif_result, indent=2, default=str))
        if output_format == "cyclonedx":
            from agent_bom.output import to_cyclonedx

            return _truncate_response(json.dumps(to_cyclonedx(report), indent=2, default=str))
        if output_format == "spdx":
            from agent_bom.output import to_spdx

            return _truncate_response(json.dumps(to_spdx(report), indent=2, default=str))
        if output_format == "junit":
            from agent_bom.output import to_junit

            return _truncate_response(to_junit(report, blast_radii))
        if output_format == "csv":
            from agent_bom.output import to_csv

            return _truncate_response(to_csv(report, blast_radii))
        if output_format == "markdown":
            from agent_bom.output import to_markdown

            return _truncate_response(to_markdown(report, blast_radii))

        result = to_json(report)

        # Policy evaluation
        if policy:
            from agent_bom.policy import _validate_policy, evaluate_policy

            _validate_policy(policy)
            result["policy_results"] = evaluate_policy(policy, active_findings)

        # Severity gate (fail)
        if fail_severity:
            from agent_bom.models import Severity

            try:
                threshold = Severity(fail_severity.lower())
            except (ValueError, KeyError):
                raise ToolError(f"Invalid severity: {fail_severity}. Use: critical, high, medium, low")
            gate_fail = any(
                severity_at_or_above(sev, threshold.value)
                for br in active_findings
                if (sev := normalize_severity(br.vulnerability.severity.value)) in {"critical", "high", "medium", "low"}
            )
            result["gate_status"] = "fail" if gate_fail else "pass"
            result["gate_severity"] = fail_severity.lower()

        # Warn severity gate (two-tier: only fires when fail gate did not trigger)
        if warn_severity and result.get("gate_status") != "fail":
            from agent_bom.models import Severity

            try:
                warn_threshold = Severity(warn_severity.lower())
            except (ValueError, KeyError):
                raise ToolError(f"Invalid warn_severity: {warn_severity}. Use: critical, high, medium, low")
            warn_matches = [
                br
                for br in active_findings
                if normalize_severity(br.vulnerability.severity.value) in {"critical", "high", "medium", "low"}
                and severity_at_or_above(br.vulnerability.severity.value, warn_threshold.value)
            ]
            result["warn_gate_status"] = "warn" if warn_matches else "pass"
            result["warn_gate_severity"] = warn_severity.lower()
            result["warn_gate_count"] = len(warn_matches)

        if scan_warnings:
            result["warnings"] = scan_warnings
        return _truncate_response(json.dumps(result, indent=2, default=str))
    except Exception as exc:
        from agent_bom.scanners import IncompleteScanError

        if isinstance(exc, IncompleteScanError):
            return _truncate_response(
                json.dumps(
                    {
                        "status": "incomplete_scan",
                        "agents": [],
                        "vulnerabilities": [],
                        "blast_radius": [],
                        "blast_radii": [],
                        "warnings": [sanitize_error(exc)],
                    }
                )
            )
        logger.exception("MCP tool error")
        raise ToolError(sanitize_error(exc)) from exc


async def check_impl(
    *,
    package: str,
    ecosystem: str = "npm",
    version: str | None = None,
    _validate_ecosystem,
    _truncate_response,
) -> str:
    """Implementation of the check tool."""
    try:
        from agent_bom.models import Package as Pkg
        from agent_bom.parsers.os_parsers import enrich_os_package_context
        from agent_bom.scanners import ScanOptions, scan_packages

        try:
            name, parsed_version = normalize_check_package_spec(package, version)
        except ToolError as exc:
            raise exc
        version = parsed_version

        try:
            eco = _validate_ecosystem(ecosystem)
        except ValueError as exc:
            raise ToolError(sanitize_error(exc)) from exc
        pkg = Pkg(name=name, version=version, ecosystem=eco)
        os_context_complete = True
        if eco in {"deb", "apk", "rpm"}:
            os_context_complete = enrich_os_package_context(pkg)

        if eco in {"deb", "apk", "rpm"} and version in ("latest", ""):
            return json.dumps(
                {
                    "package": name,
                    "ecosystem": eco,
                    "status": "error",
                    "error": f"Explicit version required for {eco} packages",
                }
            )

        # Resolve "latest" via registry
        if version in ("latest", ""):
            from agent_bom.http_client import create_client
            from agent_bom.resolver import resolve_package_version

            async with create_client(timeout=15.0) as client:
                resolved = await resolve_package_version(pkg, client)
            if resolved:
                version = pkg.version
            else:
                return json.dumps(
                    {
                        "package": name,
                        "ecosystem": eco,
                        "status": "error",
                        "error": (
                            f"Could not resolve a version for {name}. Provide an explicit "
                            f"version (e.g. {name}@1.2.3 or {name}==1.2.3) and confirm the "
                            f"ecosystem (got '{eco}')."
                        ),
                    }
                )

        await scan_packages([pkg], options=ScanOptions(offline=False))

        if not pkg.vulnerabilities and eco in {"deb", "apk", "rpm"} and not os_context_complete:
            return json.dumps(
                {
                    "package": name,
                    "version": version,
                    "ecosystem": eco,
                    "vulnerabilities": 0,
                    "status": "incomplete",
                    "message": "OS package context was insufficient for a trustworthy clean verdict",
                    "source_package": pkg.source_package,
                    "distro_name": pkg.distro_name,
                    "distro_version": pkg.distro_version,
                }
            )

        # An explicit pinned version that found no vulns might simply not exist
        # (a typo'd or hallucinated pin). Confirm it is published before calling
        # it clean, so a fake pin can't read as safe.
        if not pkg.vulnerabilities and version not in ("latest", "") and eco in ("npm", "pypi"):
            from agent_bom.http_client import create_client

            async with create_client(timeout=15.0) as client:
                published = await _version_published(name, version, eco, client)
            if not published:
                return json.dumps(
                    {
                        "package": name,
                        "version": version,
                        "ecosystem": eco,
                        "status": "unknown",
                        "message": (
                            f"Version {version} of {name} was not found in the {eco} registry — "
                            f"cannot confirm it is free of vulnerabilities (typo or unpublished "
                            f"version?). agent-bom only verifies published versions."
                        ),
                    }
                )

        if not pkg.vulnerabilities:
            return json.dumps(
                {
                    "package": name,
                    "version": version,
                    "ecosystem": eco,
                    "vulnerabilities": 0,
                    "status": "clean",
                    "message": f"No known vulnerabilities in {name}@{version}",
                }
            )

        vulns = pkg.vulnerabilities
        return _truncate_response(
            json.dumps(
                {
                    "package": name,
                    "version": version,
                    "ecosystem": eco,
                    "vulnerabilities": len(vulns),
                    "status": "vulnerable",
                    "details": [
                        {
                            "id": v.id,
                            "severity": v.severity.value,
                            "cvss_score": v.cvss_score,
                            "fixed_version": v.fixed_version,
                            "summary": (v.summary or "")[:200],
                            "compliance_tags": v.compliance_tags,
                        }
                        for v in vulns
                    ],
                },
                indent=2,
                default=str,
            )
        )
    except ToolError:
        raise
    except Exception as exc:
        logger.exception("MCP tool error")
        raise ToolError(sanitize_error(exc)) from exc


async def code_scan_impl(
    *,
    path: str,
    config: str = "auto",
    _safe_path,
    _truncate_response,
) -> str:
    """Implementation of the code_scan tool."""
    try:
        scan_path = _safe_path(path)
    except ValueError as exc:
        raise ToolError(sanitize_error(exc)) from exc

    try:
        from agent_bom.sast import SASTScanError, scan_code

        _packages, sast_result = scan_code(str(scan_path), config=config)
        return _truncate_response(json.dumps(sast_result.to_dict(), indent=2))
    except SASTScanError as exc:
        raise ToolError(sanitize_error(exc)) from exc
    except Exception as exc:
        logger.error("code_scan error: %s", exc)
        raise ToolError(sanitize_error(exc)) from exc
