"""Scanning tools — scan, check, code_scan implementations."""

from __future__ import annotations

import asyncio
import json
import logging
import re

from mcp.server.fastmcp.exceptions import ToolError

from agent_bom.core.severity import normalize_severity, severity_at_or_above
from agent_bom.mcp_tools.result_store import ResultStore
from agent_bom.mcp_tools.scan_response import (
    MAX_PAGE_LIMIT,
    SCAN_DETAIL_LEVELS,
    SCAN_RESULTS,
    IncompleteScanPayload,
    build_scan_summary,
    resolve_offline,
    section_page,
)
from agent_bom.parsers.sbom_context import imported_cloud_inventory
from agent_bom.scanners.package_check_result import has_lookup_coverage_gap
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

    from agent_bom.http_client import request_with_retry

    # Package coordinates are path data, never URL structure. Encoding every
    # reserved character also makes scoped npm names (``@scope/name``) a
    # single registry path segment instead of allowing caller-controlled path
    # separators. The shared request wrapper validates the fixed registry
    # origin before opening a socket.
    encoded_name = quote(name, safe="")
    encoded_version = quote(version, safe="")

    try:
        if ecosystem == "pypi":
            url = f"https://pypi.org/pypi/{encoded_name}/{encoded_version}/json"
        elif ecosystem == "npm":
            url = f"https://registry.npmjs.org/{encoded_name}/{encoded_version}"
        else:
            return True
        resp = await request_with_retry(client, "GET", url, max_retries=0)
        if resp is None:
            return True
        return resp.status_code == 200
    except Exception:  # noqa: BLE001 — best-effort existence check; fail open
        return True


async def scan_impl(
    *,
    config_path: str | None = None,
    no_discover: bool = False,
    repo_url: str | None = None,
    image: str | None = None,
    sbom_path: str | None = None,
    package: str | None = None,
    ecosystem: str | None = None,
    enrich: bool = False,
    offline: bool | None = None,
    scorecard: bool = False,
    transitive: bool = False,
    verify_integrity: bool = False,
    fail_severity: str | None = None,
    warn_severity: str | None = None,
    auto_update_db: bool = False,
    db_sources: str | None = None,
    output_format: str = "json",
    policy: dict | None = None,
    detail: str = "summary",
    result_id: str | None = None,
    section: str | None = None,
    offset: int = 0,
    limit: int = 25,
    _run_scan_pipeline,
    _truncate_response,
    _result_owner: str = "local",
    _result_store: ResultStore | None = None,
    _max_response_chars: int | None = None,
) -> str:
    """Implementation of the scan tool.

    When ``repo_url`` is supplied, the public repository is shallow-cloned into
    a bounded temp directory, scanned statically (no repo code is executed),
    and the temp directory is always removed afterwards. ``repo_url`` and
    ``config_path`` are mutually exclusive.

    JSON results are summary-first (``detail="summary"``); the full redacted
    report is kept under a ``result_id`` whose sections are paged with
    ``result_id`` + ``section`` + ``offset``/``limit`` follow-ups, which do not
    re-run the scan.
    """
    from contextlib import AsyncExitStack

    from agent_bom.config import MCP_MAX_RESPONSE_CHARS

    store = _result_store if _result_store is not None else SCAN_RESULTS
    max_chars = _max_response_chars if _max_response_chars is not None else MCP_MAX_RESPONSE_CHARS
    if detail not in SCAN_DETAIL_LEVELS:
        raise ToolError(f"Invalid detail: {detail!r}. Use one of: {', '.join(SCAN_DETAIL_LEVELS)}")
    if result_id is not None and str(result_id).strip():
        import asyncio

        return await asyncio.to_thread(
            _stored_result_view,
            store,
            owner=_result_owner,
            result_id=str(result_id).strip(),
            section=section,
            offset=offset,
            limit=limit,
            max_chars=max_chars,
            _truncate_response=_truncate_response,
        )
    if section is not None and str(section).strip():
        raise ToolError("section requires result_id from a previous scan response")

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
            no_discover=no_discover,
            image=image,
            sbom_path=sbom_path,
            package=package,
            ecosystem=ecosystem,
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
            detail=detail,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
            _result_owner=_result_owner,
            _result_store=store,
        )
    raise ToolError("scan failed before producing a result")


def _stored_result_view(
    store: ResultStore,
    *,
    owner: str,
    result_id: str,
    section: str | None,
    offset: int,
    limit: int,
    max_chars: int,
    _truncate_response,
) -> str:
    """Serve a follow-up view of a stored scan result without re-scanning."""
    try:
        stored = store.get(owner, result_id)
    except Exception as exc:
        raise ToolError("MCP result storage unavailable; retry after storage recovery") from exc
    if stored is None or not isinstance(stored.get("report"), dict):
        raise ToolError(
            "Unknown or expired result_id. Results are kept for a limited time per tenant "
            "and per caller; run scan again to get a fresh result_id."
        )
    report: dict = stored["report"]
    if section is None or not str(section).strip():
        summary = build_scan_summary(
            report,
            result_id=result_id,
            ttl_seconds=store.ttl_seconds,
            offline=bool(stored.get("offline")),
        )
        return _truncate_response(json.dumps(summary, indent=2, default=str))
    name = str(section).strip()
    if offset < 0:
        raise ToolError("offset must be >= 0")
    if limit < 1 or limit > MAX_PAGE_LIMIT:
        raise ToolError(f"limit must be between 1 and {MAX_PAGE_LIMIT}")
    try:
        page = section_page(report, result_id=result_id, section=name, offset=offset, limit=limit, max_chars=max_chars)
    except KeyError:
        available = ", ".join(sorted(k for k, v in report.items() if isinstance(v, list | dict) and v))
        raise ToolError(f"Unknown section {name!r}. Available sections: {available}") from None
    return _truncate_response(json.dumps(page, separators=(",", ":"), default=str))


async def _scan_impl_inner(
    *,
    config_path: str | None = None,
    no_discover: bool = False,
    image: str | None = None,
    sbom_path: str | None = None,
    package: str | None = None,
    ecosystem: str | None = None,
    enrich: bool = False,
    offline: bool | None = None,
    scorecard: bool = False,
    transitive: bool = False,
    verify_integrity: bool = False,
    fail_severity: str | None = None,
    warn_severity: str | None = None,
    auto_update_db: bool = False,
    db_sources: str | None = None,
    output_format: str = "json",
    policy: dict | None = None,
    detail: str = "summary",
    _run_scan_pipeline,
    _truncate_response,
    _result_owner: str = "local",
    _result_store: ResultStore | None = None,
) -> str:
    """Run the scan pipeline against an already-resolved local target."""
    offline = resolve_offline(offline)
    store = _result_store if _result_store is not None else SCAN_RESULTS
    try:
        from agent_bom.models import AIBOMReport
        from agent_bom.output import to_json

        enrich, scorecard, verify_integrity, pre_warnings = _apply_offline_overrides(offline, enrich, scorecard, verify_integrity)
        package = _normalize_scan_package(package)
        _maybe_refresh_vuln_db(auto_update_db, offline, db_sources, pre_warnings)
        agents, blast_radii, scan_warnings, scan_sources = await _run_scan_pipeline(
            config_path,
            image,
            sbom_path,
            package,
            enrich,
            transitive=transitive,
            offline=offline,
            ecosystem=ecosystem,
            no_discover=no_discover,
        )
        scan_warnings = [*pre_warnings, *scan_warnings]
        package_spec_unresolved = _flag_unresolved_package_spec(package, agents, scan_warnings)
        if not agents:
            return _truncate_response(json.dumps(_empty_envelope("no_agents_found", warnings=scan_warnings)))
        from agent_bom.vex import active_blast_radii

        active_findings = active_blast_radii(blast_radii)
        if verify_integrity:
            await _verify_scanned_packages(agents, scan_warnings)
        if scorecard:
            await _enrich_scanned_packages_with_scorecard(agents)
        report = AIBOMReport(agents, blast_radii, cloud_inventory_data=imported_cloud_inventory(agents), scan_sources=scan_sources)
        if agents:
            await _surface_graph_findings(report)
        if package_spec_unresolved:
            # Fail closed for every format: an empty SARIF/CycloneDX/SPDX document reads as an audited clean result.
            envelope = _empty_envelope("incomplete_scan", requested_package=package, requested_ecosystem=ecosystem, warnings=scan_warnings)
            return IncompleteScanPayload(_truncate_response(json.dumps(envelope, indent=2)))
        rendered = _render_report_format(output_format, report, blast_radii, _truncate_response)
        if rendered is not None:
            return rendered
        result = to_json(report)
        _apply_policy_and_severity_gates(result, active_findings, policy, fail_severity, warn_severity)
        if scan_warnings:
            result["warnings"] = scan_warnings
        return await _store_and_render_json(result, store, _result_owner, offline, detail, _truncate_response)
    except ToolError:
        raise
    except Exception as exc:
        incomplete = _incomplete_scan_response(exc, offline, _truncate_response)
        if incomplete is not None:
            return incomplete
        logger.exception("MCP tool error")
        raise ToolError(sanitize_error(exc)) from exc


def _empty_envelope(status: str, *, warnings: list[str], **extra: object) -> dict[str, object]:
    """Findings-free scan envelope; ``extra`` keys sit between status and the empty lists."""
    return {"status": status, **extra, "agents": [], "vulnerabilities": [], "blast_radius": [], "blast_radii": [], "warnings": warnings}


def _apply_offline_overrides(offline: bool, enrich: bool, scorecard: bool, verify_integrity: bool) -> tuple[bool, bool, bool, list[str]]:
    """Disable network-only options in offline mode, recording why."""
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
    return enrich, scorecard, verify_integrity, pre_warnings


def _normalize_scan_package(package: str | None) -> str | None:
    if package is not None:
        package = package.strip()
        if not package:
            raise ToolError("package must not be empty")
        if len(package) > 256:
            raise ToolError("package must be 256 characters or fewer")
    return package


def _maybe_refresh_vuln_db(auto_update_db: bool, offline: bool, db_sources: str | None, pre_warnings: list[str]) -> None:
    """Auto-refresh stale DB before scanning only when explicitly requested."""
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


def _flag_unresolved_package_spec(package: str | None, agents, scan_warnings: list[str]) -> bool:
    """Fail closed: a package spec that resolved to zero packages produced no
    evidence at all, so the empty finding list must not read as "clean"."""
    package_spec_unresolved = False
    if package:
        from agent_bom.mcp_server_scan import package_spec_extracted_count, unresolved_package_spec_warning

        package_spec_unresolved = package_spec_extracted_count(agents) == 0
        if package_spec_unresolved:
            warning = unresolved_package_spec_warning(package)
            if warning not in scan_warnings:
                scan_warnings.append(warning)
    return package_spec_unresolved


async def _verify_scanned_packages(agents, scan_warnings: list[str]) -> None:
    """Integrity + provenance verification. Shares the CLI's helper so the
    verdict lands on the model fields every emitter reads, instead of an
    ad-hoc attribute nothing consumes."""
    from agent_bom.http_client import create_client
    from agent_bom.integrity import verify_packages

    all_pkgs = [pkg for agent in agents for server in agent.mcp_servers for pkg in server.packages]
    if all_pkgs:
        try:
            async with create_client(timeout=15.0) as client:
                await verify_packages(all_pkgs, client)
        except Exception as exc:
            logger.debug("Integrity verification failed: %s", exc)
            scan_warnings.append(f"Package integrity verification failed: {sanitize_error(exc)}")


async def _enrich_scanned_packages_with_scorecard(agents) -> None:
    """OpenSSF Scorecard enrichment."""
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


async def _surface_graph_findings(report) -> None:
    """Share CLI/API graph-derived findings; offload the best-effort build
    so graph analysis does not block the event loop."""
    from agent_bom.graph.scan_findings import surface_graph_derived_findings

    await asyncio.to_thread(surface_graph_derived_findings, report, scan_id=report.scan_id or "mcp-scan", tenant_id="default")


def _render_report_format(output_format: str, report, blast_radii, _truncate_response) -> str | None:
    """Render a non-JSON output format; ``None`` means the JSON path applies."""
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
    return None


def _apply_policy_and_severity_gates(result: dict, active_findings, policy, fail_severity, warn_severity) -> None:
    """Policy evaluation, then the fail gate, then the warn gate (two-tier:
    only fires when the fail gate did not trigger)."""
    if policy:
        from agent_bom.policy import _validate_policy, evaluate_policy

        _validate_policy(policy)
        result["policy_results"] = evaluate_policy(policy, active_findings)
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


async def _store_and_render_json(result: dict, store: ResultStore, owner: str, offline: bool, detail: str, _truncate_response) -> str:
    """Redact and store the JSON report, then render the requested detail level."""
    from agent_bom.output.json_fmt import redact_json_payload

    def _render_json_result() -> str:
        redacted = redact_json_payload(result)
        try:
            result_id = store.put(owner, {"report": redacted, "offline": offline})
        except Exception as exc:
            raise ToolError("MCP result storage unavailable; retry after storage recovery") from exc
        if detail == "full":
            full = {"result_id": result_id, **redacted}
            return _truncate_response(json.dumps(full, indent=2, default=str))
        summary = build_scan_summary(redacted, result_id=result_id, ttl_seconds=store.ttl_seconds, offline=offline)
        return _truncate_response(json.dumps(summary, indent=2, default=str))

    # Multi-MB reports: serialize, store, and bound off the event loop.
    return await asyncio.to_thread(_render_json_result)


def _incomplete_scan_response(exc: Exception, offline: bool, _truncate_response) -> str | None:
    """Structured incomplete envelope for ``IncompleteScanError``; ``None`` otherwise."""
    from agent_bom.scanners import IncompleteScanError

    if not isinstance(exc, IncompleteScanError):
        return None
    envelope = _empty_envelope("incomplete_scan", vulnerability_lookup="offline" if offline else "online", warnings=[sanitize_error(exc)])
    return IncompleteScanPayload(_truncate_response(json.dumps(envelope)))


async def check_impl(
    *,
    package: str,
    ecosystem: str = "npm",
    version: str | None = None,
    offline: bool = False,
    _validate_ecosystem,
    _truncate_response,
) -> str:
    """Implementation of the check tool."""
    try:
        from agent_bom.models import Package as Pkg
        from agent_bom.parsers.os_parsers import enrich_os_package_context
        from agent_bom.scanners import (
            IncompleteScanError,
            ScanOptions,
            consume_coverage_warnings,
            consume_scan_warnings,
            reset_scan_warnings,
            scan_packages,
        )
        from agent_bom.scanners.package_check_result import PackageCheckResult, serialize_vulnerability

        try:
            name, parsed_version = normalize_check_package_spec(package, version)
        except ToolError as exc:
            raise exc
        try:
            eco = _validate_ecosystem(ecosystem)
        except ValueError as exc:
            raise ToolError(sanitize_error(exc)) from exc
        pkg = Pkg(name=name, version=parsed_version, ecosystem=eco)
        version = pkg.version
        result_warnings: list[str] = []

        def service_result(
            verdict: str,
            message: str,
            *,
            source_context: dict | None = None,
        ) -> str:
            details = tuple(serialize_vulnerability(vulnerability) for vulnerability in pkg.vulnerabilities)
            result = PackageCheckResult(
                package=name,
                version=version or pkg.version,
                ecosystems=(eco,),
                verdict=verdict,
                message=message,
                lookup_mode="offline" if offline else "online",
                vulnerabilities=details,
                warnings=tuple(result_warnings),
                purl=pkg.purl,
                is_malicious=bool(pkg.is_malicious),
                malicious_reason=pkg.malicious_reason,
                exit_code=0 if verdict == "clean" else 1 if verdict in {"vulnerable", "malicious"} else 2,
                source_context=source_context or {},
            )
            return _truncate_response(json.dumps(result.service_payload(), indent=2, default=str))

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
            if offline:
                return service_result(
                    "incomplete",
                    f"Offline package checks require an explicit version for {name}",
                )
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

        reset_scan_warnings()
        try:
            await scan_packages([pkg], options=ScanOptions(offline=offline))
        except IncompleteScanError as exc:
            return service_result("incomplete", sanitize_error(exc))
        result_warnings.extend(consume_scan_warnings())
        coverage_warnings = consume_coverage_warnings()
        result_warnings.extend(str(warning.get("detail") or "Package advisory coverage is incomplete") for warning in coverage_warnings)

        if pkg.is_malicious:
            reason = pkg.malicious_reason or "flagged as malicious by package intelligence"
            return service_result(
                "malicious",
                f"MALICIOUS package {name}@{version} — {reason}. Do not install.",
            )

        coverage_gap = has_lookup_coverage_gap(coverage_warnings)
        if not pkg.vulnerabilities and coverage_gap:
            return service_result(
                "incomplete",
                f"Advisory coverage was incomplete for {name}@{version}; a clean verdict cannot be trusted",
            )

        if not pkg.vulnerabilities and eco in {"deb", "apk", "rpm"} and not os_context_complete:
            return service_result(
                "incomplete",
                "OS package context was insufficient for a trustworthy clean verdict",
                source_context={
                    "source_package": pkg.source_package,
                    "distro_name": pkg.distro_name,
                    "distro_version": pkg.distro_version,
                },
            )

        # An explicit pinned version that found no vulns might simply not exist
        # (a typo'd or hallucinated pin). Confirm it is published before calling
        # it clean, so a fake pin can't read as safe.
        if not offline and not pkg.vulnerabilities and version not in ("latest", "") and eco in ("npm", "pypi"):
            from agent_bom.http_client import create_client

            async with create_client(timeout=15.0) as client:
                published = await _version_published(name, version, eco, client)
            if not published:
                return service_result(
                    "unknown",
                    (
                        f"Version {version} of {name} was not found in the {eco} registry — "
                        f"cannot confirm it is free of vulnerabilities (typo or unpublished "
                        f"version?). agent-bom only verifies published versions."
                    ),
                )

        if not pkg.vulnerabilities:
            return service_result("clean", f"No known vulnerabilities in {name}@{version}")

        return service_result(
            "vulnerable",
            f"{len(pkg.vulnerabilities)} known vulnerabilities in {name}@{version}",
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
        from agent_bom.sast import SASTResult, SASTScanError, scan_code

        _packages, sast_result = scan_code(str(scan_path), config=config)
        return _truncate_response(json.dumps(sast_result.to_dict(), indent=2))
    except SASTScanError as exc:
        detail_by_reason = {
            "offline_remote_config": "SAST skipped because offline mode disallows registry-backed rules.",
            "offline_no_local_config": "SAST skipped because offline mode found no local rule configuration.",
            "semgrep_unavailable": "SAST skipped because Semgrep is unavailable.",
        }
        payload = SASTResult(
            execution_status=exc.execution_status,
            status_reason=exc.reason_code,
            status_detail=detail_by_reason.get(exc.reason_code, "SAST execution failed."),
        ).to_dict()
        return _truncate_response(json.dumps(payload, indent=2))
    except Exception:
        logger.error("code_scan failed")
        from agent_bom.sast import SASTExecutionStatus, SASTResult

        payload = SASTResult(
            execution_status=SASTExecutionStatus.FAILED,
            status_reason="unexpected_failure",
            status_detail="SAST execution failed.",
        ).to_dict()
        return _truncate_response(json.dumps(payload, indent=2))
