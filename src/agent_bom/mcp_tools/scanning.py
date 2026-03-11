"""Scanning tools — scan, check, code_scan implementations."""

from __future__ import annotations

import json
import logging

from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


async def scan_impl(
    *,
    config_path: str | None = None,
    image: str | None = None,
    sbom_path: str | None = None,
    enrich: bool = False,
    scorecard: bool = False,
    transitive: bool = False,
    verify_integrity: bool = False,
    fail_severity: str | None = None,
    warn_severity: str | None = None,
    policy: dict | None = None,
    _run_scan_pipeline,
    _truncate_response,
) -> str:
    """Implementation of the scan tool."""
    try:
        from agent_bom.models import AIBOMReport
        from agent_bom.output import to_json

        agents, blast_radii, scan_warnings, scan_sources = await _run_scan_pipeline(
            config_path,
            image,
            sbom_path,
            enrich,
            transitive=transitive,
        )
        if not agents:
            result: dict[str, object] = {"status": "no_agents_found", "agents": [], "blast_radii": []}
            if scan_warnings:
                result["warnings"] = scan_warnings
            return _truncate_response(json.dumps(result))

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
                from agent_bom.scorecard import enrich_packages_with_scorecard

                all_pkgs = [p for a in agents for s in a.mcp_servers for p in s.packages]
                if all_pkgs:
                    await enrich_packages_with_scorecard(all_pkgs)
            except Exception as exc:
                logger.debug("Scorecard enrichment failed: %s", exc)

        report = AIBOMReport(agents=agents, blast_radii=blast_radii, scan_sources=scan_sources)
        result = to_json(report)

        # Policy evaluation
        if policy:
            from agent_bom.policy import _validate_policy, evaluate_policy

            _validate_policy(policy)
            result["policy_results"] = evaluate_policy(policy, blast_radii)

        # Severity gate (fail)
        if fail_severity:
            from agent_bom.models import Severity

            severity_order = ["critical", "high", "medium", "low"]
            try:
                threshold = Severity(fail_severity.lower())
                threshold_idx = severity_order.index(threshold.value)
            except (ValueError, KeyError):
                return json.dumps({"error": f"Invalid severity: {fail_severity}. Use: critical, high, medium, low"})
            gate_fail = any(
                severity_order.index(sev) <= threshold_idx
                for br in blast_radii
                if (sev := br.vulnerability.severity.value) in severity_order
            )
            result["gate_status"] = "fail" if gate_fail else "pass"
            result["gate_severity"] = fail_severity.lower()

        # Warn severity gate (two-tier: only fires when fail gate did not trigger)
        if warn_severity and result.get("gate_status") != "fail":
            from agent_bom.models import Severity

            severity_order = ["critical", "high", "medium", "low"]
            try:
                warn_threshold = Severity(warn_severity.lower())
                warn_threshold_idx = severity_order.index(warn_threshold.value)
            except (ValueError, KeyError):
                return json.dumps({"error": f"Invalid warn_severity: {warn_severity}. Use: critical, high, medium, low"})
            warn_matches = [
                br
                for br in blast_radii
                if br.vulnerability.severity.value in severity_order
                and severity_order.index(br.vulnerability.severity.value) <= warn_threshold_idx
            ]
            result["warn_gate_status"] = "warn" if warn_matches else "pass"
            result["warn_gate_severity"] = warn_severity.lower()
            result["warn_gate_count"] = len(warn_matches)

        if scan_warnings:
            result["warnings"] = scan_warnings
        return _truncate_response(json.dumps(result, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def check_impl(
    *,
    package: str,
    ecosystem: str = "npm",
    _validate_ecosystem,
    _truncate_response,
) -> str:
    """Implementation of the check tool."""
    try:
        from agent_bom.models import Package as Pkg
        from agent_bom.scanners import build_vulnerabilities, query_osv_batch

        # Parse name@version
        spec = package.strip()
        if "@" in spec and not spec.startswith("@"):
            name, version = spec.rsplit("@", 1)
        elif spec.startswith("@") and spec.count("@") > 1:
            last_at = spec.rindex("@")
            name, version = spec[:last_at], spec[last_at + 1 :]
        else:
            name, version = spec, "latest"

        try:
            eco = _validate_ecosystem(ecosystem)
        except ValueError as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})
        pkg = Pkg(name=name, version=version, ecosystem=eco)

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
                        "error": f"Could not resolve latest version for {name}",
                    }
                )

        results = await query_osv_batch([pkg])
        key = f"{eco}:{name}@{version}"
        vuln_data = results.get(key, [])

        if not vuln_data:
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

        vulns = build_vulnerabilities(vuln_data, pkg)
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
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


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
        return json.dumps({"error": sanitize_error(exc)})

    try:
        from agent_bom.sast import SASTScanError, scan_code

        _packages, sast_result = scan_code(str(scan_path), config=config)
        return _truncate_response(json.dumps(sast_result.to_dict(), indent=2))
    except SASTScanError as exc:
        return json.dumps({"error": sanitize_error(exc)})
    except Exception as exc:
        logger.error("code_scan error: %s", exc)
        return json.dumps({"error": sanitize_error(exc)})
