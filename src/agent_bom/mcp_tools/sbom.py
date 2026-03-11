"""SBOM tools — generate_sbom, remediate, diff implementations."""

from __future__ import annotations

import json
import logging

from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


async def generate_sbom_impl(
    *,
    format: str = "cyclonedx",
    config_path: str | None = None,
    _run_scan_pipeline,
    _truncate_response,
) -> str:
    """Implementation of the generate_sbom tool."""
    try:
        from agent_bom.models import AIBOMReport
        from agent_bom.output import to_cyclonedx, to_spdx

        agents, blast_radii, _warnings, scan_sources = await _run_scan_pipeline(config_path=config_path)
        if not agents:
            return json.dumps({"error": "No agents found to generate SBOM from"})

        report = AIBOMReport(agents=agents, blast_radii=blast_radii, scan_sources=scan_sources)

        if format.lower() == "spdx":
            return _truncate_response(json.dumps(to_spdx(report), indent=2, default=str))
        else:
            return _truncate_response(json.dumps(to_cyclonedx(report), indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def remediate_impl(
    *,
    config_path: str | None = None,
    image: str | None = None,
    _run_scan_pipeline,
    _truncate_response,
) -> str:
    """Implementation of the remediate tool."""
    try:
        from agent_bom.models import AIBOMReport
        from agent_bom.remediate import generate_remediation

        agents, blast_radii, _warnings, scan_sources = await _run_scan_pipeline(config_path, image)
        if not agents:
            return json.dumps(
                {
                    "package_fixes": [],
                    "credential_fixes": [],
                    "unfixable": [],
                    "message": "No agents found — nothing to remediate",
                }
            )

        report = AIBOMReport(agents=agents, blast_radii=blast_radii, scan_sources=scan_sources)
        plan = generate_remediation(report, blast_radii)

        return _truncate_response(
            json.dumps(
                {
                    "generated_at": plan.generated_at,
                    "package_fixes": [
                        {
                            "package": f.package,
                            "ecosystem": f.ecosystem,
                            "current_version": f.current_version,
                            "fixed_version": f.fixed_version,
                            "command": f.command,
                            "vulns": f.vulns[:5],
                            "total_vulns": len(f.vulns),
                            "agents": f.agents[:5],
                            "total_agents": len(f.agents),
                            "references": f.references[:10],
                            "total_references": len(f.references),
                        }
                        for f in plan.package_fixes
                    ],
                    "credential_fixes": [
                        {
                            "credential": f.credential_name,
                            "locations": f.locations[:5],
                            "total_locations": len(f.locations),
                            "risk": f.risk_description,
                            "fix_steps": f.fix_steps,
                        }
                        for f in plan.credential_fixes
                    ],
                    "total_unfixable": len(plan.unfixable),
                    "unfixable": plan.unfixable[:10],
                },
                indent=2,
                default=str,
            )
        )
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def diff_impl(
    *,
    baseline: dict | None = None,
    _run_scan_pipeline,
    _truncate_response,
) -> str:
    """Implementation of the diff tool."""
    try:
        from agent_bom.history import diff_reports, latest_report, load_report, save_report
        from agent_bom.models import AIBOMReport
        from agent_bom.output import to_json

        agents, blast_radii, _warnings, scan_sources = await _run_scan_pipeline()
        if not agents:
            return json.dumps({"error": "No agents found — nothing to diff"})

        report = AIBOMReport(agents=agents, blast_radii=blast_radii, scan_sources=scan_sources)
        current = to_json(report)

        if baseline is None:
            latest = latest_report()
            if latest:
                baseline = load_report(latest)
            else:
                save_report(current)
                return json.dumps(
                    {
                        "message": "No baseline found. Current scan saved as first baseline.",
                        "current_summary": current.get("summary", {}),
                    },
                    indent=2,
                    default=str,
                )

        result = diff_reports(baseline, current)
        save_report(current)
        return _truncate_response(json.dumps(result, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})
