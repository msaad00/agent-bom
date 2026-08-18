"""Compliance tools — policy_check, cis_benchmark, aisvs_benchmark, license_compliance_scan implementations."""

from __future__ import annotations

import json
import logging

from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


async def policy_check_impl(
    *,
    policy_json: str,
    _run_scan_pipeline,
    _truncate_response,
) -> str:
    """Implementation of the policy_check tool."""
    try:
        from agent_bom.policy import _validate_policy, evaluate_policy

        policy = json.loads(policy_json)
        _validate_policy(policy)

        _agents, blast_radii, _warnings, _srcs = await _run_scan_pipeline()
        result = evaluate_policy(policy, blast_radii)
        return _truncate_response(json.dumps(result, indent=2, default=str))
    except json.JSONDecodeError as exc:
        return json.dumps({"error": f"Invalid JSON: {exc}"})
    except ValueError as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def compliance_impl(
    *,
    config_path: str | None = None,
    image: str | None = None,
    _run_scan_pipeline,
    _truncate_response,
) -> str:
    """Implementation of the compliance tool."""
    try:
        from agent_bom.atlas import ATLAS_TECHNIQUES
        from agent_bom.nist_ai_rmf import NIST_AI_RMF
        from agent_bom.owasp import OWASP_LLM_TOP10
        from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
        from agent_bom.owasp_mcp import OWASP_MCP_TOP10

        agents, blast_radii, _warnings, scan_sources = await _run_scan_pipeline(config_path, image)
        has_evidence = bool(agents or blast_radii or scan_sources)

        # Convert BlastRadius objects to dicts for aggregation
        br_dicts = []
        for br in blast_radii:
            br_dicts.append(
                {
                    "severity": br.vulnerability.severity.value,
                    "package": f"{br.package.name}@{br.package.version}",
                    "affected_agents": [a.name for a in br.affected_agents],
                    "owasp_tags": list(br.owasp_tags),
                    "atlas_tags": list(br.atlas_tags),
                    "nist_ai_rmf_tags": list(br.nist_ai_rmf_tags),
                    "owasp_mcp_tags": list(br.owasp_mcp_tags),
                    "owasp_agentic_tags": list(getattr(br, "owasp_agentic_tags", [])),
                    "nist_800_53_tags": list(getattr(br, "nist_800_53_tags", [])),
                }
            )

        def _build_controls(catalog, tag_field, id_key, *, scored: bool):
            controls = []
            for code, name in sorted(catalog.items()):
                sev_bk = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                pkgs, ags, findings = set(), set(), 0
                for br in br_dicts:
                    if code in br.get(tag_field, []):
                        findings += 1
                        sev = (br.get("severity") or "").lower()
                        if sev in sev_bk:
                            sev_bk[sev] += 1
                        if br.get("package"):
                            pkgs.add(br["package"])
                        for a in br.get("affected_agents", []):
                            ags.add(a)
                if not scored:
                    status = "applicable" if findings else "not_applicable"
                else:
                    # A scored control with no mapped finding is NOT a pass.
                    status = (
                        "fail"
                        if findings and (sev_bk["critical"] > 0 or sev_bk["high"] > 0)
                        else "warning"
                        if findings
                        else "not_evaluated"
                    )
                controls.append(
                    {
                        id_key: code,
                        "name": name,
                        "findings": findings,
                        "status": status,
                        "severity_breakdown": sev_bk,
                        "affected_packages": sorted(pkgs),
                        "affected_agents": sorted(ags),
                        "scored": scored,
                    }
                )
            return controls

        owasp = _build_controls(OWASP_LLM_TOP10, "owasp_tags", "code", scored=False)
        atlas = _build_controls(ATLAS_TECHNIQUES, "atlas_tags", "code", scored=False)
        nist = _build_controls(NIST_AI_RMF, "nist_ai_rmf_tags", "code", scored=True)
        owasp_mcp = _build_controls(OWASP_MCP_TOP10, "owasp_mcp_tags", "code", scored=False)
        owasp_agentic = _build_controls(
            OWASP_AGENTIC_TOP10,
            "owasp_agentic_tags",
            "code",
            scored=False,
        )

        all_catalog_entries = owasp + atlas + nist + owasp_mcp + owasp_agentic
        scored_controls = [control for control in all_catalog_entries if control["scored"]]
        total = len(all_catalog_entries)
        scored_total = len(scored_controls)
        # Same scorer as /v1/compliance, the per-framework route, the HTML
        # report and the evidence bundle. None of these catalogues carry
        # detective controls, so every evaluated control here is substantive.
        from agent_bom.evidence.scoring import score_compliance

        verdict = score_compliance(
            passed=sum(1 for c in scored_controls if c["status"] == "pass"),
            warned=sum(1 for c in scored_controls if c["status"] == "warning"),
            failed=sum(1 for c in scored_controls if c["status"] == "fail"),
            has_evidence=has_evidence,
        )
        evaluated_controls = verdict.evaluated
        not_evaluated_controls = scored_total - evaluated_controls
        score = verdict.score

        # Catalog-backed NIST SP 800-53 Rev 5 line (vendor-asserted), scored
        # INDEPENDENTLY over evaluated controls only via the shared scorer — the
        # SAME representation the /v1/compliance API and CLI narrative report.
        # Deliberately NOT folded into overall_score (the AI-framework score
        # above): the curated CVE evidence would otherwise be double-counted. No
        # CIS Foundations checks exist on the local-scan path, so CIS statuses
        # are empty; scan_count is 1 when agents were discovered so an unmapped
        # estate reads no_data, never a false pass.
        from agent_bom.compliance_nist_catalog import build_nist_800_53_catalog_line

        nist_800_53_catalog = build_nist_800_53_catalog_line(br_dicts, {}, 1 if has_evidence else 0)

        return _truncate_response(
            json.dumps(
                {
                    "overall_score": score,
                    "overall_status": verdict.status,
                    "total_controls": total,
                    "total_catalog_entries": len(all_catalog_entries),
                    "scored_controls": scored_total,
                    "unscored_catalog_entries": total - scored_total,
                    "evaluated_controls": evaluated_controls,
                    "not_evaluated_controls": not_evaluated_controls,
                    "owasp_llm_top10": owasp,
                    "mitre_atlas": atlas,
                    "nist_ai_rmf": nist,
                    "owasp_mcp_top10": owasp_mcp,
                    "owasp_agentic_top10": owasp_agentic,
                    "nist_800_53_catalog": nist_800_53_catalog,
                },
                indent=2,
                default=str,
            )
        )
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def cis_benchmark_impl(
    *,
    provider: str,
    checks: str | None = None,
    region: str | None = None,
    profile: str | None = None,
    subscription_id: str | None = None,
    project_id: str | None = None,
    _truncate_response,
) -> str:
    """Implementation of the cis_benchmark tool."""
    try:
        check_list = [c.strip() for c in checks.split(",")] if checks else None

        # Validate inputs to prevent injection
        import re as _re

        if region and not _re.fullmatch(r"[a-z]{2}(-gov)?-[a-z]+-\d{1,2}", region):
            return json.dumps({"error": f"Invalid AWS region format: {region}"})

        # This benchmark spends the control plane's own cloud identity, so it
        # carries the same operator opt-in as the REST surface. Gating one and
        # not the other would leave this tool as a way around it.
        from agent_bom.cloud.ambient_credentials import (
            PROFILE_REJECTED_NOTE,
            ambient_cis_enabled,
            configured_aws_profile,
            disabled_payload,
        )

        if profile:
            return json.dumps({"error": PROFILE_REJECTED_NOTE})
        profile = configured_aws_profile()
        if not ambient_cis_enabled():
            return json.dumps(disabled_payload(provider))

        cis_report: object
        if provider == "aws":
            if region:
                from agent_bom.cloud.aws_cis_benchmark import run_benchmark

                cis_report = run_benchmark(region=region, profile=profile, checks=check_list)
            else:
                from agent_bom.cloud.aws_cis_benchmark import run_benchmark_all_regions

                cis_report = run_benchmark_all_regions(region=region, profile=profile, checks=check_list)
        elif provider == "snowflake":
            from agent_bom.cloud.snowflake_cis_benchmark import run_benchmark as run_sf_cis

            cis_report = run_sf_cis(checks=check_list)
        elif provider == "azure":
            from agent_bom.cloud.azure_cis_benchmark import run_benchmark as run_azure_cis

            cis_report = run_azure_cis(subscription_id=subscription_id, checks=check_list)
        elif provider == "gcp":
            from agent_bom.cloud.gcp_cis_benchmark import run_benchmark as run_gcp_cis

            cis_report = run_gcp_cis(project_id=project_id, checks=check_list)
        else:
            return json.dumps({"error": f"Unsupported provider: {provider}. Use 'aws', 'snowflake', 'azure', or 'gcp'."})

        return _truncate_response(json.dumps(cis_report.to_dict(), indent=2, default=str))  # type: ignore[attr-defined]
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def aisvs_benchmark_impl(
    *,
    checks: str | None = None,
    _truncate_response,
) -> str:
    """Implementation of the aisvs_benchmark tool."""
    try:
        from agent_bom.cloud.aisvs_benchmark import run_benchmark as _run_aisvs

        check_list = [c.strip() for c in checks.split(",")] if checks else None
        report = _run_aisvs(checks=check_list)
        return _truncate_response(json.dumps(report.to_dict(), indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def license_compliance_scan_impl(
    *,
    scan_json: str,
    policy_json: str = "",
    scan_dir: str = "",
    _truncate_response,
) -> str:
    """Implementation of the license_compliance_scan tool."""
    try:
        from agent_bom.license_policy import evaluate_license_policy, to_serializable
        from agent_bom.models import Agent, AgentType, MCPServer, Package

        data = json.loads(scan_json)
        policy = json.loads(policy_json) if policy_json else None

        # Accept either a full scan result (with agents) or a flat package list
        agents: list[Agent] = []
        if isinstance(data, dict) and "agents" in data:
            # Full scan result -- reconstruct agents
            for agent_data in data["agents"]:
                servers = []
                for srv in agent_data.get("mcp_servers", []):
                    pkgs = [
                        Package(
                            name=p.get("name", ""),
                            version=p.get("version", ""),
                            ecosystem=p.get("ecosystem", ""),
                            license=p.get("license"),
                            license_expression=p.get("license_expression"),
                        )
                        for p in srv.get("packages", [])
                    ]
                    servers.append(MCPServer(name=srv.get("name", ""), command="", packages=pkgs))
                agents.append(Agent(name=agent_data.get("name", ""), agent_type=AgentType.CUSTOM, config_path="", mcp_servers=servers))
        elif isinstance(data, list):
            # Flat package list
            pkgs = [
                Package(
                    name=p.get("name", ""),
                    version=p.get("version", ""),
                    ecosystem=p.get("ecosystem", ""),
                    license=p.get("license"),
                    license_expression=p.get("license_expression"),
                )
                for p in data
            ]
            agents = [
                Agent(
                    name="input",
                    agent_type=AgentType.CUSTOM,
                    config_path="",
                    mcp_servers=[MCPServer(name="packages", command="", packages=pkgs)],
                )
            ]

        report = evaluate_license_policy(agents, policy=policy)
        result = to_serializable(report)

        # Optional: scan a local directory for LICENSE files and SPDX headers
        if scan_dir:
            from pathlib import Path

            from agent_bom.license_file_scanner import scan_directory

            dir_result = scan_directory(Path(scan_dir))
            result["license_file_scan"] = dir_result.to_dict()

        return _truncate_response(json.dumps(result, indent=2))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})
