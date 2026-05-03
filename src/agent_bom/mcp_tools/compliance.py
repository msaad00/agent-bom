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
        from agent_bom.owasp_mcp import OWASP_MCP_TOP10

        agents, blast_radii, _warnings, _srcs = await _run_scan_pipeline(config_path, image)

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
                }
            )

        def _build_controls(catalog, tag_field, id_key):
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
                status = "pass" if findings == 0 else ("fail" if sev_bk["critical"] > 0 or sev_bk["high"] > 0 else "warning")
                controls.append(
                    {
                        id_key: code,
                        "name": name,
                        "findings": findings,
                        "status": status,
                        "severity_breakdown": sev_bk,
                        "affected_packages": sorted(pkgs),
                        "affected_agents": sorted(ags),
                    }
                )
            return controls

        owasp = _build_controls(OWASP_LLM_TOP10, "owasp_tags", "code")
        atlas = _build_controls(ATLAS_TECHNIQUES, "atlas_tags", "code")
        nist = _build_controls(NIST_AI_RMF, "nist_ai_rmf_tags", "code")
        owasp_mcp = _build_controls(OWASP_MCP_TOP10, "owasp_mcp_tags", "code")

        all_controls = owasp + atlas + nist + owasp_mcp
        total = len(all_controls)
        total_pass = sum(1 for c in all_controls if c["status"] == "pass")
        score = round((total_pass / total) * 100, 1) if total > 0 else 100.0
        has_fail = any(c["status"] == "fail" for c in all_controls)
        has_warn = any(c["status"] == "warning" for c in all_controls)

        return _truncate_response(
            json.dumps(
                {
                    "overall_score": score,
                    "overall_status": "fail" if has_fail else ("warning" if has_warn else "pass"),
                    "total_controls": total,
                    "owasp_llm_top10": owasp,
                    "mitre_atlas": atlas,
                    "nist_ai_rmf": nist,
                    "owasp_mcp_top10": owasp_mcp,
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
        if profile and not _re.fullmatch(r"[a-zA-Z0-9._-]{1,100}", profile):
            return json.dumps({"error": "Invalid AWS profile name. Use alphanumeric, dot, dash, underscore (max 100 chars)."})

        cis_report: object
        if provider == "aws":
            from agent_bom.cloud.aws_cis_benchmark import run_benchmark as run_aws_cis

            cis_report = run_aws_cis(region=region, profile=profile, checks=check_list)
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
