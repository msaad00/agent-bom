"""SARIF 2.1.0 output for GitHub Security tab integration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from agent_bom.asset_provenance import agent_discovery_provenance, package_discovery_provenance, sanitize_discovery_provenance
from agent_bom.finding import FindingType
from agent_bom.models import AIBOMReport, Severity
from agent_bom.security import sanitize_sensitive_payload

_SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.NONE: "none",
    Severity.UNKNOWN: "note",
}

# GitHub Security tab uses security-severity (0.0–10.0) for granular sorting.
# Ranges per docs.github.com: >9.0=critical, 7.0–8.9=high, 4.0–6.9=medium, 0.1–3.9=low
_SECURITY_SEVERITY_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.5",
    Severity.NONE: "0.0",
    Severity.UNKNOWN: "0.0",
}


def _to_relative_path(path: str) -> str:
    """Convert an absolute path to a relative path suitable for SARIF.

    GitHub Code Scanning requires relative paths from the repo root.
    Absolute paths cause "No summary of scanned files" in the Security tab.
    For dependency findings, points to the most likely manifest file.
    """

    p = Path(path)
    # If it's a directory (e.g., project root from --self-scan), point to manifest
    if p.is_dir():
        for manifest in ("pyproject.toml", "package.json", "go.mod", "Cargo.toml", "requirements.txt"):
            if (p / manifest).exists():
                return manifest
        return "pyproject.toml"  # default fallback for Python projects

    # If it's an absolute path, try to make it relative to cwd
    if p.is_absolute():
        try:
            return str(p.relative_to(Path.cwd()))
        except ValueError:
            # Can't make relative — extract just the filename
            return p.name

    return path


def _sanitize_sarif_property(value: Any) -> Any:
    """Apply final defensive redaction before data leaves via SARIF."""
    return sanitize_sensitive_payload(value, max_str_len=1000)


def to_sarif(report: AIBOMReport, *, exclude_unfixable: bool = False) -> dict:
    """Convert report to SARIF 2.1.0 dict for GitHub Security tab.

    Args:
        exclude_unfixable: If True, skip findings where no fix is available
            (fixed_version is None/empty). Reduces noise in GitHub Security tab
            from CVEs that can't be acted on.
    """
    rules = []
    results = []
    seen_rule_ids: set[str] = set()

    for br in report.blast_radii:
        vuln = br.vulnerability
        rule_id = vuln.id

        # Skip unfixable findings when requested (no upstream fix available)
        if exclude_unfixable and not vuln.fixed_version:
            continue

        level = _SARIF_SEVERITY_MAP.get(vuln.severity, "warning")

        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            # Use actual CVSS score when available, otherwise map from severity
            sec_sev = str(vuln.cvss_score) if vuln.cvss_score is not None else _SECURITY_SEVERITY_SCORE.get(vuln.severity, "0.0")
            rule_props: dict = {"security-severity": sec_sev}
            if vuln.epss_score is not None:
                rule_props["epss-score"] = round(vuln.epss_score, 5)
            if vuln.is_kev:
                rule_props["kev"] = True
            # exploit_likelihood (issue #486) — graded signal computed
            # from KEV + EPSS percentile / probability.
            rule_props["exploit_likelihood"] = vuln.exploit_likelihood
            if vuln.cwe_ids:
                rule_props["tags"] = vuln.cwe_ids
            rule: dict = {
                "id": rule_id,
                "shortDescription": {"text": f"{vuln.severity.value.upper()}: {vuln.id} in {br.package.name}@{br.package.version}"},
                "fullDescription": {"text": vuln.summary or f"Vulnerability {vuln.id}"},
                "helpUri": f"https://osv.dev/vulnerability/{vuln.id}",
                "defaultConfiguration": {"level": level},
                "properties": rule_props,
            }
            rules.append(rule)

        affected = ", ".join(a.name for a in br.affected_agents)
        message_text = f"{vuln.id} ({vuln.severity.value}) in {br.package.name}@{br.package.version}. Affects agents: {affected}."
        if vuln.fixed_version:
            message_text += f" Fix: upgrade to {vuln.fixed_version}."

        raw_config_path = br.affected_agents[0].config_path if br.affected_agents else "unknown"
        # SARIF requires relative paths from repo root for GitHub Security tab.
        # Absolute paths cause "No summary of scanned files" in GitHub UI.
        config_path = _to_relative_path(raw_config_path)

        fp_input = f"{rule_id}:{br.package.name}:{br.package.version}:{config_path}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

        kind = "informational" if vuln.severity == Severity.NONE else "fail"
        result: dict = {
            "ruleId": rule_id,
            "level": level,
            "kind": kind,
            "message": {"text": message_text},
            "fingerprints": {
                "agent-bom/v1": fingerprint,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": config_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1,
                        },
                    },
                }
            ],
        }
        # Always emit structured properties so downstream consumers get
        # the exploit_likelihood (#486) + blast metrics without needing
        # a compliance tag to trigger enrichment.
        result_properties: dict = {
            "blast_score": br.risk_score,
            "epss_score": vuln.epss_score,
            "is_kev": vuln.is_kev,
            "exploit_likelihood": vuln.exploit_likelihood,
            "exposed_credentials": br.exposed_credentials,
            "impact_category": getattr(br, "impact_category", "code-execution"),
            "attack_vector_summary": getattr(br, "attack_vector_summary", None),
            "reachability": br.reachability,
        }
        package_provenance = package_discovery_provenance(br.package)
        if package_provenance:
            result_properties["package_discovery_provenance"] = _sanitize_sarif_property(package_provenance)
        agent_provenance = [
            provenance for provenance in (agent_discovery_provenance(agent) for agent in br.affected_agents[:10]) if provenance
        ]
        if agent_provenance:
            result_properties["agent_discovery_provenance"] = _sanitize_sarif_property(agent_provenance)
        server_provenance = [
            provenance
            for provenance in (
                sanitize_discovery_provenance(getattr(server, "discovery_provenance", None)) for server in br.affected_servers[:10]
            )
            if provenance
        ]
        if server_provenance:
            result_properties["server_discovery_provenance"] = _sanitize_sarif_property(server_provenance)
        if (
            br.owasp_tags
            or br.atlas_tags
            or br.nist_ai_rmf_tags
            or br.owasp_mcp_tags
            or br.owasp_agentic_tags
            or br.eu_ai_act_tags
            or br.nist_csf_tags
            or br.iso_27001_tags
            or br.soc2_tags
            or br.cis_tags
            or br.cmmc_tags
        ):
            result_properties.update(
                {
                    "owasp_tags": br.owasp_tags,
                    "atlas_tags": br.atlas_tags,
                    "attack_tags": getattr(br, "attack_tags", []),
                    "nist_ai_rmf_tags": br.nist_ai_rmf_tags,
                    "owasp_mcp_tags": br.owasp_mcp_tags,
                    "owasp_agentic_tags": br.owasp_agentic_tags,
                    "eu_ai_act_tags": br.eu_ai_act_tags,
                    "nist_csf_tags": br.nist_csf_tags,
                    "iso_27001_tags": br.iso_27001_tags,
                    "soc2_tags": br.soc2_tags,
                    "cis_tags": br.cis_tags,
                    "cmmc_tags": br.cmmc_tags,
                }
            )
        result["properties"] = result_properties
        results.append(result)

    # Unified non-CVE findings, including MCP intelligence/blocklist matches.
    finding_sev_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
    finding_sev_score = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "1.0", "info": "0.0"}
    for finding in report.to_findings():
        if finding.finding_type == FindingType.CVE:
            continue
        sev = str(finding.severity or "medium").lower()
        rule_id = f"finding/{finding.finding_type.value}"
        level = finding_sev_map.get(sev, "warning")
        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": finding.finding_type.value.replace("_", " ").title()},
                    "fullDescription": {"text": finding.description or finding.title or finding.finding_type.value},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "security-severity": finding_sev_score.get(sev, "4.0"),
                        "source": finding.source.value,
                        "finding_type": finding.finding_type.value,
                    },
                }
            )

        file_path = _to_relative_path(finding.asset.location or "agent-bom-report.json")
        fp_input = f"{finding.id}:{file_path}:{finding.asset.stable_id}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "kind": "fail" if level in {"error", "warning"} else "informational",
                "message": {"text": finding.title or finding.description or finding.finding_type.value},
                "fingerprints": {"agent-bom/v1": fingerprint},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": 1, "startColumn": 1},
                        },
                    }
                ],
                "properties": {
                    "risk_score": finding.risk_score,
                    "asset_type": finding.asset.asset_type,
                    "asset_name": finding.asset.name,
                    "evidence": _sanitize_sarif_property(finding.evidence),
                    "remediation_guidance": _sanitize_sarif_property(finding.remediation_guidance),
                },
            }
        )

    # IaC misconfiguration findings (Dockerfile, K8s, Terraform, CloudFormation)
    iac_data = getattr(report, "iac_findings_data", None)
    if iac_data:
        iac_sev_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
        iac_sev_score = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "1.0", "info": "0.0"}
        for iac_finding in iac_data.get("findings", []):
            sev = iac_finding.get("severity", "medium").lower()
            rule_id = f"iac/{iac_finding.get('rule_id', 'unknown')}"
            level = iac_sev_map.get(sev, "warning")
            file_path = _to_relative_path(iac_finding.get("file_path", "unknown") or "unknown")
            line_num = iac_finding.get("line_number") or 1

            if rule_id not in seen_rule_ids:
                seen_rule_ids.add(rule_id)
                rules.append(
                    {
                        "id": rule_id,
                        "shortDescription": {"text": iac_finding.get("title", rule_id)},
                        "fullDescription": {"text": iac_finding.get("message", iac_finding.get("title", ""))},
                        "defaultConfiguration": {"level": level},
                        "properties": {
                            "security-severity": iac_sev_score.get(sev, "4.0"),
                            "category": iac_finding.get("category", "iac"),
                            "compliance": iac_finding.get("compliance", []),
                        },
                    }
                )

            fp_input = f"{rule_id}:{file_path}:{line_num}"
            fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "kind": "fail",
                    "message": {"text": iac_finding.get("message", iac_finding.get("title", "IaC misconfiguration"))},
                    "fingerprints": {"agent-bom/v1": fingerprint},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": line_num, "startColumn": 1},
                            },
                        }
                    ],
                }
            )

    # AI inventory findings (shadow AI, deprecated models, API keys, invisible Unicode)
    ai_inv = getattr(report, "ai_inventory_data", None)
    if ai_inv:
        ai_sev_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
        ai_sev_score = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "1.0", "info": "0.0"}
        for comp in ai_inv.get("components", []):
            sev = comp.get("severity", "info")
            if sev not in ("critical", "high", "medium"):
                continue  # only actionable findings in SARIF
            comp_type = comp.get("type", "unknown")
            # Redact credential fragments — never embed key material in SARIF
            raw_name = comp.get("name", "")
            name = "[REDACTED]" if comp_type == "api_key" else raw_name
            rule_id = f"ai-inventory/{comp_type}/{name}"
            level = ai_sev_map.get(sev, "warning")

            if rule_id not in seen_rule_ids:
                seen_rule_ids.add(rule_id)
                rules.append(
                    {
                        "id": rule_id,
                        "shortDescription": {"text": f"{sev.upper()}: {comp_type.replace('_', ' ')} — {name}"},
                        "fullDescription": {"text": comp.get("description", "") or f"AI component finding: {name}"},
                        "defaultConfiguration": {"level": level},
                        "properties": {"security-severity": ai_sev_score.get(sev, "0.0")},
                    }
                )

            file_path = _to_relative_path(comp.get("file", "unknown") or "unknown")
            fp_input = f"{rule_id}:{file_path}:{comp.get('line', 1)}"
            fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()
            desc = comp.get("description", "") or f"{comp_type.replace('_', ' ')}: {name}"
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "kind": "fail",
                    "message": {"text": desc},
                    "fingerprints": {"agent-bom/v1": fingerprint},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": comp.get("line", 1), "startColumn": 1},
                            },
                        }
                    ],
                }
            )

    # CIS benchmark findings (AWS / Azure / GCP / Snowflake). Each failed
    # check emits a SARIF result with the structured remediation dict
    # (issue #665) in ``properties.remediation`` so GitHub Code Scanning
    # and downstream SARIF consumers can surface fix guidance per finding.
    cis_sev_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
    cis_sev_score = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "1.0", "info": "0.0"}
    for cloud_key, data_attr in (
        ("aws", "cis_benchmark_data"),
        ("azure", "azure_cis_benchmark_data"),
        ("gcp", "gcp_cis_benchmark_data"),
        ("snowflake", "snowflake_cis_benchmark_data"),
    ):
        bundle = getattr(report, data_attr, None)
        if not bundle:
            continue
        for check in bundle.get("checks", []):
            if check.get("status") != "fail":
                continue
            sev = (check.get("severity") or "medium").lower()
            check_id = check.get("check_id") or "unknown"
            rule_id = f"cis/{cloud_key}/{check_id}"
            level = cis_sev_map.get(sev, "warning")
            remediation = check.get("remediation") or {}
            title = check.get("title") or rule_id
            help_uri = remediation.get("docs") or ""

            if rule_id not in seen_rule_ids:
                seen_rule_ids.add(rule_id)
                cis_rule: dict = {
                    "id": rule_id,
                    "shortDescription": {"text": f"{sev.upper()}: CIS {cloud_key.upper()} {check_id} — {title}"},
                    "fullDescription": {"text": check.get("recommendation") or title},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "security-severity": cis_sev_score.get(sev, "4.0"),
                        "tags": ["cis", cloud_key, "compliance"],
                        "cis_section": check.get("cis_section") or "",
                    },
                }
                if help_uri:
                    cis_rule["helpUri"] = help_uri
                rules.append(cis_rule)

            # Synthetic fingerprint so repeat runs produce stable IDs.
            fp_input = f"{rule_id}:{','.join(check.get('resource_ids') or [])}"
            fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

            # CIS findings are cloud-control-level, not file-level. Point
            # at a conventional manifest so GitHub renders the result;
            # the rich context lives in ``properties``.
            result_props: dict = {
                "remediation": remediation,
                "cis_section": check.get("cis_section") or "",
                "evidence": _sanitize_sarif_property(check.get("evidence") or ""),
                "resource_ids": _sanitize_sarif_property(check.get("resource_ids") or []),
            }
            # Surface the remediation knobs flat for consumers that
            # can't (or don't want to) read nested dicts.
            if remediation:
                result_props["fix_cli"] = remediation.get("fix_cli")
                result_props["fix_console"] = remediation.get("fix_console") or ""
                result_props["effort"] = remediation.get("effort") or "manual"
                result_props["priority"] = remediation.get("priority") or 3
                result_props["guardrails"] = remediation.get("guardrails") or []
                result_props["requires_human_review"] = bool(remediation.get("requires_human_review"))

            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "kind": "fail",
                    "message": {"text": f"CIS {cloud_key.upper()} {check_id} failed: {title}"},
                    "fingerprints": {"agent-bom/v1": fingerprint},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"cis-{cloud_key}-benchmark", "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": 1, "startColumn": 1},
                            },
                        }
                    ],
                    "properties": result_props,
                }
            )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-bom",
                        "version": report.tool_version,
                        "informationUri": "https://github.com/msaad00/agent-bom",
                        "rules": rules,
                    }
                },
                "results": results,
                **({"automationDetails": {"id": f"agent-bom/{report.scan_id}"}} if report.scan_id else {}),
            }
        ],
    }


def export_sarif(
    report: AIBOMReport,
    output_path: str,
    *,
    exclude_unfixable: bool = False,
) -> None:
    """Export report as SARIF 2.1.0 JSON file."""
    data = to_sarif(report, exclude_unfixable=exclude_unfixable)
    Path(output_path).write_text(json.dumps(data, indent=2))
