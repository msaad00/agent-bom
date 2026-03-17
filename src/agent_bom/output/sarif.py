"""SARIF 2.1.0 output for GitHub Security tab integration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_bom.models import AIBOMReport, Severity

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


def to_sarif(report: AIBOMReport) -> dict:
    """Convert report to SARIF 2.1.0 dict for GitHub Security tab."""
    rules = []
    results = []
    seen_rule_ids: set[str] = set()

    for br in report.blast_radii:
        vuln = br.vulnerability
        rule_id = vuln.id
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

        config_path = br.affected_agents[0].config_path if br.affected_agents else "unknown"

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
            result["properties"] = {
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
                "blast_score": br.risk_score,
                "epss_score": vuln.epss_score,
                "is_kev": vuln.is_kev,
                "exposed_credentials": br.exposed_credentials,
            }
        results.append(result)

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

            fp_input = f"{rule_id}:{comp.get('file', '')}:{comp.get('line', 1)}"
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
                                "artifactLocation": {"uri": comp.get("file", "unknown"), "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": comp.get("line", 1), "startColumn": 1},
                            },
                        }
                    ],
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


def export_sarif(report: AIBOMReport, output_path: str) -> None:
    """Export report as SARIF 2.1.0 JSON file."""
    data = to_sarif(report)
    Path(output_path).write_text(json.dumps(data, indent=2))
