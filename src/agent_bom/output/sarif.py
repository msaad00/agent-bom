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
            rule: dict = {
                "id": rule_id,
                "shortDescription": {"text": f"{vuln.severity.value.upper()}: {vuln.id} in {br.package.name}@{br.package.version}"},
                "fullDescription": {"text": vuln.summary or f"Vulnerability {vuln.id}"},
                "helpUri": f"https://osv.dev/vulnerability/{vuln.id}",
                "defaultConfiguration": {"level": level},
            }
            if vuln.cwe_ids:
                rule["properties"] = {"tags": vuln.cwe_ids}
            rules.append(rule)

        affected = ", ".join(a.name for a in br.affected_agents)
        message_text = f"{vuln.id} ({vuln.severity.value}) in {br.package.name}@{br.package.version}. Affects agents: {affected}."
        if vuln.fixed_version:
            message_text += f" Fix: upgrade to {vuln.fixed_version}."

        config_path = br.affected_agents[0].config_path if br.affected_agents else "unknown"

        fp_input = f"{rule_id}:{br.package.name}:{br.package.version}:{config_path}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()

        result: dict = {
            "ruleId": rule_id,
            "level": level,
            "kind": "fail",
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
                "blast_score": br.risk_score,
                "exposed_credentials": br.exposed_credentials,
            }
        results.append(result)

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
            }
        ],
    }


def export_sarif(report: AIBOMReport, output_path: str) -> None:
    """Export report as SARIF 2.1.0 JSON file."""
    data = to_sarif(report)
    Path(output_path).write_text(json.dumps(data, indent=2))
