"""Policy-as-code engine for agent-bom.

Allows teams to define declarative security rules that are evaluated against
scan results and produce structured violations. Rules are loaded from a JSON
or YAML policy file and evaluated against BlastRadius findings.

Example policy file (policy.json):
{
  "version": "1",
  "name": "production-security-policy",
  "rules": [
    {
      "id": "no-critical",
      "description": "No critical vulnerabilities allowed",
      "severity_gte": "CRITICAL",
      "action": "fail"
    },
    {
      "id": "no-kev",
      "description": "CISA Known Exploited Vulnerabilities must be fixed immediately",
      "is_kev": true,
      "action": "fail"
    },
    {
      "id": "no-ai-with-creds",
      "description": "AI framework packages with credentials must not have high+ vulns",
      "ai_risk": true,
      "has_credentials": true,
      "severity_gte": "HIGH",
      "action": "fail"
    },
    {
      "id": "warn-medium-with-creds",
      "description": "Medium vulns in servers with credentials generate warnings",
      "has_credentials": true,
      "severity_gte": "MEDIUM",
      "action": "warn"
    }
  ]
}
"""

from __future__ import annotations

import json
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
RISK_LEVEL_ORDER = {"high": 3, "medium": 2, "low": 1}

POLICY_TEMPLATE = {
    "version": "1",
    "name": "my-security-policy",
    "rules": [
        {
            "id": "no-kev",
            "description": "CISA Known Exploited Vulnerabilities must be fixed immediately",
            "is_kev": True,
            "action": "fail",
        },
        {
            "id": "no-critical",
            "description": "No critical vulnerabilities allowed",
            "severity_gte": "CRITICAL",
            "action": "fail",
        },
        {
            "id": "no-ai-creds-high",
            "description": "AI framework packages with exposed credentials must not have high+ vulnerabilities",
            "ai_risk": True,
            "has_credentials": True,
            "severity_gte": "HIGH",
            "action": "fail",
        },
        {
            "id": "warn-high-with-creds",
            "description": "High vulnerabilities in servers with credentials trigger a warning",
            "has_credentials": True,
            "severity_gte": "HIGH",
            "action": "warn",
        },
        {
            "id": "warn-medium",
            "description": "Medium vulnerabilities generate advisory warnings",
            "severity_gte": "MEDIUM",
            "action": "warn",
        },
        {
            "id": "no-unverified-high",
            "description": "Unverified MCP servers with high+ vulnerabilities are blocked",
            "unverified_server": True,
            "severity_gte": "HIGH",
            "action": "fail",
        },
        {
            "id": "warn-excessive-agency",
            "description": "Servers with >5 tools and any CVE trigger excessive agency warning",
            "min_tools": 6,
            "action": "warn",
        },
        {
            "id": "no-high-risk-server-cve",
            "description": "High-risk registry servers must not have critical CVEs",
            "registry_risk_gte": "high",
            "severity_gte": "CRITICAL",
            "action": "fail",
        },
    ],
}


def load_policy(path: str) -> dict:
    """Load a policy file (JSON or YAML).

    Raises ValueError with a clear message if the file is invalid.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    text = p.read_text()

    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml
            data = yaml.safe_load(text)
        except ImportError:
            raise ImportError("PyYAML is required for YAML policy files: pip install pyyaml")
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in policy file: {e}")

    _validate_policy(data)
    return data


def _validate_policy(policy: dict) -> None:
    """Light validation of policy structure."""
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object")
    if "rules" not in policy:
        raise ValueError("Policy must have a 'rules' array")
    if not isinstance(policy["rules"], list):
        raise ValueError("Policy 'rules' must be an array")
    for i, rule in enumerate(policy["rules"]):
        if "id" not in rule:
            raise ValueError(f"Rule at index {i} missing 'id'")
        if rule.get("action") not in ("fail", "warn", None):
            raise ValueError(f"Rule '{rule['id']}' action must be 'fail' or 'warn'")


def _rule_matches(rule: dict, br) -> bool:
    """Check if a BlastRadius finding matches a policy rule.

    Conditions are ANDed: ALL specified conditions must be true.
    """
    # severity_gte: severity must be >= this level
    if "severity_gte" in rule:
        threshold = SEVERITY_ORDER.get(rule["severity_gte"].upper(), 0)
        actual = SEVERITY_ORDER.get(br.vulnerability.severity.value.upper(), 0)
        if actual < threshold:
            return False

    # is_kev: finding must be in CISA KEV catalog
    if rule.get("is_kev"):
        if not br.vulnerability.is_kev:
            return False

    # ai_risk: finding must have AI risk context (AI framework package)
    if rule.get("ai_risk"):
        if not br.ai_risk_context:
            return False

    # has_credentials: affected servers must expose credentials
    if rule.get("has_credentials"):
        if not br.exposed_credentials:
            return False

    # ecosystem: package must be from this ecosystem
    if "ecosystem" in rule:
        if br.package.ecosystem != rule["ecosystem"]:
            return False

    # package_name_contains: package name must contain this substring
    if "package_name_contains" in rule:
        if rule["package_name_contains"].lower() not in br.package.name.lower():
            return False

    # min_agents: finding must affect at least N agents
    if "min_agents" in rule:
        if len(br.affected_agents) < rule["min_agents"]:
            return False

    # min_tools: server must expose at least N tools (excessive agency)
    if "min_tools" in rule:
        if len(br.exposed_tools) < rule["min_tools"]:
            return False

    # unverified_server: package must come from an unverified registry entry
    if rule.get("unverified_server"):
        from agent_bom.parsers import get_registry_entry
        is_unverified = False
        for server in br.affected_servers:
            reg = get_registry_entry(server)
            if reg and not reg.get("verified", False):
                is_unverified = True
                break
        if not is_unverified:
            return False

    # registry_risk_gte: registry risk level must be >= threshold (low < medium < high)
    if "registry_risk_gte" in rule:
        from agent_bom.parsers import get_registry_entry
        threshold = RISK_LEVEL_ORDER.get(rule["registry_risk_gte"].lower(), 0)
        any_match = False
        for server in br.affected_servers:
            reg = get_registry_entry(server)
            if reg:
                actual = RISK_LEVEL_ORDER.get(reg.get("risk_level", "low"), 0)
                if actual >= threshold:
                    any_match = True
                    break
        if not any_match:
            return False

    # owasp_tag: finding must have this OWASP LLM Top 10 tag
    if "owasp_tag" in rule:
        tags = getattr(br, "owasp_tags", [])
        if rule["owasp_tag"] not in tags:
            return False

    return True


def evaluate_policy(policy: dict, blast_radii: list) -> dict:
    """Evaluate policy rules against blast radius findings.

    Returns a dict with:
      violations  – list of {rule, finding, action} for matching rules
      failures    – subset of violations where action == 'fail'
      warnings    – subset of violations where action == 'warn'
      passed      – True if no 'fail' violations
    """
    violations = []

    for rule in policy.get("rules", []):
        action = rule.get("action", "fail")
        for br in blast_radii:
            if _rule_matches(rule, br):
                violations.append({
                    "rule_id": rule["id"],
                    "rule_description": rule.get("description", ""),
                    "action": action,
                    "vulnerability_id": br.vulnerability.id,
                    "severity": br.vulnerability.severity.value,
                    "package": f"{br.package.name}@{br.package.version}",
                    "ecosystem": br.package.ecosystem,
                    "affected_agents": [a.name for a in br.affected_agents],
                    "exposed_credentials": br.exposed_credentials,
                    "is_kev": br.vulnerability.is_kev,
                    "ai_risk_context": br.ai_risk_context,
                })

    failures = [v for v in violations if v["action"] == "fail"]
    warnings = [v for v in violations if v["action"] == "warn"]

    return {
        "policy_name": policy.get("name", "unnamed"),
        "violations": violations,
        "failures": failures,
        "warnings": warnings,
        "passed": len(failures) == 0,
    }
