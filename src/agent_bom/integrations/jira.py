"""Jira integration — create tickets from agent-bom findings.

Uses the Jira REST API v3 with basic auth (email + API token).
No SDK dependencies — pure httpx.
"""

from __future__ import annotations

import logging
from typing import Optional

from agent_bom.http_client import create_client, request_with_retry

logger = logging.getLogger(__name__)

# Severity → Jira priority mapping
_SEVERITY_PRIORITY: dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "none": "Lowest",
}


async def create_jira_ticket(
    jira_url: str,
    email: str,
    api_token: str,
    project_key: str,
    finding: dict,
    issue_type: str = "Bug",
) -> Optional[str]:
    """Create a Jira ticket from a blast radius finding.

    Args:
        jira_url: Jira instance URL (e.g. https://company.atlassian.net)
        email: Jira user email for basic auth
        api_token: Jira API token
        project_key: Jira project key (e.g. SEC)
        finding: Blast radius dict from agent-bom scan output
        issue_type: Jira issue type (default: Bug)

    Returns:
        Ticket key (e.g. SEC-123) or None on failure.
    """
    vuln_id = finding.get("vulnerability_id", "Unknown")
    severity = finding.get("severity", "medium")
    package = finding.get("package", "unknown")
    risk_score = finding.get("risk_score", 0)
    fix_version = finding.get("fixed_version")

    summary = f"[agent-bom] {vuln_id} in {package} (risk {risk_score:.1f}/10)"

    description_parts = [
        f"*Vulnerability:* {vuln_id}",
        f"*Package:* {package}",
        f"*Severity:* {severity}",
        f"*Risk Score:* {risk_score}/10",
        f"*Affected Agents:* {', '.join(finding.get('affected_agents', []))}",
        f"*Affected Servers:* {', '.join(finding.get('affected_servers', []))}",
        f"*Exposed Credentials:* {', '.join(finding.get('exposed_credentials', []))}",
    ]
    if fix_version:
        description_parts.append(f"*Fix:* Upgrade to {fix_version}")
    if finding.get("owasp_tags"):
        description_parts.append(f"*OWASP LLM:* {', '.join(finding['owasp_tags'])}")
    if finding.get("owasp_mcp_tags"):
        description_parts.append(f"*OWASP MCP:* {', '.join(finding['owasp_mcp_tags'])}")

    description = "\n".join(description_parts)

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary[:255],
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": description}]}],
            },
            "issuetype": {"name": issue_type},
            "priority": {"name": _SEVERITY_PRIORITY.get(severity, "Medium")},
            "labels": ["agent-bom", "security", f"severity-{severity}"],
        }
    }

    url = f"{jira_url.rstrip('/')}/rest/api/3/issue"

    async with create_client(timeout=15.0) as client:
        import base64
        auth_str = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth_str}",
            "Content-Type": "application/json",
        }
        response = await request_with_retry(
            client, "POST", url, json_body=payload, headers=headers, max_retries=2,
        )

        if response and response.status_code in (200, 201):
            data = response.json()
            ticket_key = data.get("key", "")
            logger.info("Jira ticket created: %s", ticket_key)
            return ticket_key

        status = response.status_code if response else "no response"
        logger.warning("Jira ticket creation failed: %s", status)
        return None
