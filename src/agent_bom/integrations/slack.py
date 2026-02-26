"""Slack integration — send finding alerts via incoming webhook.

Uses Slack Block Kit for structured messages. No SDK — pure httpx.
"""

from __future__ import annotations

import logging

from agent_bom.http_client import create_client, request_with_retry

logger = logging.getLogger(__name__)

# Severity → emoji mapping
_SEVERITY_EMOJI: dict[str, str] = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "medium": ":large_yellow_circle:",
    "low": ":white_circle:",
}


def _build_slack_blocks(finding: dict) -> list[dict]:
    """Build Slack Block Kit blocks from a blast radius finding."""
    vuln_id = finding.get("vulnerability_id", "Unknown")
    severity = finding.get("severity", "medium")
    package = finding.get("package", "unknown")
    risk_score = finding.get("risk_score", 0)
    emoji = _SEVERITY_EMOJI.get(severity, ":question:")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} agent-bom Security Finding"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Vulnerability:*\n{vuln_id}"},
                {"type": "mrkdwn", "text": f"*Package:*\n{package}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_score}/10"},
            ],
        },
    ]

    # Affected agents/servers
    agents = finding.get("affected_agents", [])
    servers = finding.get("affected_servers", [])
    creds = finding.get("exposed_credentials", [])

    if agents or servers or creds:
        context_parts = []
        if agents:
            context_parts.append(f"*Agents:* {', '.join(agents)}")
        if servers:
            context_parts.append(f"*Servers:* {', '.join(servers)}")
        if creds:
            context_parts.append(f"*Credentials:* {', '.join(creds)}")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": " | ".join(context_parts)},
        })

    # Fix version if available
    fix = finding.get("fixed_version")
    if fix:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f":white_check_mark: *Fix:* Upgrade to `{fix}`"},
        })

    # Compliance tags
    tags = []
    for tag_field in ("owasp_tags", "owasp_mcp_tags", "atlas_tags", "nist_ai_rmf_tags"):
        tags.extend(finding.get(tag_field, []))
    if tags:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Compliance: {' '.join(tags)}"}],
        })

    return blocks


async def send_slack_alert(
    webhook_url: str,
    finding: dict,
) -> bool:
    """Send a finding alert to a Slack channel via incoming webhook.

    Args:
        webhook_url: Slack incoming webhook URL
        finding: Blast radius dict from agent-bom scan output

    Returns:
        True if message was sent successfully.
    """
    blocks = _build_slack_blocks(finding)
    payload = {"blocks": blocks}

    async with create_client(timeout=10.0) as client:
        response = await request_with_retry(
            client, "POST", webhook_url, json_body=payload, max_retries=2,
        )

        if response and response.status_code == 200:
            logger.info("Slack alert sent for %s", finding.get("vulnerability_id", "?"))
            return True

        status = response.status_code if response else "no response"
        logger.warning("Slack alert failed: %s", status)
        return False


def build_summary_message(findings: list[dict]) -> dict:
    """Build a summary Slack message for multiple findings.

    Returns a Slack message payload dict.
    """
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") == "low")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": ":shield: agent-bom Scan Summary"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Total Findings:*\n{len(findings)}"},
                {"type": "mrkdwn", "text": f"*Critical:* {critical} | *High:* {high} | *Medium:* {medium} | *Low:* {low}"},
            ],
        },
    ]

    # Top 3 highest risk findings
    top = sorted(findings, key=lambda f: f.get("risk_score", 0), reverse=True)[:3]
    if top:
        top_text = "\n".join(
            f"- `{f.get('package', '?')}` — {f.get('vulnerability_id', '?')} (risk {f.get('risk_score', 0):.1f})"
            for f in top
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Top Risks:*\n{top_text}"},
        })

    return {"blocks": blocks}
