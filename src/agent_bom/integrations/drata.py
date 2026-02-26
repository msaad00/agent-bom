"""Drata integration — export GRC compliance evidence.

Drata is a compliance automation platform. This uploads scan results
as external evidence for SOC 2/ISO 27001 audits.

Uses the Drata REST API — no SDK dependency.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from agent_bom.http_client import create_client, request_with_retry

logger = logging.getLogger(__name__)

DRATA_API_URL = "https://public-api.drata.com"


async def upload_evidence(
    token: str,
    scan_result: dict,
    control_id: Optional[int] = None,
    evidence_name: str = "agent-bom AI Supply Chain Scan",
) -> Optional[str]:
    """Upload agent-bom scan results as Drata compliance evidence.

    Args:
        token: Drata API bearer token
        scan_result: Full JSON scan result from agent-bom
        control_id: Optional Drata control ID to link evidence to
        evidence_name: Human-readable evidence name

    Returns:
        Evidence ID or None on failure.
    """
    total_vulns = scan_result.get("summary", {}).get("total_vulnerabilities", 0)
    total_agents = scan_result.get("summary", {}).get("total_agents", 0)

    payload = {
        "name": evidence_name,
        "description": (
            f"AI supply chain security scan by agent-bom. "
            f"{total_agents} agent(s) scanned, {total_vulns} vulnerability(ies) found."
        ),
        "evidenceType": "EXTERNAL",
        "collectedAt": datetime.now(timezone.utc).isoformat(),
        "metadata": {
            "tool": "agent-bom",
            "version": scan_result.get("tool_version", ""),
            "total_agents": total_agents,
            "total_vulnerabilities": total_vulns,
        },
    }

    if control_id:
        payload["controlId"] = control_id

    url = f"{DRATA_API_URL}/public/evidence"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    async with create_client(timeout=15.0) as client:
        response = await request_with_retry(
            client, "POST", url, json_body=payload, headers=headers, max_retries=2,
        )

        if response and response.status_code in (200, 201):
            data = response.json()
            evidence_id = str(data.get("id", ""))
            logger.info("Drata evidence uploaded: %s", evidence_id)
            return evidence_id

        status = response.status_code if response else "no response"
        logger.warning("Drata evidence upload failed: %s", status)
        return None
