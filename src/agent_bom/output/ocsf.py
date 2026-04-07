"""OCSF v1.1 audit log format for agent-bom runtime alerts.

Converts runtime alerts to Open Cybersecurity Schema Framework (OCSF) v1.1
format for enterprise SIEM integration (Splunk, CrowdStrike, Elastic, etc.).

OCSF event class: Security Finding (2001)
Category: Findings (2)
Profile: Security Control

References:
- https://schema.ocsf.io/1.1.0/classes/security_finding
- https://ocsf.io
"""

from __future__ import annotations

import time
from typing import Any

from agent_bom.graph import SEVERITY_TO_OCSF as _SEVERITY_MAP

# Detector → OCSF analytic type mapping
_ANALYTIC_TYPE: dict[str, str] = {
    "argument_analyzer": "Rule",
    "credential_leak": "Rule",
    "pii_leak": "Rule",
    "tool_drift": "Behavioral",
    "rate_limit": "Statistical",
    "sequence_analyzer": "Behavioral",
    "response_inspector": "Rule",
    "vector_db_injection": "Rule",
    "shield_correlation": "Correlation",
    "shield_killswitch": "Policy",
}


def alert_to_ocsf(alert: dict, product_version: str = "") -> dict[str, Any]:
    """Convert an agent-bom runtime alert to OCSF v1.1 Security Finding.

    Args:
        alert: Runtime alert dict from ProtectionEngine.
        product_version: agent-bom version string.

    Returns:
        OCSF v1.1 Security Finding event dict.
    """
    severity = alert.get("severity", "info").lower()
    detector = alert.get("detector", "unknown")
    details = alert.get("details", {})

    return {
        # OCSF metadata
        "class_uid": 2001,  # Security Finding
        "class_name": "Security Finding",
        "category_uid": 2,  # Findings
        "category_name": "Findings",
        "severity_id": _SEVERITY_MAP.get(severity, 1),
        "severity": severity.capitalize(),
        "activity_id": 1,  # Create
        "activity_name": "Create",
        "type_uid": 200101,  # Security Finding: Create
        "status_id": 1,  # New
        "status": "New",
        "time": int(time.time() * 1000),
        "message": alert.get("message", ""),
        # Finding details
        "finding_info": {
            "title": alert.get("message", ""),
            "uid": f"{detector}:{details.get('tool', 'unknown')}:{alert.get('ts', '')}",
            "types": [detector],
            "analytic": {
                "type": _ANALYTIC_TYPE.get(detector, "Other"),
                "name": detector,
                "uid": detector,
            },
        },
        # Resource (the MCP tool being analyzed)
        "resources": [
            {
                "type": "Other",
                "name": details.get("tool", "unknown"),
                "data": {k: v for k, v in details.items() if k not in ("tool",) and isinstance(v, (str, int, float, bool))},
            }
        ],
        # Product metadata
        "metadata": {
            "product": {
                "name": "agent-bom",
                "vendor_name": "agent-bom",
                "version": product_version,
            },
            "version": "1.1.0",
            "profiles": ["security_control"],
        },
    }


def alerts_to_ocsf(alerts: list[dict], product_version: str = "") -> list[dict]:
    """Convert a list of runtime alerts to OCSF v1.1 format."""
    return [alert_to_ocsf(a, product_version) for a in alerts]
