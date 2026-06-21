"""OCSF v1.1 audit log format for agent-bom runtime alerts.

Converts runtime alerts to Open Cybersecurity Schema Framework (OCSF) v1.1
format for enterprise SIEM and detection-platform integration.

OCSF event class: Security Finding (2001)
Category: Findings (2)
Profile: Security Control

References:
- https://schema.ocsf.io/1.1.0/classes/security_finding
- https://ocsf.io
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from agent_bom.asset_provenance import sanitize_discovery_provenance
from agent_bom.graph import SEVERITY_TO_OCSF as _SEVERITY_MAP
from agent_bom.security import sanitize_sensitive_payload

if TYPE_CHECKING:
    from agent_bom.finding import Finding

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
    safe_details: dict[str, Any] = {}
    if isinstance(details, dict):
        sanitized = sanitize_sensitive_payload(details, max_str_len=1000)
        if isinstance(sanitized, dict):
            safe_details = sanitized
    if isinstance(details, dict) and "discovery_provenance" in details:
        safe_provenance = sanitize_discovery_provenance(details.get("discovery_provenance"))
        if safe_provenance:
            safe_details["discovery_provenance"] = safe_provenance

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
                "name": details.get("tool", "unknown") if isinstance(details, dict) else "unknown",
                "data": {k: v for k, v in safe_details.items() if k != "tool"},
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


# OCSF Security Finding status_id values (schema.ocsf.io). A suppressed finding
# must surface as Suppressed (4) so SIEM/detection platforms can filter it out
# rather than treating it as a live "New" detection.
_OCSF_STATUS_NEW = 1
_OCSF_STATUS_SUPPRESSED = 4


def finding_to_ocsf(finding: "Finding", product_version: str = "") -> dict[str, Any]:
    """Convert a unified :class:`~agent_bom.finding.Finding` to OCSF v1.1.

    This is the Finding-native OCSF path (vs :func:`alert_to_ocsf`, which is
    runtime-alert-native). It preserves the fields the unified Finding now
    carries — **suppression state** (mapped to ``status_id``/``status``),
    AI-native risk context, and the structured reach lists — so a suppressed
    finding never appears as a live detection downstream and reach is not
    collapsed to bare counts.
    """
    severity = str(finding.severity or "info").lower()
    suppressed = bool(finding.suppressed)
    status_id = _OCSF_STATUS_SUPPRESSED if suppressed else _OCSF_STATUS_NEW
    status = "Suppressed" if suppressed else "New"

    finding_info: dict[str, Any] = {
        "title": finding.title or finding.finding_type.value,
        "uid": finding.id,
        "desc": finding.description or "",
        "types": [finding.finding_type.value],
        "src_url": None,
    }
    if finding.cve_id:
        finding_info["uid"] = finding.id
        finding_info["cve"] = {"uid": finding.cve_id}

    # AI-native risk context — kept on a dedicated namespaced bag so SIEM
    # consumers can surface the LLM narrative + attack-vector summary.
    ai_context = {
        key: value
        for key, value in (
            ("ai_risk_context", finding.ai_risk_context),
            ("ai_summary", finding.ai_summary),
            ("attack_vector_summary", finding.attack_vector_summary),
        )
        if value
    }

    # Suppression detail (beyond status_id) lives in unmapped so nothing is lost.
    suppression: dict[str, Any] = {}
    if suppressed or finding.suppression_id or finding.suppression_state:
        suppression = {
            key: value
            for key, value in (
                ("suppressed", suppressed),
                ("suppression_id", finding.suppression_id),
                ("suppression_state", finding.suppression_state),
                ("suppression_reason", finding.suppression_reason),
                ("unsuppressed_risk_score", finding.unsuppressed_risk_score),
            )
            if value is not None
        }

    unmapped: dict[str, Any] = {
        "risk_score": finding.risk_score,
        # Structured reach lists — not collapsed to counts.
        "affected_servers": list(finding.affected_servers),
        "affected_agents": list(finding.affected_agents),
        "exposed_credentials": list(finding.exposed_credentials),
        "exposed_tools": list(finding.exposed_tools),
    }
    if ai_context:
        unmapped["ai_context"] = ai_context
    if suppression:
        unmapped["suppression"] = suppression

    return {
        "class_uid": 2001,  # Security Finding
        "class_name": "Security Finding",
        "category_uid": 2,  # Findings
        "category_name": "Findings",
        "severity_id": _SEVERITY_MAP.get(severity, 1),
        "severity": severity.capitalize(),
        "activity_id": 1,  # Create
        "activity_name": "Create",
        "type_uid": 200101,  # Security Finding: Create
        "status_id": status_id,
        "status": status,
        "time": int(time.time() * 1000),
        "message": finding.title or finding.description or finding.finding_type.value,
        "finding_info": finding_info,
        "resources": [
            {
                "type": finding.asset.asset_type,
                "name": finding.asset.name,
                "uid": finding.asset.stable_id,
            }
        ],
        "metadata": {
            "product": {
                "name": "agent-bom",
                "vendor_name": "agent-bom",
                "version": product_version,
            },
            "version": "1.1.0",
            "profiles": ["security_control"],
        },
        "unmapped": unmapped,
    }


def findings_to_ocsf(findings: "list[Finding]", product_version: str = "") -> list[dict]:
    """Convert a list of unified findings to OCSF v1.1 Security Findings."""
    return [finding_to_ocsf(f, product_version) for f in findings]
