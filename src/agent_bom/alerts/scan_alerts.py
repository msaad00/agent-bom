"""Generate alerts from scan results.

Converts scan findings into alert dicts suitable for :class:`AlertDispatcher`.
Called automatically after scan completion when the alert pipeline is active.
"""

from __future__ import annotations

from datetime import datetime, timezone


def alerts_from_scan_result(report_dict: dict) -> list[dict]:
    """Generate alert dicts from a completed scan report.

    Triggers on:
    - CRITICAL/HIGH severity CVEs
    - CISA KEV (actively exploited) vulnerabilities
    - Malicious package detections
    - Policy violations (if policy results present)

    Args:
        report_dict: Serialized AIBOMReport (from ``to_json()``).

    Returns:
        List of alert dicts ready for dispatch.
    """
    alerts: list[dict] = []
    ts = datetime.now(timezone.utc).isoformat()

    blast_radii = report_dict.get("blast_radius", [])
    if not blast_radii:
        blast_radii = report_dict.get("blast_radii", [])

    for br in blast_radii:
        vuln = br if isinstance(br, dict) else {}
        vuln_id = vuln.get("vulnerability_id") or vuln.get("id", "")
        severity = (vuln.get("severity") or "").lower()
        is_kev = vuln.get("is_kev") or vuln.get("cisa_kev", False)
        package_name = vuln.get("package", {}).get("name", "") if isinstance(vuln.get("package"), dict) else vuln.get("package_name", "")
        risk_score = vuln.get("risk_score", 0)

        # CISA KEV — actively exploited
        if is_kev:
            alerts.append(
                {
                    "type": "scan_alert",
                    "detector": "scan_kev",
                    "severity": "critical",
                    "message": f"Actively exploited vulnerability {vuln_id} in {package_name} (CISA KEV)",
                    "details": {"vuln_id": vuln_id, "package": package_name, "risk_score": risk_score},
                    "ts": ts,
                }
            )

        # CRITICAL/HIGH CVEs
        elif severity in ("critical", "high"):
            alerts.append(
                {
                    "type": "scan_alert",
                    "detector": "scan_cve",
                    "severity": severity,
                    "message": f"{severity.upper()} vulnerability {vuln_id} in {package_name}",
                    "details": {"vuln_id": vuln_id, "package": package_name, "risk_score": risk_score},
                    "ts": ts,
                }
            )

    # Malicious packages
    for agent in report_dict.get("agents", []):
        for server in agent.get("mcp_servers", []):
            for pkg in server.get("packages", []):
                if pkg.get("is_malicious"):
                    alerts.append(
                        {
                            "type": "scan_alert",
                            "detector": "scan_malicious",
                            "severity": "critical",
                            "message": f"Malicious package detected: {pkg.get('name', '')}@{pkg.get('version', '')}",
                            "details": {
                                "package": pkg.get("name", ""),
                                "version": pkg.get("version", ""),
                                "reason": pkg.get("malicious_reason", ""),
                            },
                            "ts": ts,
                        }
                    )

    # Policy violations
    policy = report_dict.get("policy_results") or {}
    if policy.get("passed") is False:
        for violation in policy.get("violations", []):
            alerts.append(
                {
                    "type": "scan_alert",
                    "detector": "scan_policy",
                    "severity": violation.get("severity", "high"),
                    "message": f"Policy violation: {violation.get('rule', '')} — {violation.get('message', '')}",
                    "details": violation,
                    "ts": ts,
                }
            )

    return alerts
