"""SIEM wire-format projection for finding delta-stream batches."""

from __future__ import annotations

from typing import Any

from agent_bom.siem.ocsf import to_ocsf_detection_finding


def delta_events_to_ocsf(raw_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Project canonical finding-delta events to OCSF Detection Findings."""

    ocsf_events: list[dict[str, Any]] = []
    for event in raw_events:
        raw_finding = event.get("finding")
        finding = raw_finding if isinstance(raw_finding, dict) else {}
        alert = {
            "severity": finding.get("severity", "medium"),
            "message": finding.get("title") or finding.get("id") or event.get("canonical_id"),
            "detector": f"finding_delta_{event.get('event_type', 'new')}",
            "details": event,
        }
        ocsf_events.append(to_ocsf_detection_finding(alert))
    return ocsf_events
