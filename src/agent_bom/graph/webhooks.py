"""Graph delta webhooks — alert when critical changes appear between scans.

After a scan persists a new graph snapshot, ``check_and_notify()`` compares
it to the previous snapshot.  If new critical vulnerabilities, attack paths,
or lateral movement risks appear, it emits a webhook event compatible with
the existing SIEM push infrastructure.
"""

from __future__ import annotations

import logging
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.severity import SEVERITY_RANK
from agent_bom.graph.types import EntityType

logger = logging.getLogger(__name__)


def compute_delta_alerts(
    old_graph: UnifiedGraph | None,
    new_graph: UnifiedGraph,
) -> list[dict[str, Any]]:
    """Compare two graph snapshots and return alert dicts for critical changes.

    Returns a list of alert dicts suitable for SIEM push or webhook delivery.
    Each alert has: type, severity, title, description, node_ids, scan_id.
    """
    alerts: list[dict[str, Any]] = []

    old_node_ids = set(old_graph.nodes) if old_graph else set()
    new_node_ids = set(new_graph.nodes)

    # ── New critical/high vulnerabilities ────────────────────────────
    for nid in new_node_ids - old_node_ids:
        node = new_graph.nodes[nid]
        if node.entity_type == EntityType.VULNERABILITY and SEVERITY_RANK.get(node.severity, 0) >= 4:
            alerts.append(
                {
                    "type": "new_vulnerability",
                    "severity": node.severity,
                    "title": f"New {node.severity} vulnerability: {node.label}",
                    "description": f"Vulnerability {node.label} appeared in scan {new_graph.scan_id}",
                    "node_ids": [nid],
                    "scan_id": new_graph.scan_id,
                    "attributes": {
                        "cvss_score": node.attributes.get("cvss_score"),
                        "is_kev": node.attributes.get("is_kev", False),
                        "affected_agent_count": node.attributes.get("affected_agent_count", 0),
                    },
                }
            )

    # ── New misconfigurations ────────────────────────────────────────
    for nid in new_node_ids - old_node_ids:
        node = new_graph.nodes[nid]
        if node.entity_type == EntityType.MISCONFIGURATION and SEVERITY_RANK.get(node.severity, 0) >= 4:
            alerts.append(
                {
                    "type": "new_misconfiguration",
                    "severity": node.severity,
                    "title": f"New {node.severity} misconfiguration: {node.label}",
                    "description": f"CIS/SAST finding appeared in scan {new_graph.scan_id}",
                    "node_ids": [nid],
                    "scan_id": new_graph.scan_id,
                }
            )

    # ── New attack paths with high composite risk ────────────────────
    old_path_keys = set()
    if old_graph:
        old_path_keys = {(p.source, p.target) for p in old_graph.attack_paths}
    for path in new_graph.attack_paths:
        if (path.source, path.target) not in old_path_keys and path.composite_risk >= 7.0:
            alerts.append(
                {
                    "type": "new_attack_path",
                    "severity": "critical" if path.composite_risk >= 9.0 else "high",
                    "title": f"New high-risk attack path: {path.summary or f'{path.source} → {path.target}'}",
                    "description": f"Composite risk {path.composite_risk}/10, {len(path.hops)} hops",
                    "node_ids": path.hops,
                    "scan_id": new_graph.scan_id,
                    "attributes": {
                        "composite_risk": path.composite_risk,
                        "credential_exposure": path.credential_exposure,
                        "vuln_ids": path.vuln_ids,
                    },
                }
            )

    # ── New lateral movement risks ───────────────────────────────────
    old_risk_keys = set()
    if old_graph:
        old_risk_keys = {(r.pattern, tuple(sorted(r.agents))) for r in old_graph.interaction_risks}
    for risk in new_graph.interaction_risks:
        key = (risk.pattern, tuple(sorted(risk.agents)))
        if key not in old_risk_keys and risk.risk_score >= 7.0:
            alerts.append(
                {
                    "type": "new_interaction_risk",
                    "severity": "critical" if risk.risk_score >= 9.0 else "high",
                    "title": f"New interaction risk: {risk.pattern}",
                    "description": risk.description,
                    "node_ids": [f"agent:{a}" for a in risk.agents],
                    "scan_id": new_graph.scan_id,
                    "attributes": {
                        "risk_score": risk.risk_score,
                        "pattern": risk.pattern,
                        "owasp_agentic_tag": risk.owasp_agentic_tag,
                    },
                }
            )

    # ── Nodes removed (potential drift) ──────────────────────────────
    removed = old_node_ids - new_node_ids
    if removed and old_graph:
        agent_removed = [nid for nid in removed if old_graph.nodes[nid].entity_type == EntityType.AGENT]
        if agent_removed:
            alerts.append(
                {
                    "type": "agent_removed",
                    "severity": "medium",
                    "title": f"{len(agent_removed)} agent(s) no longer detected",
                    "description": f"Agents removed: {', '.join(sorted(agent_removed))}",
                    "node_ids": agent_removed,
                    "scan_id": new_graph.scan_id,
                }
            )

    return alerts


def format_alerts_for_siem(alerts: list[dict[str, Any]], product_version: str = "0.0.0") -> list[dict[str, Any]]:
    """Convert delta alerts to OCSF Detection Finding format for SIEM push."""
    import time

    from agent_bom.graph.severity import SEVERITY_TO_OCSF

    ocsf_events = []
    for alert in alerts:
        severity_str = alert.get("severity", "medium").lower()
        ocsf_events.append(
            {
                "class_uid": 2004,
                "category_uid": 2,
                "type_uid": 200401,
                "activity_id": 1,
                "activity_name": "Create",
                "severity_id": SEVERITY_TO_OCSF.get(severity_str, 0),
                "severity": severity_str.capitalize(),
                "status_id": 1,
                "status": "New",
                "time": int(time.time() * 1000),
                "message": alert["title"],
                "finding_info": {
                    "title": alert["title"],
                    "desc": alert["description"],
                    "types": [alert["type"]],
                    "uid": f"delta:{alert['scan_id']}:{alert['type']}:{alert.get('node_ids', [''])[0]}",
                },
                "metadata": {
                    "product": {
                        "name": "agent-bom",
                        "vendor_name": "msaad00",
                        "version": product_version,
                    },
                    "version": "1.1.0",
                    "log_name": "agent-bom-graph-delta",
                },
            }
        )
    return ocsf_events
