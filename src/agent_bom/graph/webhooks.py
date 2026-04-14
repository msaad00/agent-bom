"""Graph delta alerts, outbound delivery, and OCSF-ready export.

After a scan persists a new graph snapshot, the graph delta helpers compare
it to the previous snapshot and produce alerts for new critical findings,
attack paths, lateral movement risk, and drift. Those alerts can be:

- rendered as persisted current-state and diff views
- exported as OCSF-ready events for SIEM workflows
- dispatched to configured webhook or Slack channels
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from agent_bom.event_normalization import build_event_ref, build_event_relationships
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.severity import SEVERITY_RANK
from agent_bom.graph.types import EntityType

logger = logging.getLogger(__name__)


def _graph_node_ref(
    graph: UnifiedGraph | None,
    node_id: str,
    *,
    role: str,
) -> dict[str, Any] | None:
    """Resolve one graph node into a canonical event target reference."""
    if graph is None:
        return None
    node = graph.nodes.get(node_id)
    if node is None:
        return None
    return build_event_ref(
        ref_type=node.entity_type.value,
        ref_id=node.id,
        name=node.label,
        role=role,
        attributes={
            "severity": node.severity,
            "status": node.status.value if hasattr(node.status, "value") else str(node.status),
            "risk_score": node.risk_score,
        },
    )


def _graph_relationships(
    *,
    graph: UnifiedGraph | None,
    targets: list[tuple[str, str]],
    source: str = "graph_delta",
) -> dict[str, Any] | None:
    """Build an additive canonical relationship envelope for delta alerts."""
    target_refs = [_graph_node_ref(graph, node_id, role=role) for node_id, role in targets]
    return build_event_relationships(source=source, targets=[ref for ref in target_refs if ref])


def _dispatch_outbound_alert(dispatcher: Any, alert: dict[str, Any], outbound_channels: int) -> tuple[int, int]:
    """Dispatch one alert, returning delivered and queued outbound counts."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        successes = asyncio.run(dispatcher.dispatch(alert))
        return max(0, successes - 1), 0

    dispatcher.dispatch_sync(alert)
    return 0, outbound_channels


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
            details = {
                "node_ids": [nid],
                "scan_id": new_graph.scan_id,
                "delta_type": "new_vulnerability",
                "risk_score": node.risk_score,
                "cvss_score": node.attributes.get("cvss_score"),
                "is_kev": node.attributes.get("is_kev", False),
                "affected_agent_count": node.attributes.get("affected_agent_count", 0),
            }
            alerts.append(
                {
                    "type": "new_vulnerability",
                    "detector": "graph_new_vulnerability",
                    "severity": node.severity,
                    "message": f"New {node.severity} vulnerability: {node.label}",
                    "title": f"New {node.severity} vulnerability: {node.label}",
                    "description": f"Vulnerability {node.label} appeared in scan {new_graph.scan_id}",
                    "node_ids": [nid],
                    "scan_id": new_graph.scan_id,
                    "details": details,
                    "event_relationships": _graph_relationships(
                        graph=new_graph,
                        targets=[(nid, "affected_finding")],
                    ),
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
            details = {
                "node_ids": [nid],
                "scan_id": new_graph.scan_id,
                "delta_type": "new_misconfiguration",
                "risk_score": node.risk_score,
            }
            alerts.append(
                {
                    "type": "new_misconfiguration",
                    "detector": "graph_new_misconfiguration",
                    "severity": node.severity,
                    "message": f"New {node.severity} misconfiguration: {node.label}",
                    "title": f"New {node.severity} misconfiguration: {node.label}",
                    "description": f"CIS/SAST finding appeared in scan {new_graph.scan_id}",
                    "node_ids": [nid],
                    "scan_id": new_graph.scan_id,
                    "details": details,
                    "event_relationships": _graph_relationships(
                        graph=new_graph,
                        targets=[(nid, "affected_finding")],
                    ),
                }
            )

    # ── New attack paths with high composite risk ────────────────────
    old_path_keys = set()
    if old_graph:
        old_path_keys = {(p.source, p.target) for p in old_graph.attack_paths}
    for path in new_graph.attack_paths:
        if (path.source, path.target) not in old_path_keys and path.composite_risk >= 7.0:
            details = {
                "node_ids": path.hops,
                "scan_id": new_graph.scan_id,
                "delta_type": "new_attack_path",
                "risk_score": path.composite_risk,
                "composite_risk": path.composite_risk,
                "credential_exposure": path.credential_exposure,
                "vuln_ids": path.vuln_ids,
            }
            alerts.append(
                {
                    "type": "new_attack_path",
                    "detector": "graph_new_attack_path",
                    "severity": "critical" if path.composite_risk >= 9.0 else "high",
                    "message": f"New high-risk attack path: {path.summary or f'{path.source} → {path.target}'}",
                    "title": f"New high-risk attack path: {path.summary or f'{path.source} → {path.target}'}",
                    "description": f"Composite risk {path.composite_risk}/10, {len(path.hops)} hops",
                    "node_ids": path.hops,
                    "scan_id": new_graph.scan_id,
                    "details": details,
                    "event_relationships": _graph_relationships(
                        graph=new_graph,
                        targets=[
                            (path.source, "path_source"),
                            (path.target, "path_target"),
                        ],
                    ),
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
            node_ids = [f"agent:{a}" for a in risk.agents]
            details = {
                "node_ids": node_ids,
                "scan_id": new_graph.scan_id,
                "delta_type": "new_interaction_risk",
                "risk_score": risk.risk_score,
                "pattern": risk.pattern,
                "owasp_agentic_tag": risk.owasp_agentic_tag,
            }
            alerts.append(
                {
                    "type": "new_interaction_risk",
                    "detector": "graph_new_interaction_risk",
                    "severity": "critical" if risk.risk_score >= 9.0 else "high",
                    "message": f"New interaction risk: {risk.pattern}",
                    "title": f"New interaction risk: {risk.pattern}",
                    "description": risk.description,
                    "node_ids": node_ids,
                    "scan_id": new_graph.scan_id,
                    "details": details,
                    "event_relationships": _graph_relationships(
                        graph=new_graph,
                        targets=[(node_id, "affected_agent") for node_id in node_ids],
                    ),
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
            details = {
                "node_ids": agent_removed,
                "scan_id": new_graph.scan_id,
                "delta_type": "agent_removed",
            }
            alerts.append(
                {
                    "type": "agent_removed",
                    "detector": "graph_agent_removed",
                    "severity": "medium",
                    "message": f"{len(agent_removed)} agent(s) no longer detected",
                    "title": f"{len(agent_removed)} agent(s) no longer detected",
                    "description": f"Agents removed: {', '.join(sorted(agent_removed))}",
                    "node_ids": agent_removed,
                    "scan_id": new_graph.scan_id,
                    "details": details,
                    "event_relationships": _graph_relationships(
                        graph=old_graph,
                        targets=[(node_id, "removed_agent") for node_id in agent_removed],
                    ),
                }
            )

    return alerts


def _graph_delta_webhook_url() -> str:
    return os.environ.get("AGENT_BOM_GRAPH_DELTA_WEBHOOK", "").strip() or os.environ.get("AGENT_BOM_ALERT_WEBHOOK", "").strip()


def _graph_delta_slack_webhook_url() -> str:
    return os.environ.get("AGENT_BOM_GRAPH_DELTA_SLACK_WEBHOOK", "").strip() or os.environ.get("SLACK_WEBHOOK_URL", "").strip()


def dispatch_delta_alerts(
    alerts: list[dict[str, Any]],
    *,
    product_version: str = "0.0.0",
) -> dict[str, Any]:
    """Dispatch graph delta alerts to configured outbound channels.

    Uses dedicated graph delta webhook/slack env vars when present and falls
    back to the generic scan/runtime webhook env vars. Returns delivery
    metadata plus OCSF-ready events for downstream export.
    """
    from agent_bom.alerts.dispatcher import AlertDispatcher

    webhook_url = _graph_delta_webhook_url()
    slack_webhook_url = _graph_delta_slack_webhook_url()
    outbound_channels = int(bool(webhook_url)) + int(bool(slack_webhook_url))
    ocsf_events = format_alerts_for_siem(alerts, product_version)
    result = {
        "configured": outbound_channels > 0,
        "attempted": len(alerts),
        "delivered": 0,
        "queued": 0,
        "outbound_channels": outbound_channels,
        "ocsf_event_count": len(ocsf_events),
        "ocsf_events": ocsf_events,
    }
    if not alerts or outbound_channels == 0:
        return result

    dispatcher = AlertDispatcher()
    if webhook_url:
        dispatcher.add_webhook(webhook_url)
    if slack_webhook_url:
        dispatcher.add_slack(slack_webhook_url)

    delivered = 0
    queued = 0
    for alert in alerts:
        dispatched, scheduled = _dispatch_outbound_alert(dispatcher, alert, outbound_channels)
        delivered += dispatched
        queued += scheduled

    result["delivered"] = delivered
    result["queued"] = queued
    return result


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
