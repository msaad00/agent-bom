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
from collections.abc import Mapping
from typing import Any

from agent_bom.event_normalization import build_event_ref, build_event_relationships
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.delta_digest import PriorSnapshotDigest
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.severity import SEVERITY_RANK
from agent_bom.graph.types import EntityType
from agent_bom.posture_streaming import PostureEvent, WebhookDestination, WebhookOutbox, default_webhook_outbox
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


def _graph_node_ref(
    nodes: Mapping[str, UnifiedNode] | None,
    node_id: str,
    *,
    role: str,
) -> dict[str, Any] | None:
    """Resolve one node (from a node mapping) into a canonical event target ref."""
    if nodes is None:
        return None
    node = nodes.get(node_id)
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
    nodes: Mapping[str, UnifiedNode] | None,
    targets: list[tuple[str, str]],
    source: str = "graph_delta",
) -> dict[str, Any] | None:
    """Build an additive canonical relationship envelope for delta alerts."""
    target_refs = [_graph_node_ref(nodes, node_id, role=role) for node_id, role in targets]
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

    Thin wrapper over :func:`compute_delta_alerts_from_digest` — projects the
    fully materialised ``old_graph`` into a :class:`PriorSnapshotDigest` first.
    Callers that can stream the prior snapshot (the scan pipeline) should build
    the digest via a bounded store read and call the digest form directly, so
    peak RSS is not doubled by a second full graph (#4055 / #4075).
    """
    return compute_delta_alerts_from_digest(PriorSnapshotDigest.from_graph(old_graph), new_graph)


def compute_delta_alerts_from_digest(
    prior: PriorSnapshotDigest,
    new_graph: UnifiedGraph,
) -> list[dict[str, Any]]:
    """Compute delta alerts against a bounded prior-snapshot digest.

    Byte-identical to :func:`compute_delta_alerts` on the same underlying
    snapshots, but the prior side is a :class:`PriorSnapshotDigest` (node ids +
    agent nodes + path/risk keys) rather than a whole ``UnifiedGraph`` — so the
    caller never materialises a second full graph just to diff against it.
    """
    alerts: list[dict[str, Any]] = []

    old_node_ids = prior.node_ids

    # ── New critical/high findings ───────────────────────────────────
    # Large control-plane snapshots are usually dominated by unchanged
    # inventory nodes. Walk the new node mapping once and use O(1) membership
    # against the prior snapshot instead of materializing full node-id
    # difference sets or scanning the same delta twice.
    for nid, node in new_graph.nodes.items():
        if nid in old_node_ids:
            continue
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
                        nodes=new_graph.nodes,
                        targets=[(nid, "affected_finding")],
                    ),
                    "attributes": {
                        "cvss_score": node.attributes.get("cvss_score"),
                        "is_kev": node.attributes.get("is_kev", False),
                        "affected_agent_count": node.attributes.get("affected_agent_count", 0),
                    },
                }
            )
        elif node.entity_type == EntityType.MISCONFIGURATION and SEVERITY_RANK.get(node.severity, 0) >= 4:
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
                        nodes=new_graph.nodes,
                        targets=[(nid, "affected_finding")],
                    ),
                }
            )

    # ── New attack paths with high composite risk ────────────────────
    old_path_keys = prior.attack_path_keys
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
                        nodes=new_graph.nodes,
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
    old_risk_keys = prior.interaction_risk_keys
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
                        nodes=new_graph.nodes,
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
    if prior.agent_nodes:
        agent_removed = [nid for nid in prior.agent_nodes if nid not in new_graph.nodes]
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
                        nodes=prior.agent_nodes,
                        targets=[(node_id, "removed_agent") for node_id in agent_removed],
                    ),
                }
            )

    return alerts


def _graph_delta_webhook_url() -> str:
    return os.environ.get("AGENT_BOM_GRAPH_DELTA_WEBHOOK", "").strip() or os.environ.get("AGENT_BOM_ALERT_WEBHOOK", "").strip()


def _graph_delta_webhook_signing_secret() -> str:
    return (
        os.environ.get("AGENT_BOM_GRAPH_DELTA_WEBHOOK_SIGNING_SECRET", "").strip()
        or os.environ.get("AGENT_BOM_POSTURE_WEBHOOK_SIGNING_SECRET", "").strip()
    )


def _graph_delta_destination_id() -> str:
    return os.environ.get("AGENT_BOM_GRAPH_DELTA_WEBHOOK_DESTINATION_ID", "").strip() or "graph-delta-webhook"


def _graph_delta_slack_webhook_url() -> str:
    return os.environ.get("AGENT_BOM_GRAPH_DELTA_SLACK_WEBHOOK", "").strip() or os.environ.get("SLACK_WEBHOOK_URL", "").strip()


def _graph_delta_webhook_destination(*, tenant_id: str) -> tuple[WebhookDestination | None, str]:
    webhook_url = _graph_delta_webhook_url()
    if not webhook_url:
        return None, ""
    signing_secret = _graph_delta_webhook_signing_secret()
    if not signing_secret:
        return None, "AGENT_BOM_GRAPH_DELTA_WEBHOOK_SIGNING_SECRET is required for durable graph delta webhook delivery"
    try:
        return (
            WebhookDestination(
                destination_id=_graph_delta_destination_id(),
                tenant_id=tenant_id,
                url=webhook_url,
                signing_secret=signing_secret,
                allow_private_networks=os.environ.get("AGENT_BOM_GRAPH_DELTA_WEBHOOK_ALLOW_PRIVATE_NETWORKS", "").strip().lower()
                in {"1", "true", "yes", "on"},
            ),
            "",
        )
    except ValueError as exc:
        return None, sanitize_error(exc)


def _posture_event_for_graph_delta(alert: dict[str, Any], *, tenant_id: str, product_version: str) -> PostureEvent:
    raw_details = alert.get("details")
    details: Mapping[str, Any] = raw_details if isinstance(raw_details, Mapping) else {}
    subject_id = str(alert.get("scan_id") or details.get("scan_id") or "")
    alert_type = str(alert.get("type") or "graph_delta")
    primary_node = ""
    node_ids = alert.get("node_ids")
    if isinstance(node_ids, list) and node_ids:
        primary_node = str(node_ids[0])
    if primary_node:
        subject_id = f"{subject_id}:{alert_type}:{primary_node}" if subject_id else f"{alert_type}:{primary_node}"
    return PostureEvent(
        event_type="graph.delta",
        tenant_id=tenant_id,
        source="graph_delta",
        subject_id=subject_id,
        payload={
            "alert": alert,
            "product_version": product_version,
        },
    )


def enqueue_delta_alerts(
    alerts: list[dict[str, Any]],
    *,
    destination: WebhookDestination,
    product_version: str = "0.0.0",
    outbox: WebhookOutbox | None = None,
) -> dict[str, Any]:
    """Queue graph delta alerts into the signed posture webhook outbox."""

    target_outbox = outbox or default_webhook_outbox()
    queued = 0
    row_ids: list[int] = []
    for alert in alerts:
        event = _posture_event_for_graph_delta(alert, tenant_id=destination.tenant_id, product_version=product_version)
        row_id = target_outbox.enqueue(event, destination)
        row_ids.append(row_id)
        queued += 1
    return {"queued": queued, "outbox_row_ids": row_ids, "destination_id": destination.destination_id}


def dispatch_delta_alerts(
    alerts: list[dict[str, Any]],
    *,
    product_version: str = "0.0.0",
    tenant_id: str = "default",
    outbox: WebhookOutbox | None = None,
) -> dict[str, Any]:
    """Dispatch graph delta alerts to configured outbound channels.

    Generic graph-delta webhooks are queued through the durable posture outbox
    when a signing secret is configured. Slack delivery remains an explicit
    best-effort notification channel. Returns delivery metadata plus OCSF-ready
    events for downstream export.
    """
    from agent_bom.alerts.dispatcher import AlertDispatcher

    webhook_destination, webhook_config_error = _graph_delta_webhook_destination(tenant_id=tenant_id)
    slack_webhook_url = _graph_delta_slack_webhook_url()
    outbound_channels = int(bool(webhook_destination)) + int(bool(slack_webhook_url))
    ocsf_events = format_alerts_for_siem(alerts, product_version)
    result = {
        "configured": outbound_channels > 0,
        "attempted": len(alerts),
        "delivered": 0,
        "queued": 0,
        "dead_lettered": 0,
        "outbound_channels": outbound_channels,
        "outbox_row_ids": [],
        "webhook_config_error": webhook_config_error,
        "ocsf_event_count": len(ocsf_events),
        "ocsf_events": ocsf_events,
    }
    if not alerts or outbound_channels == 0:
        return result

    if webhook_destination:
        queued = enqueue_delta_alerts(
            alerts,
            destination=webhook_destination,
            product_version=product_version,
            outbox=outbox,
        )
        result["queued"] = queued["queued"]
        result["outbox_row_ids"] = queued["outbox_row_ids"]

    if not slack_webhook_url:
        return result

    dispatcher = AlertDispatcher()
    dispatcher.add_slack(slack_webhook_url)

    delivered = 0
    scheduled = 0
    for alert in alerts:
        dispatched, alert_scheduled = _dispatch_outbound_alert(dispatcher, alert, 1)
        delivered += dispatched
        scheduled += alert_scheduled

    result["delivered"] = delivered
    queued_count = result.get("queued", 0)
    result["queued"] = (queued_count if isinstance(queued_count, int) else 0) + scheduled
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
