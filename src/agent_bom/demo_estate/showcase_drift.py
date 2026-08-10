"""Seed behavioural-drift incidents into the store the product actually reads.

``build_showcase_graph`` already constructs drift incidents, but into a private
``_DriftStore`` it hands straight back to the caller. Every surface that reports
drift — the governance overlay (``graph/governance_overlay.py``), the gateway's
drift lookup, and the drift tiles above them — reads the process-global
``get_drift_incident_store()`` instead. So the demo estate computed a full set of
incidents that nothing could ever see, and the drift surfaces reported 0 on an
estate whose own graph described the drift.

Same shape as the identity, fleet, governance and gateway seeds before it: the
evidence existed and simply never reached the store the reader queries.

Incidents are keyed by ``incident_id`` and written through ``upsert``, so
re-seeding on every boot updates rather than duplicates.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

_logger = logging.getLogger(__name__)

_DEMO_INCIDENT_PREFIX = "demo-drift-"

# Each tuple: (suffix, blueprint_id, status, drift_score, violations, warnings,
#              days_ago_first, hours_ago_last, occurrences, top_violations)
#
# The blueprint ids match the seeded governance blueprints so a viewer can move
# from an incident to the blueprint it violates without hitting a dead end.
_INCIDENTS: tuple[tuple[str, str, str, float, int, int, int, int, int, list[dict[str, Any]]], ...] = (
    (
        "clinical-unauthorized-tool",
        "bp-clinical-summarization",
        "drift_detected",
        0.82,
        3,
        1,
        6,
        2,
        7,
        [
            {"tool_name": "ehr.write_note", "type": "unauthorized_tool", "detail": "not in the approved composition"},
            {"tool_name": "warehouse-server.export_csv", "type": "unauthorized_tool", "detail": "bulk export outside blueprint"},
        ],
    ),
    (
        "prior-auth-model-swap",
        "bp-prior-auth",
        "drift_detected",
        0.64,
        2,
        2,
        4,
        9,
        4,
        [
            {"tool_name": "payer.submit_draft", "type": "unapproved_model", "detail": "invoked with a model outside the approved set"},
        ],
    ),
    (
        "patient-intake-ungoverned",
        "bp-patient-chat",
        "review",
        0.41,
        1,
        3,
        2,
        5,
        2,
        [
            {"tool_name": "scheduling.availability", "type": "draft_blueprint_in_use", "detail": "draft blueprint serving live traffic"},
        ],
    ),
)


def seed_showcase_drift_incidents(*, tenant_id: str = SHOWCASE_TENANT, now: datetime | None = None) -> dict[str, Any]:
    """Write the demo estate's drift incidents into the real store (idempotent)."""
    from agent_bom.api.drift_incident_store import DriftIncident, get_drift_incident_store

    store = get_drift_incident_store()
    anchor = now or datetime.now(timezone.utc)

    existing = store.list(tenant_id, include_resolved=True, limit=200)
    # An operator's own drift incidents must never be joined by demo rows.
    if existing and not any(i.incident_id.startswith(_DEMO_INCIDENT_PREFIX) for i in existing):
        return {"seeded": 0, "reason": "operator_incidents_present"}

    seeded = 0
    for suffix, blueprint_id, status, score, violations, warnings, days_ago, hours_ago, occurrences, top in _INCIDENTS:
        store.upsert(
            DriftIncident(
                incident_id=f"{_DEMO_INCIDENT_PREFIX}{suffix}",
                tenant_id=tenant_id,
                blueprint_id=blueprint_id,
                status=status,
                drift_score=score,
                violation_count=violations,
                warning_count=warnings,
                top_violations=list(top),
                first_detected_at=(anchor - timedelta(days=days_ago)).isoformat(),
                last_detected_at=(anchor - timedelta(hours=hours_ago)).isoformat(),
                occurrences=occurrences,
            )
        )
        seeded += 1

    _logger.info("demo estate drift incidents seeded %s", seeded)
    return {"seeded": seeded, "tenant_id": tenant_id}
