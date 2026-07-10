"""Seed demo connections, sources, and spend samples for first-run UI surfaces.

The graph + scan job bootstrap already fills findings/compliance, but
Connections, Sources, and AI Spend pages read separate stores. This module
adds idempotent showcase rows so service-registry chips and admin pages are
not empty zeros on demo.agent-bom.com.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from agent_bom.api.connection_store import (
    STATUS_ACTIVE,
    CloudConnectionRecord,
    get_connection_store,
)
from agent_bom.api.cost_store import LLMCostRecord, get_cost_store
from agent_bom.api.models import SourceKind, SourceRecord, SourceStatus
from agent_bom.api.stores import _get_source_store
from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

_logger = logging.getLogger(__name__)

_ANCHOR = "2026-07-06T15:30:00+00:00"
_DEMO_CONN_PREFIX = "demo-conn-"
_DEMO_SOURCE_PREFIX = "demo-src-"
_DEMO_COST_CALL_ID = "demo-cost-showcase-v1"


def _tenant_scoped_id(base: str, tenant_id: str) -> str:
    """Keep canonical showcase IDs while preventing cross-tenant PK collisions."""
    if tenant_id == SHOWCASE_TENANT:
        return base
    suffix = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:12]
    return f"{base}-{suffix}"


def seed_showcase_catalog_if_empty(*, tenant_id: str = SHOWCASE_TENANT) -> dict[str, Any]:
    """Seed each showcase catalog surface, healing partial prior attempts."""
    conn_store = get_connection_store()
    connections = [
        CloudConnectionRecord(
            id=_tenant_scoped_id("demo-conn-aws", tenant_id),
            tenant_id=tenant_id,
            provider="aws",
            display_name="AWS showcase (read-only)",
            role_ref="arn:aws:iam::123456789012:role/agent-bom-readonly",
            external_id_encrypted="",
            regions=["us-east-1", "us-west-2"],
            status=STATUS_ACTIVE,
            created_at=_ANCHOR,
            updated_at=_ANCHOR,
            last_scan_at=_ANCHOR,
            last_scan_id="showcase",
            auth_params={"demo": True},
        ),
        CloudConnectionRecord(
            id=_tenant_scoped_id("demo-conn-gcp", tenant_id),
            tenant_id=tenant_id,
            provider="gcp",
            display_name="GCP showcase (read-only)",
            role_ref="agent-bom@showcase-demo.iam.gserviceaccount.com",
            external_id_encrypted="",
            status=STATUS_ACTIVE,
            created_at=_ANCHOR,
            updated_at=_ANCHOR,
            last_scan_at=_ANCHOR,
            last_scan_id="showcase",
            auth_params={"project_id": "showcase-demo", "demo": True},
        ),
        CloudConnectionRecord(
            id=_tenant_scoped_id("demo-conn-azure", tenant_id),
            tenant_id=tenant_id,
            provider="azure",
            display_name="Azure showcase (read-only)",
            role_ref="/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Authorization/roleAssignments/demo",
            external_id_encrypted="",
            status=STATUS_ACTIVE,
            created_at=_ANCHOR,
            updated_at=_ANCHOR,
            last_scan_at=_ANCHOR,
            last_scan_id="showcase",
            auth_params={
                "tenant_id": "00000000-0000-0000-0000-0000000000aa",
                "subscription_id": "00000000-0000-0000-0000-000000000001",
                "demo": True,
            },
        ),
    ]
    existing_connection_ids = {record.id for record in conn_store.list_for_tenant(tenant_id)}
    connections_seeded = 0
    for record in connections:
        if record.id not in existing_connection_ids:
            conn_store.put(record)
            connections_seeded += 1

    try:
        source_store = _get_source_store()
    except RuntimeError:
        source_store = None

    sources_seeded = 0
    if source_store is not None:
        for source in (
            SourceRecord(
                source_id=_tenant_scoped_id("demo-src-repo", tenant_id),
                tenant_id=tenant_id,
                display_name="Golden monorepo scan",
                kind=SourceKind.SCAN_REPO,
                description="Curated demo repo scan target",
                owner="platform-security",
                enabled=True,
                status=SourceStatus.HEALTHY,
                last_run_at=_ANCHOR,
                last_run_status="success",
                last_job_id="showcase",
                created_at=_ANCHOR,
                updated_at=_ANCHOR,
            ),
            SourceRecord(
                source_id=_tenant_scoped_id("demo-src-mcp", tenant_id),
                tenant_id=tenant_id,
                display_name="MCP config ingest",
                kind=SourceKind.SCAN_MCP_CONFIG,
                description="Demo MCP posture source",
                owner="ai-platform",
                enabled=True,
                status=SourceStatus.HEALTHY,
                last_run_at=_ANCHOR,
                last_run_status="success",
                last_job_id="showcase",
                created_at=_ANCHOR,
                updated_at=_ANCHOR,
            ),
        ):
            existing_source_ids = {
                record.source_id for record in source_store.list_all(tenant_id=tenant_id)
            }
            if source.source_id not in existing_source_ids:
                source_store.put(source)
                sources_seeded += 1

    cost_store = get_cost_store()
    cost_seeded = 0
    if not any(
        record.call_id == _DEMO_COST_CALL_ID
        for record in cost_store.list_records(tenant_id, limit=1000)
    ):
        cost_store.record_cost(LLMCostRecord(
            tenant_id=tenant_id,
            call_id=_DEMO_COST_CALL_ID,
            agent="cursor-demo-agent",
            session_id="demo-estate",
            provider="anthropic",
            model="claude-sonnet",
            input_tokens=128_000,
            output_tokens=12_400,
            cost_usd=4.82,
            priced=True,
            observed_at=_ANCHOR,
            cost_center="ai-platform",
            allocation_tags={"env": "demo", "team": "security"},
        ))
        cost_seeded = 1

    summary: dict[str, Any] = {
        "seeded": bool(connections_seeded or sources_seeded or cost_seeded),
        "connections": connections_seeded,
        "sources": sources_seeded,
        "cost_samples": cost_seeded,
    }
    if not summary["seeded"]:
        summary["reason"] = "catalog_present"
    _logger.info("demo estate catalog seeded tenant=%s %s", tenant_id, summary)
    return summary
