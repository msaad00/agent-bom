"""Seed demo connections, sources, and spend samples for first-run UI surfaces.

The graph + scan job bootstrap already fills findings/compliance, but
Connections, Sources, and AI Spend pages read separate stores. This module
adds idempotent showcase rows so service-registry chips and admin pages are
not empty zeros on demo.agent-bom.com.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any

from agent_bom.api import connection_crypto
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


def _tenant_has_demo_catalog(tenant_id: str) -> bool:
    return any(
        record.id.startswith(_DEMO_CONN_PREFIX)
        for record in get_connection_store().list_for_tenant(tenant_id)
    )


def _ensure_demo_connections_key() -> None:
    """Provision an ephemeral Fernet key for showcase connections when unset.

    Demo estate is a read-only showcase; an operator-managed key is still
    preferred in production, but the catalog must not fail closed on POC VMs
    that only enable ``AGENT_BOM_DEMO_ESTATE``.
    """
    if connection_crypto.connections_key_configured():
        return
    from cryptography.fernet import Fernet

    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = Fernet.generate_key().decode("ascii")
    connection_crypto.reset_key_cache()
    _logger.warning(
        "demo estate: generated ephemeral %s for showcase cloud connections",
        connection_crypto.CONNECTIONS_KEY_ENV,
    )


def _demo_secret() -> str:
    _ensure_demo_connections_key()
    return connection_crypto.encrypt_secret("demo-estate-readonly-external-id")


def seed_showcase_catalog_if_empty(*, tenant_id: str = SHOWCASE_TENANT) -> dict[str, Any]:
    """Seed connections, sources, and a priced LLM row when the catalog is empty."""
    if _tenant_has_demo_catalog(tenant_id):
        return {"seeded": False, "reason": "catalog_present"}

    secret = _demo_secret()
    conn_store = get_connection_store()
    connections = [
        CloudConnectionRecord(
            id="demo-conn-aws",
            tenant_id=tenant_id,
            provider="aws",
            display_name="AWS showcase (read-only)",
            role_ref="arn:aws:iam::123456789012:role/agent-bom-readonly",
            external_id_encrypted=secret,
            regions=["us-east-1", "us-west-2"],
            status=STATUS_ACTIVE,
            created_at=_ANCHOR,
            updated_at=_ANCHOR,
            last_scan_at=_ANCHOR,
            last_scan_id="showcase",
        ),
        CloudConnectionRecord(
            id="demo-conn-gcp",
            tenant_id=tenant_id,
            provider="gcp",
            display_name="GCP showcase (read-only)",
            role_ref="agent-bom@showcase-demo.iam.gserviceaccount.com",
            external_id_encrypted=secret,
            status=STATUS_ACTIVE,
            created_at=_ANCHOR,
            updated_at=_ANCHOR,
            last_scan_at=_ANCHOR,
            last_scan_id="showcase",
            auth_params={"project_id": "showcase-demo"},
        ),
        CloudConnectionRecord(
            id="demo-conn-azure",
            tenant_id=tenant_id,
            provider="azure",
            display_name="Azure showcase (read-only)",
            role_ref="/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Authorization/roleAssignments/demo",
            external_id_encrypted=secret,
            status=STATUS_ACTIVE,
            created_at=_ANCHOR,
            updated_at=_ANCHOR,
            last_scan_at=_ANCHOR,
            last_scan_id="showcase",
            auth_params={
                "tenant_id": "00000000-0000-0000-0000-0000000000aa",
                "subscription_id": "00000000-0000-0000-0000-000000000001",
            },
        ),
    ]
    for record in connections:
        conn_store.put(record)

    try:
        source_store = _get_source_store()
    except RuntimeError:
        source_store = None

    sources_seeded = 0
    if source_store is not None:
        for source in (
            SourceRecord(
                source_id="demo-src-repo",
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
                source_id="demo-src-mcp",
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
            source_store.put(source)
            sources_seeded += 1

    get_cost_store().record_cost(
        LLMCostRecord(
            tenant_id=tenant_id,
            call_id=f"demo-cost-{uuid.uuid4().hex[:8]}",
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
        )
    )

    summary = {
        "seeded": True,
        "connections": len(connections),
        "sources": sources_seeded,
        "cost_samples": 1,
    }
    _logger.info("demo estate catalog seeded tenant=%s %s", tenant_id, summary)
    return summary
