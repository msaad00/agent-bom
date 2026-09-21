"""Exact lifecycle counts on the tenant-bound PostgreSQL application role."""

import os
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires a migrated live PostgreSQL database")


def test_identity_counts_above_page_limit_preserve_rls():
    from agent_bom.api.agent_identity_store import AgentIdentity
    from agent_bom.api.postgres_agent_identity import PostgresAgentIdentityStore
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    tenant = f"identity-count-{uuid4()}"
    store = PostgresAgentIdentityStore()
    token = set_current_tenant(tenant)
    try:
        for index in range(1003):
            store.put(
                AgentIdentity(
                    identity_id=f"{tenant}-{index}",
                    agent_id="same-agent",
                    tenant_id=tenant,
                    token_hash=f"{tenant}-{index}",
                    token_prefix="test",
                    role="viewer",
                    blueprint_id="",
                    status="active" if index < 1001 else "rotating" if index == 1001 else "revoked",
                    issued_at="2026-01-01T00:00:00Z",
                    expires_at="2026-01-02T00:00:00Z",
                )
            )
        assert store.count(tenant) == 1002
        assert store.count(tenant, include_inactive=True) == 1003
        assert len(store.list(tenant, limit=1000)) == 1000
        assert store.count("other-tenant", include_inactive=True) == 0
        other_token = set_current_tenant("other-tenant")
        try:
            assert store.count(tenant, include_inactive=True) == 0
        finally:
            reset_current_tenant(other_token)
    finally:
        reset_current_tenant(token)
