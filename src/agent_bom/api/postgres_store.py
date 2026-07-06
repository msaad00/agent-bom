"""PostgreSQL-backed storage backends for agent-bom.

This module keeps the public import surface stable while the concrete store
implementations are split by responsibility:

- scan job persistence lives in ``postgres_job_store.py``
- fleet agent persistence lives in ``postgres_fleet_store.py``
- shared pool / tenant / RLS helpers live in ``postgres_common.py``
- audit + trend stores live in ``postgres_audit.py``
- graph + cache stores live in ``postgres_graph.py``

Requires ``pip install 'agent-bom[postgres]'``.
"""

from __future__ import annotations

from agent_bom.api.postgres_access import PostgresExceptionStore, PostgresKeyStore
from agent_bom.api.postgres_audit import PostgresAuditLog, PostgresTrendStore
from agent_bom.api.postgres_common import (
    _apply_tenant_session,
    _current_tenant,
    _ensure_tenant_rls,
    _get_pool,
    _tenant_connection,
    bypass_tenant_rls,
    is_tenant_rls_bypassed,
    reset_current_tenant,
    reset_pool,
    set_current_tenant,
)
from agent_bom.api.postgres_cost import PostgresCostStore  # noqa: F401
from agent_bom.api.postgres_fleet_store import PostgresFleetStore
from agent_bom.api.postgres_graph import PostgresGraphStore, PostgresScanCache
from agent_bom.api.postgres_job_store import PostgresJobStore
from agent_bom.api.postgres_policy import (  # noqa: F401
    PostgresCredentialRefStore,
    PostgresPolicyStore,
    PostgresScheduleStore,
    PostgresSourceStore,
)
from agent_bom.api.postgres_tenant_quota import PostgresTenantQuotaStore  # noqa: F401

__all__ = [
    "_apply_tenant_session",
    "_current_tenant",
    "_ensure_tenant_rls",
    "_get_pool",
    "_tenant_connection",
    "PostgresAuditLog",
    "PostgresExceptionStore",
    "PostgresFleetStore",
    "PostgresGraphStore",
    "PostgresJobStore",
    "PostgresKeyStore",
    "PostgresPolicyStore",
    "PostgresScanCache",
    "PostgresScheduleStore",
    "PostgresTrendStore",
    "bypass_tenant_rls",
    "is_tenant_rls_bypassed",
    "reset_current_tenant",
    "reset_pool",
    "set_current_tenant",
]
