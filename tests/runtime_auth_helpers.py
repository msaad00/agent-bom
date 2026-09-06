"""Verified-key and internal-principal fixtures for runtime source contracts."""

import time
from datetime import datetime, timedelta, timezone

from agent_bom.cloud.runtime_source_auth import RuntimeSourcePrincipal, runtime_source_scope


def runtime_principal(source_id="edr-1", tenant="tenant-a", scopes=None, **overrides):
    now = time.time()
    fields = dict(
        subject="test-producer",
        tenant_id=tenant,
        scopes=tuple([runtime_source_scope(source_id)] if scopes is None else scopes),
        issued_at=now - 1,
        expires_at=now + 1799,
    )
    fields.update(overrides)
    return RuntimeSourcePrincipal(**fields)


def runtime_headers(source_id="edr-1", tenant="tenant-alpha", role="admin", scopes=None, **overrides):
    from agent_bom.api.auth import Role, create_api_key, get_key_store

    raw, key = create_api_key(
        name="runtime-test-producer",
        role=Role(role),
        tenant_id=tenant,
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
        scopes=["*", runtime_source_scope(source_id)] if scopes is None else scopes,
    )
    for name, value in overrides.items():
        setattr(key, name, value)
    get_key_store().add(key)
    return {"X-API-Key": raw}
