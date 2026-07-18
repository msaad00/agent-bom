"""API-key verification must not block the event loop or serialize scrypt.

``APIKeyMiddleware.dispatch`` awaits ``store.verify(raw_key)``, whose
``KeyStore.verify`` runs ``hashlib.scrypt`` (~21ms of CPU) — historically while
holding ``self._lock``. That stalled the async event loop for every auth and
serialized all concurrent verifies. The fix:

- ``KeyStore.verify`` holds ``_lock`` only long enough to snapshot the key list;
  the scrypt derivation runs lock-free, so concurrent verifies do not serialize.
- ``APIKeyMiddleware`` offloads ``store.verify`` to a worker thread
  (``anyio.to_thread.run_sync``) so the CPU work never runs on the loop.

Correctness (accept valid / reject invalid / respect revocation + expiry) is
preserved.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from starlette.testclient import TestClient

from agent_bom.api import auth as auth_mod
from agent_bom.api import middleware as middleware_mod
from agent_bom.api.auth import KeyStore, Role, create_api_key


def test_verify_runs_scrypt_outside_the_lock(monkeypatch):
    store = KeyStore()
    raw_key, api_key = create_api_key("svc", Role.ADMIN, tenant_id="t")
    store.add(api_key)

    real_verify = auth_mod.verify_api_key
    observed_unlocked: list[bool] = []

    def _instrumented(raw, stored_keys):
        # If the lock is still held here, the scrypt work is serialized behind it.
        acquired = store._lock.acquire(blocking=False)
        observed_unlocked.append(acquired)
        if acquired:
            store._lock.release()
        return real_verify(raw, stored_keys)

    monkeypatch.setattr(auth_mod, "verify_api_key", _instrumented)

    result = store.verify(raw_key)
    assert result is not None and result.key_id == api_key.key_id
    assert observed_unlocked == [True], "scrypt/verify must run outside KeyStore._lock"


def test_verify_correctness_preserved():
    store = KeyStore()
    raw_valid, valid = create_api_key("valid", Role.ADMIN, tenant_id="t")
    store.add(valid)

    raw_revoked, revoked = create_api_key("revoked", Role.ADMIN, tenant_id="t")
    store.add(revoked)
    assert store.remove(revoked.key_id) is True

    raw_expired, expired = create_api_key("expired", Role.ADMIN, tenant_id="t")
    # Past expiry is rejected at creation, so set it directly to exercise the
    # is_usable() expiry path inside verify.
    expired.expires_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    store.add(expired)

    assert store.verify(raw_valid) is not None
    assert store.verify(raw_revoked) is None
    assert store.verify(raw_expired) is None
    assert store.verify("abom_not_a_real_key") is None


def _spy_run_sync(monkeypatch):
    real = middleware_mod.anyio.to_thread.run_sync
    offloaded: list[str] = []

    async def _spy(fn, /, *args, **kwargs):
        offloaded.append(getattr(fn, "__name__", repr(fn)))
        return await real(fn, *args, **kwargs)

    monkeypatch.setattr(middleware_mod.anyio.to_thread, "run_sync", _spy)
    return offloaded


def test_api_key_middleware_offloads_verify(monkeypatch):
    """APIKeyMiddleware.dispatch must offload the RBAC scrypt verify off the loop."""
    from agent_bom.api import server as api_server
    from agent_bom.api.auth import get_key_store, set_key_store

    # A configured credential (SCIM bearer) keeps APIKeyMiddleware installed even
    # under the conftest's unauthenticated opt-in, so the RBAC verify path runs.
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "scim-secret")
    api_server.configure_api(api_key=None)
    original = get_key_store()
    store = KeyStore()
    raw_key, api_key = create_api_key("alice@example.com", Role.ADMIN, tenant_id="tenant-alpha")
    store.add(api_key)
    set_key_store(store)

    offloaded = _spy_run_sync(monkeypatch)

    client = TestClient(api_server.app)
    try:
        response = client.get("/v1/auth/policy", headers={"Authorization": f"Bearer {raw_key}"})
    finally:
        set_key_store(original)

    assert response.status_code == 200, response.text
    assert "verify" in offloaded, f"middleware must offload store.verify off the loop; saw {offloaded}"


def test_rate_limit_tenant_scope_offloads_verify(monkeypatch):
    """RateLimitMiddleware bucketing must offload its scrypt verify off the loop.

    In the anonymous/demo deployment APIKeyMiddleware is removed, so this is the
    only key verification on the request path.
    """
    import asyncio
    from types import SimpleNamespace

    from agent_bom.api.auth import get_key_store, set_key_store

    original = get_key_store()
    store = KeyStore()
    raw_key, api_key = create_api_key("svc", Role.ADMIN, tenant_id="tenant-beta")
    store.add(api_key)
    set_key_store(store)

    offloaded = _spy_run_sync(monkeypatch)
    mw = middleware_mod.RateLimitMiddleware(lambda scope, receive, send: None)
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="", auth_method=""), headers={})

    try:
        scope = asyncio.run(mw._resolve_tenant_scope(request, raw_key))
    finally:
        set_key_store(original)

    assert scope == "tenant-beta"
    assert "verify" in offloaded, f"rate-limit bucketing must offload verify; saw {offloaded}"
