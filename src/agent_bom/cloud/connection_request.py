"""Shared request-builder for read-only cloud connections.

Single source of truth for the ``CloudConnectionCreate`` field mapping used by
*both* the ``agent-bom connect`` CLI verb and the control-plane API. Keeping the
field names here means the CLI's local-verify and server-register paths cannot
drift from the API's ``CloudConnectionCreate`` schema — the CLI never invents a
divergent connection shape.

Two helpers:

- :func:`build_connection_create_body` builds the JSON body the API client POSTs
  to ``/v1/cloud/connections``. Its keys are exactly the ``CloudConnectionCreate``
  fields (``provider``/``display_name``/``role_ref``/``external_id``/``regions``/
  ``auth_params``/``scan_interval_minutes``).
- :func:`ephemeral_connection_record` yields an in-process
  :class:`~agent_bom.api.connection_store.CloudConnectionRecord` whose secret is
  encrypted with the *same* :mod:`agent_bom.api.connection_crypto` the server
  uses, so the *same* :func:`~agent_bom.cloud.connection_broker.broker_session`
  can materialize a read-only credential for a standalone local verify. The
  record never leaves the process and the secret is never printed.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_bom.api.connection_store import CloudConnectionRecord


def build_connection_create_body(
    *,
    provider: str,
    display_name: str,
    role_ref: str,
    external_id: str,
    regions: Sequence[str] | None = None,
    auth_params: Mapping[str, str] | None = None,
    scan_interval_minutes: int | None = None,
) -> dict[str, Any]:
    """Build the ``CloudConnectionCreate`` request body (API-schema field names).

    ``external_id`` is the single write-only secret — it is included in the body
    (the server encrypts it at rest) but callers must never log or print it.
    Optional-but-empty fields (regions/auth_params/scan_interval_minutes) are
    omitted so the body stays minimal and matches the pydantic defaults.
    """
    body: dict[str, Any] = {
        "provider": provider,
        "display_name": display_name,
        "role_ref": role_ref,
        "external_id": external_id,
    }
    if regions:
        body["regions"] = list(regions)
    if auth_params:
        body["auth_params"] = {str(k): str(v) for k, v in auth_params.items()}
    if scan_interval_minutes is not None:
        body["scan_interval_minutes"] = scan_interval_minutes
    return body


@contextmanager
def ephemeral_connection_record(
    *,
    provider: str,
    display_name: str,
    role_ref: str,
    external_id: str,
    regions: Sequence[str] | None = None,
    auth_params: Mapping[str, str] | None = None,
) -> Iterator[CloudConnectionRecord]:
    """Yield an ephemeral connection record for a standalone local verify.

    The secret is encrypted through the same :mod:`connection_crypto` contract the
    server uses so the same broker can decrypt it. When no connections key is
    configured (the common standalone case) a throwaway Fernet key is generated
    for the lifetime of the context and torn down on exit; if a real key *is*
    configured it is reused untouched. The record is in-process only — it is never
    persisted, returned over the API, or logged, and the secret is never printed.
    """
    from cryptography.fernet import Fernet

    from agent_bom.api import connection_crypto as cc
    from agent_bom.api.connection_store import CloudConnectionRecord

    use_ephemeral_key = not cc.connections_key_configured()
    prev_key = os.environ.get(cc.CONNECTIONS_KEY_ENV)
    prev_provider = os.environ.get(cc.CONNECTIONS_KEY_PROVIDER_ENV)

    if use_ephemeral_key:
        os.environ[cc.CONNECTIONS_KEY_ENV] = Fernet.generate_key().decode("ascii")
        # Force the plain env key provider so no managed-provider network call runs.
        os.environ.pop(cc.CONNECTIONS_KEY_PROVIDER_ENV, None)
        cc.reset_key_cache()
    try:
        external_id_encrypted = cc.encrypt_secret(external_id)
        record = CloudConnectionRecord(
            id=f"cli-local-{uuid.uuid4()}",
            tenant_id="cli-local",
            provider=provider,
            display_name=display_name,
            role_ref=role_ref,
            external_id_encrypted=external_id_encrypted,
            regions=list(regions or []),
            auth_params={str(k): str(v) for k, v in (auth_params or {}).items()},
        )
        yield record
    finally:
        if use_ephemeral_key:
            if prev_key is None:
                os.environ.pop(cc.CONNECTIONS_KEY_ENV, None)
            else:
                os.environ[cc.CONNECTIONS_KEY_ENV] = prev_key
            if prev_provider is None:
                os.environ.pop(cc.CONNECTIONS_KEY_PROVIDER_ENV, None)
            else:
                os.environ[cc.CONNECTIONS_KEY_PROVIDER_ENV] = prev_provider
            # Drop the throwaway key from the in-process cache.
            cc.reset_key_cache()


__all__ = ["build_connection_create_body", "ephemeral_connection_record"]
