"""Shared connector lifecycle. Vendor reads never mutate devices or enroll agents."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from agent_bom.api.connection_crypto import ConnectionSecretError, decrypt_secret, encrypt_secret
from agent_bom.device_posture import DeviceSignal

from .models import Connection, ConnectionCreate, ConnectionSpec, SyncRequest, SyncState, now
from .providers import falcon_page, freshness, jamf_page
from .store import EndpointStore
from .transport import CollectionError, EndpointClient


def create_connection(store: EndpointStore, tenant: str, body: ConnectionCreate) -> Connection:
    encrypted = encrypt_secret(body.client_secret.get_secret_value())
    connection = Connection(
        **ConnectionSpec.model_validate(body.model_dump(exclude={"client_secret"})).model_dump(),
        id=str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([tenant, body.provider, body.account_id, body.origin]))),
        tenant_id=tenant,
        created_at=now(),
    )
    store.create(connection, encrypted)
    return connection


def require_connection(store: EndpointStore, tenant: str, connection_id: str) -> tuple[Connection, str]:
    record = store.get(tenant, connection_id)
    if record is None:
        raise CollectionError("connection_not_found")
    if not record[0].enabled:
        raise CollectionError("connection_disabled")
    return record


def _resume_state(store: EndpointStore, connection: Connection, restart: bool) -> SyncState:
    state = store.latest(connection.tenant_id, connection.id)
    if state and connection.provider == "crowdstrike" and state.cursor_at:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(state.cursor_at)).total_seconds()
        restart = restart or age >= 110  # Falcon scroll offsets expire after two minutes.
    if state is None or restart or state.status == "complete":
        at = now()
        return SyncState(
            run_id=str(uuid.uuid4()), connection_id=connection.id, tenant_id=connection.tenant_id, started_at=at, updated_at=at
        )
    return state.model_copy(update={"status": "collecting", "gap": ""})


def sync_connection(store: EndpointStore, tenant: str, connection_id: str, request: SyncRequest) -> SyncState:
    connection, encrypted = require_connection(store, tenant, connection_id)
    owner = str(uuid.uuid4())
    store.claim(tenant, connection_id, owner)
    client: EndpointClient | None = None
    try:
        state = _resume_state(store, connection, request.restart)
        store.checkpoint(state, [], owner)
        try:
            client = EndpointClient(connection, decrypt_secret(encrypted))
        except ConnectionSecretError:
            raise CollectionError("credential_decryption_unavailable") from None
        started = time.monotonic()
        fetch_page = jamf_page if connection.provider == "jamf" else falcon_page
        for _ in range(request.max_pages):
            at = now()
            page = fetch_page(client, connection, state.cursor, at)
            if state.expected_count is not None and state.expected_count != page.expected:
                raise CollectionError("inventory_changed_during_collection")
            count = state.device_count + len(page.devices)
            if count > 100_000:
                raise CollectionError("inventory_limit_exceeded")
            if page.complete and count != page.expected:
                raise CollectionError("inventory_count_mismatch")
            candidate = state.model_copy(
                update={
                    "updated_at": now(),
                    "cursor_at": at,
                    "cursor": page.cursor,
                    "device_count": count,
                    "expected_count": page.expected,
                    "pages": state.pages + 1,
                    "status": "complete" if page.complete else "partial",
                    "gap": "" if page.complete else "more_pages_required",
                }
            )
            store.checkpoint(candidate, page.devices, owner)
            state = candidate
            if page.complete or time.monotonic() - started >= 45:
                break
        return state
    except CollectionError as exc:
        state = state.model_copy(update={"status": "partial" if state.pages else "failed", "gap": exc.args[0], "updated_at": now()})
        store.checkpoint(state, [], owner)
        return state
    finally:
        if client:
            client.close()
        store.release(tenant, connection_id, owner)


def fresh_device(signal: DeviceSignal) -> DeviceSignal:
    """Evaluate age at read/decision time, so cached success cannot live forever."""
    hours = signal.attributes.get("freshness_hours", 24)
    signal.attributes["freshness"] = freshness(signal.last_seen, hours, now())
    if signal.attributes["freshness"] != "fresh":
        signal.managed = signal.compliant = signal.disk_encrypted = None
        if "sensor_healthy" in signal.attributes:
            signal.attributes["sensor_healthy"] = None
    return signal


def device_page(store: EndpointStore, tenant: str, connection_id: str, *, limit: int = 100, offset: int = 0) -> dict:
    if store.get(tenant, connection_id) is None:
        raise CollectionError("connection_not_found")
    state = store.latest(tenant, connection_id)
    devices = store.devices(tenant, connection_id, state.run_id, limit=limit, offset=offset) if state else []
    bindings = store.bindings_for_devices(tenant, [device.device_id for device in devices])
    for device in devices:
        device.attributes["agent_bindings"] = bindings.get(device.device_id, [])
    return {
        "schema_version": "endpoint.inventory.v1",
        "recent_receipts": [state.model_dump() for state in store.history(tenant, connection_id)],
        "sync": state.model_dump() if state else None,
        "devices": [fresh_device(signal).to_public_dict() for signal in devices],
        "offset": offset,
        "limit": limit,
    }


def connection_list(store: EndpointStore, tenant: str) -> dict:
    """One API/MCP listing contract includes completeness and collection gaps."""
    result = []
    for connection in store.connections(tenant):
        state = store.latest(tenant, connection.id)
        result.append({"connection": connection.model_dump(), "sync": state.model_dump() if state else None})
    return {"connections": result}
