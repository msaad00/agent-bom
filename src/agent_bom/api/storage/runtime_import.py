"""Restore complete runtime session groups using the existing projection owner."""

from __future__ import annotations

import json
from typing import Any, cast

from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore
from agent_bom.api.runtime_event_store import _merge_sessions_for_batch, sanitize_runtime_metadata
from agent_bom.api.storage.canonical_import import PinnedImportPool, payload_of
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.api.tenant_worker import tenant_bound_context

RUNTIME_TABLES = {"runtime_observations", "runtime_sessions"}


def runtime_groups(records: list[tuple[str, Any, dict[str, Any]]]) -> dict[tuple[str, str], tuple[Any, list[Any]]]:
    groups: dict[tuple[str, str], tuple[Any, list[Any]]] = {
        (r.tenant_id, r.session_id): (r, []) for t, r, _ in records if t == "runtime_sessions"
    }
    for table, record, _ in records:
        if table == "runtime_observations":
            key = record.tenant_id, record.session_id
            if key not in groups:
                raise ValueError("Runtime observation has no selected session")
            groups[key][1].append(record)
    return groups


def validate_runtime_groups(records: list[tuple[str, Any, dict[str, Any]]], tables: list[str]) -> None:
    if RUNTIME_TABLES.intersection(tables) and not RUNTIME_TABLES.issubset(tables):
        raise ValueError("Select both runtime observation and session tables together")
    for (_, session_id), (session, observations) in runtime_groups(records).items():
        for record in observations:
            if record.raw_payload_stored or record.redaction_status != "metadata_only":
                raise ValueError("Runtime recovery requires metadata-only source evidence")
            if any(sanitize_runtime_metadata(value) != value for value in (record.summary, record.metadata)):
                raise ValueError("Runtime source metadata requires explicit redaction before recovery")
        derived = _merge_sessions_for_batch({}, observations).get(session_id)
        if derived is None or payload_of(derived) != payload_of(session):
            raise ValueError("Runtime session cannot be reconstructed from the selected observations; retain and reconcile the source")


def import_runtime_groups(conn: Any, records: list[tuple[str, Any, dict[str, Any]]]) -> dict[str, int]:
    counts = {"inserted": 0, "unchanged": 0, "conflicts": 0}
    groups = runtime_groups(records)
    if groups and not postgres_deployment_configured():
        raise ValueError("Configure the Postgres deployment before importing runtime evidence")
    for (tenant_id, session_id), (session, observations) in groups.items():
        conn.execute("SELECT set_config('app.tenant_id',%s,true)", (tenant_id,))
        conn.execute("SELECT set_config('app.bypass_rls','0',true)")
        with tenant_bound_context(tenant_id):
            owner = PostgresRuntimeEventStore(pool=cast(Any, PinnedImportPool(conn)))
            current = owner.get_session(tenant_id, session_id)
            rows = conn.execute(
                "SELECT data FROM runtime_observations WHERE tenant_id=%s AND session_id=%s", (tenant_id, session_id)
            ).fetchall()
            existing = {json.loads(row[0])["observation_id"]: json.loads(row[0]) for row in rows}
            expected = {record.observation_id: payload_of(record) for record in observations}
            if current is not None or existing:
                if current is not None and payload_of(current) == payload_of(session) and existing == expected:
                    counts["unchanged"] += len(observations) + 1
                else:
                    counts["conflicts"] += 1
                continue
            # Another target session may already own an observation identity.
            identities = [record.observation_id for record in observations]
            collision = conn.execute(
                "SELECT 1 FROM runtime_observations WHERE tenant_id=%s AND observation_id=ANY(%s) LIMIT 1", (tenant_id, identities)
            ).fetchone()
            if collision:
                counts["conflicts"] += 1
                continue
            owner.restore_observations_batch(observations)
            written = owner.get_session(tenant_id, session_id)
            persisted = {
                r.observation_id: payload_of(r)
                for r in owner.list_observations(tenant_id, session_id=session_id, limit=len(observations) + 1)
            }
            if written is None or payload_of(written) != payload_of(session) or persisted != expected:
                raise ValueError("Runtime recovery did not preserve the selected evidence")
            counts["inserted"] += len(observations) + 1
    return counts
