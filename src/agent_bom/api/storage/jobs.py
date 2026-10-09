"""Shared job mutation SQL with adapter-owned transactions and deployed names."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from agent_bom.api.finding_read_context import read_once_shared
from agent_bom.api.storage.sql import Dialect, SqlSession, load_json
from agent_bom.core.tenancy import require_explicit_tenant_id

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob


def require_job_tenant(tenant_id: str) -> str:
    require_explicit_tenant_id(tenant_id)
    return tenant_id


def put_job(session: SqlSession, dialect: Dialect, job: ScanJob, *, if_absent: bool = False) -> int:
    require_job_tenant(job.tenant_id)
    table, tenant = ("scan_jobs", "team_id") if dialect == "postgres" else ("jobs", "tenant_id")
    columns = (
        "job_id",
        "status",
        "created_at",
        "completed_at",
        tenant,
        "batch_id",
        "parent_job_id",
        "child_job_ids",
        "target",
        "target_index",
        "target_count",
        "schedule_id",
        "triggered_by",
        "data",
    )
    placeholders = ["?::jsonb" if dialect == "postgres" and col in {"child_job_ids", "target", "data"} else "?" for col in columns]
    update = ", ".join(f"{col}=excluded.{col}" for col in columns if col not in {"job_id", tenant})
    conflict = "DO NOTHING" if if_absent else f"DO UPDATE SET {update}"  # nosec B608 - fixed column names
    # Identifiers and SQL fragments above are selected only from fixed literals.
    sql = (
        f"INSERT INTO {table} ({', '.join(columns)}) "  # nosec B608 - static identifiers
        f"VALUES ({', '.join(placeholders)}) ON CONFLICT ({tenant}, job_id) {conflict}"
    )
    return int(
        session.execute(
            sql,
            (
                job.job_id,
                job.status.value,
                job.created_at,
                job.completed_at,
                job.tenant_id,
                job.batch_id,
                job.parent_job_id,
                json.dumps(job.child_job_ids),
                json.dumps(job.target) if job.target is not None else None,
                job.target_index,
                job.target_count,
                job.schedule_id,
                job.triggered_by,
                job.model_dump_json(),
            ),
        ).rowcount
        or 0
    )


def parse_job_payload(payload: Any) -> ScanJob:
    """Parse one persisted job row.

    Inside an aggregate read scope, identical payload text is parsed once and
    the resulting object is shared by every read in that scope, and by any
    concurrent scope reading the same text: a dashboard page fires several
    aggregate reads at once, and each re-parsing a multi-megabyte payload held
    the GIL for the whole parse. Any committed change produces different text
    and therefore a fresh parse; the shared object is read-only by contract.
    Outside a scope every call returns an independent object.
    """
    from agent_bom.api.models import ScanJob

    if not isinstance(payload, str):
        return ScanJob.model_validate(load_json(payload))
    return read_once_shared(("scan_job_payload", payload), lambda: ScanJob.model_validate_json(payload))


def get_job(session: SqlSession, dialect: Dialect, job_id: str, tenant_id: str | None) -> ScanJob | None:
    table, tenant = ("scan_jobs", "team_id") if dialect == "postgres" else ("jobs", "tenant_id")
    where = "job_id = ?" + (f" AND {tenant} = ?" if tenant_id is not None else "")
    params = (job_id, tenant_id) if tenant_id is not None else (job_id,)
    rows = session.execute(
        f"SELECT data FROM {table} WHERE {where} LIMIT 2",  # nosec B608 - static identifiers and predicates
        params,
    ).fetchall()
    if len(rows) > 1:
        raise ValueError("Ambiguous job identity requires a tenant_id")
    return parse_job_payload(rows[0][0]) if rows else None
