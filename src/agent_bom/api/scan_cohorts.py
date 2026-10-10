"""Deterministic identities and manifests for correlation cohorts."""

from __future__ import annotations

import uuid

_CORRELATION_COHORT_NAMESPACE = uuid.UUID("4ed03a68-3d20-5e02-971f-66f17c235c91")


def correlation_cohort_id(*, tenant_id: str, idempotency_key: str) -> str:
    """Return an immutable tenant-bound cohort id from an explicit request key."""

    tenant = tenant_id.strip()
    key = idempotency_key.strip()
    if not tenant or not key or len(key) > 200:
        raise ValueError("tenant_id and idempotency_key are required for a correlation cohort")
    return str(uuid.uuid5(_CORRELATION_COHORT_NAMESPACE, f"{tenant}\x00{key}"))


def correlation_cohort_parent_job_id(*, tenant_id: str, correlation_cohort_id: str) -> str:
    """Return the stable parent job id reserved for one tenant-bound cohort."""

    return str(
        uuid.uuid5(
            _CORRELATION_COHORT_NAMESPACE,
            f"{tenant_id}\x00{correlation_cohort_id}\x00parent",
        )
    )
