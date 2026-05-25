"""Dataset version registry API routes."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Path, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_bom.api.audit_log import log_action
from agent_bom.api.dataset_version_store import DatasetVersionRecord, get_dataset_version_store
from agent_bom.api.tenancy import require_request_tenant_id

router = APIRouter()

_STABLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")


class DatasetVersionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version_id: str | None = Field(default=None, min_length=1, max_length=128)
    artifact_uri: str | None = Field(default=None, max_length=2048)
    digest: str | None = Field(default=None, max_length=256)
    digest_algorithm: str = Field(default="sha256", min_length=1, max_length=32)
    source: str = Field(default="api", min_length=1, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str | None = Field(default=None, description="Deprecated compatibility field; request tenant scope is authoritative.")

    @field_validator("version_id")
    @classmethod
    def _version_id_must_be_stable(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip()
        if not _STABLE_ID_RE.fullmatch(normalized):
            raise ValueError("version_id must be a stable identifier")
        return normalized

    @field_validator("digest_algorithm", "source")
    @classmethod
    def _non_empty_label(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be empty")
        return normalized


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "api"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_dataset_id(dataset_id: str) -> str:
    normalized = dataset_id.strip()
    if not _STABLE_ID_RE.fullmatch(normalized):
        raise HTTPException(status_code=422, detail="dataset_id must be a stable identifier")
    return normalized


@router.post("/v1/datasets/{dataset_id}/versions", tags=["datasets"], status_code=201)
async def register_dataset_version(
    request: Request,
    dataset_id: Annotated[str, Path(min_length=1, max_length=128)],
    body: DatasetVersionCreate,
) -> dict[str, Any]:
    """Register a dataset artifact version for headless agents and scanners."""
    tenant_id = _tenant_id(request)
    normalized_dataset_id = _validate_dataset_id(dataset_id)
    version_id = body.version_id or str(uuid.uuid4())
    ignored_body_tenant = bool(body.tenant_id and body.tenant_id != tenant_id)
    record = DatasetVersionRecord(
        tenant_id=tenant_id,
        dataset_id=normalized_dataset_id,
        version_id=version_id,
        created_at=_now(),
        source=body.source,
        artifact_uri=body.artifact_uri,
        digest=body.digest,
        digest_algorithm=body.digest_algorithm,
        metadata=body.metadata,
    )
    get_dataset_version_store().put(record)
    log_action(
        "datasets.version_registered",
        actor=_actor(request),
        resource=f"dataset/{normalized_dataset_id}/version/{version_id}",
        tenant_id=tenant_id,
    )
    warnings = ["tenant_id in body ignored; request tenant scope is authoritative"] if ignored_body_tenant else []
    return {"schema_version": "v1", "dataset": record.to_dict(), "warnings": warnings}


@router.get("/v1/datasets/{dataset_id}/versions", tags=["datasets"])
async def list_dataset_versions(
    request: Request,
    dataset_id: Annotated[str, Path(min_length=1, max_length=128)],
) -> dict[str, Any]:
    tenant_id = _tenant_id(request)
    normalized_dataset_id = _validate_dataset_id(dataset_id)
    versions = [record.to_dict() for record in get_dataset_version_store().list(tenant_id, normalized_dataset_id)]
    return {
        "schema_version": "v1",
        "tenant_id": tenant_id,
        "dataset_id": normalized_dataset_id,
        "versions": versions,
        "count": len(versions),
    }


@router.get("/v1/datasets/{dataset_id}/versions/{version_id}", tags=["datasets"])
async def get_dataset_version(
    request: Request,
    dataset_id: Annotated[str, Path(min_length=1, max_length=128)],
    version_id: Annotated[str, Path(min_length=1, max_length=128)],
) -> dict[str, Any]:
    tenant_id = _tenant_id(request)
    normalized_dataset_id = _validate_dataset_id(dataset_id)
    normalized_version_id = _validate_dataset_id(version_id)
    record = get_dataset_version_store().get(tenant_id, normalized_dataset_id, normalized_version_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Dataset version not found")
    return {"schema_version": "v1", "dataset": record.to_dict()}
