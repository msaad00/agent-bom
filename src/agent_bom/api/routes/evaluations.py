"""Evaluation run registry API routes."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_bom.api.audit_log import log_action
from agent_bom.api.dataset_version_store import get_dataset_version_store
from agent_bom.api.evaluation_store import EvaluationRunRecord, get_evaluation_run_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.security import sanitize_error

router = APIRouter()

_STABLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_STATUS_VALUES = {"queued", "running", "completed", "failed", "cancelled"}


class EvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1, max_length=128)
    input_ref: str | None = Field(default=None, max_length=2048)
    expected_ref: str | None = Field(default=None, max_length=2048)
    output_ref: str | None = Field(default=None, max_length=2048)
    trace_id: str | None = Field(default=None, max_length=128)
    scores: dict[str, float] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("case_id")
    @classmethod
    def _case_id_must_be_stable(cls, value: str) -> str:
        return _validate_stable_label(value, "case_id")


class EvaluationRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evaluation_id: str | None = Field(default=None, min_length=1, max_length=128)
    name: str | None = Field(default=None, max_length=256)
    status: str = Field(default="completed")
    dataset_id: str | None = Field(default=None, max_length=128)
    dataset_version_id: str | None = Field(default=None, max_length=128)
    trace_id: str | None = Field(default=None, max_length=128)
    model: str | None = Field(default=None, max_length=256)
    prompt_hash: str | None = Field(default=None, max_length=256)
    source: str = Field(default="api", min_length=1, max_length=128)
    scores: dict[str, float] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    cases: list[EvaluationCase] = Field(default_factory=list, max_length=500)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str | None = Field(default=None, description="Deprecated compatibility field; request tenant scope is authoritative.")

    @field_validator("evaluation_id", "dataset_id", "dataset_version_id")
    @classmethod
    def _stable_optional_id(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return value
        return _validate_stable_label(value, str(info.field_name))

    @field_validator("status")
    @classmethod
    def _known_status(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in _STATUS_VALUES:
            raise ValueError(f"status must be one of {sorted(_STATUS_VALUES)}")
        return normalized

    @field_validator("source")
    @classmethod
    def _source_non_empty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("source must not be empty")
        return normalized

    @model_validator(mode="after")
    def _dataset_version_requires_dataset(self) -> EvaluationRunCreate:
        if self.dataset_version_id and not self.dataset_id:
            raise ValueError("dataset_version_id requires dataset_id")
        return self


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _actor(request: Request) -> str:
    return getattr(request.state, "api_key_name", "") or getattr(request.state, "auth_method", "") or "api"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_stable_label(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not _STABLE_ID_RE.fullmatch(normalized):
        raise ValueError(f"{field_name} must be a stable identifier")
    return normalized


def _validate_path_id(value: str, field_name: str) -> str:
    try:
        return _validate_stable_label(value, field_name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=sanitize_error(exc)) from exc


def _validate_dataset_link(tenant_id: str, body: EvaluationRunCreate) -> None:
    if not body.dataset_id or not body.dataset_version_id:
        return
    record = get_dataset_version_store().get(tenant_id, body.dataset_id, body.dataset_version_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Dataset version not found for evaluation run")


@router.post("/evaluations", tags=["evaluations"], status_code=201)
async def register_evaluation_run(request: Request, body: EvaluationRunCreate) -> dict[str, Any]:
    """Register an evaluation run linked to dataset versions, traces, models, and prompt hashes."""
    tenant_id = _tenant_id(request)
    _validate_dataset_link(tenant_id, body)
    now = _now()
    evaluation_id = body.evaluation_id or str(uuid.uuid4())
    ignored_body_tenant = bool(body.tenant_id and body.tenant_id != tenant_id)
    record = EvaluationRunRecord(
        tenant_id=tenant_id,
        evaluation_id=evaluation_id,
        created_at=now,
        updated_at=now,
        name=body.name,
        status=body.status,
        dataset_id=body.dataset_id,
        dataset_version_id=body.dataset_version_id,
        trace_id=body.trace_id,
        model=body.model,
        prompt_hash=body.prompt_hash,
        source=body.source,
        scores=body.scores,
        summary=body.summary,
        cases=[case.model_dump(exclude_none=True) for case in body.cases],
        metadata=body.metadata,
    )
    get_evaluation_run_store().put(record)
    log_action(
        "evaluations.run_registered",
        actor=_actor(request),
        resource=f"evaluation/{evaluation_id}",
        tenant_id=tenant_id,
    )
    warnings = ["tenant_id in body ignored; request tenant scope is authoritative"] if ignored_body_tenant else []
    return {"schema_version": "evals.runs.v1", "evaluation": record.to_dict(), "warnings": warnings}


@router.get("/evaluations", tags=["evaluations"])
async def list_evaluation_runs(
    request: Request,
    dataset_id: Annotated[str | None, Query(max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    tenant_id = _tenant_id(request)
    normalized_dataset_id = _validate_path_id(dataset_id, "dataset_id") if dataset_id else None
    runs = [
        record.to_dict()
        for record in get_evaluation_run_store().list(
            tenant_id,
            dataset_id=normalized_dataset_id,
            limit=limit,
            offset=offset,
        )
    ]
    return {
        "schema_version": "evals.runs.v1",
        "tenant_id": tenant_id,
        "evaluations": runs,
        "count": len(runs),
        "limit": limit,
        "offset": offset,
    }


@router.get("/evaluations/{evaluation_id}", tags=["evaluations"])
async def get_evaluation_run(
    request: Request,
    evaluation_id: Annotated[str, Path(min_length=1, max_length=128)],
) -> dict[str, Any]:
    tenant_id = _tenant_id(request)
    normalized_evaluation_id = _validate_path_id(evaluation_id, "evaluation_id")
    record = get_evaluation_run_store().get(tenant_id, normalized_evaluation_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Evaluation run not found")
    return {"schema_version": "evals.runs.v1", "evaluation": record.to_dict()}
