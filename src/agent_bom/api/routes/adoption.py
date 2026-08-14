"""Opt-in, privacy-bounded adoption funnel observability."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, model_validator

from agent_bom.db.adoption_events import get_adoption_event_store
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(prefix="/observability/adoption", tags=["observability"])
_READ = require_authenticated_permission("config")
_WRITE = require_authenticated_permission("scan")


class AdoptionEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event: Literal["scan_completed", "artifact_created", "investigation_started", "verification_completed"]
    channel: Literal["cli", "ci", "github_action", "control_plane", "docker"]
    outcome: Literal["complete", "partial", "failed", "verified_fixed", "still_affected", "unavailable_evidence"] | None = None
    artifact_type: Literal["json", "sarif", "cyclonedx", "spdx", "html", "markdown", "graph"] | None = None
    ci_provider: Literal["github_actions", "gitlab_ci", "circleci", "jenkins", "other"] | None = None

    @model_validator(mode="after")
    def required_dimensions(self) -> AdoptionEventRequest:
        if self.event == "scan_completed" and self.outcome is None:
            raise ValueError("scan_completed requires outcome")
        if self.event == "artifact_created" and self.artifact_type is None:
            raise ValueError("artifact_created requires artifact_type")
        return self


@router.get("")
def adoption_summary(_role: object = _READ) -> dict[str, object]:
    return get_adoption_event_store().summary()


@router.post("/events", status_code=202)
def record_adoption_event(body: AdoptionEventRequest, _role: object = _WRITE) -> dict[str, object]:
    dimensions = body.model_dump(exclude={"event"}, exclude_none=True)
    recorded = get_adoption_event_store().record(body.event, **dimensions)
    return {"schema_version": "adoption-event.v1", "recorded": recorded}
