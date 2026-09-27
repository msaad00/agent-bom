"""Bounded operator-recorded lifecycle references, separate from runtime proof."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_bom.evidence.agent_bom import AgentBomDocument

RecordKind = Literal["agent", "deployment", "instance", "run", "snapshot"]
Id = Annotated[str, Field(min_length=1, max_length=512, pattern=r"^\S(?:[^\x00-\x1f\x7f]*\S)?$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class LifecycleInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CaptureSnapshot(LifecycleInput):
    scan_id: Id
    agent_id: Id


class RegisterDeployment(LifecycleInput):
    deployment_id: Id
    agent_id: Id
    snapshot_id: Digest
    version: Annotated[str, Field(min_length=1, max_length=200)]


class RegisterInstance(LifecycleInput):
    instance_id: Id
    deployment_id: Id
    identity_id: Id
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def aware_expiry(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("expiry requires a timezone")
        return value.astimezone(timezone.utc) if value is not None else None


class RegisterRun(LifecycleInput):
    run_id: Id
    instance_id: Id
    conversation_id: Id | None = None


class LifecycleRecord(LifecycleInput):
    kind: RecordKind
    record_id: Id
    tenant_id: Id
    agent_id: Id
    recorded_at: datetime
    recorded_by: Annotated[str, Field(min_length=1, max_length=200)]
    parent_id: Id | None = None
    snapshot_id: Digest | None = None
    identity_id: Id | None = None
    version: str | None = None
    conversation_id: Id | None = None
    expires_at: datetime | None = None
    retired_at: datetime | None = None
    retired_by: str | None = None
    composition_digest: Digest | None = None
    observed_at: datetime | None = None
    # A registry write is an operator assertion, never proof of possession,
    # execution, authority, successful completion, or delegation.
    assurance: Literal["operator_recorded"] = "operator_recorded"

    def active(self, at: datetime) -> bool:
        return self.retired_at is None and (self.expires_at is None or self.expires_at > at)


class LifecyclePage(LifecycleInput):
    items: list[LifecycleRecord]
    next_offset: int | None
    history_limit_reached: bool = False


def composition_digest(document: AgentBomDocument) -> str:
    """Compare recorded composition independently of receipts and display labels.

    Coverage, identity assurance and source time remain in the full snapshot
    digest. Stable component IDs and relationship basis remain significant.
    """
    components = [row.model_dump(mode="json", exclude={"evidence_ids"}) for row in document.content.components]
    edges = [row.model_dump(mode="json", exclude={"evidence_ids"}) for row in document.content.relationships]
    payload = {
        "subject": {"agent_id": document.content.subject.agent_id, "version": document.content.subject.version},
        "components": sorted(components, key=lambda row: row["component_id"]),
        "relationships": sorted(edges, key=lambda row: (row["source"], row["target"], row["relationship"])),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
