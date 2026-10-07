"""Fleet identity and observation models shared by persistence backends."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field, field_validator, model_validator

from agent_bom.canonical_ids import canonical_agent_id
from agent_bom.platform_invariants import normalize_tenant_id, normalize_timestamp, now_utc_iso


class FleetLifecycleState(str, Enum):
    DISCOVERED = "discovered"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    QUARANTINED = "quarantined"
    DECOMMISSIONED = "decommissioned"


class FleetAgent(BaseModel):
    """A managed agent in the fleet registry."""

    agent_id: str
    canonical_id: str = ""
    name: str
    agent_type: str
    config_path: str = ""
    source_id: str = ""
    device_fingerprint: str = ""
    enrollment_name: str = ""
    mdm_provider: str = ""
    lifecycle_state: FleetLifecycleState = FleetLifecycleState.DISCOVERED
    owner: str | None = None
    environment: str | None = None
    tags: list[str] = Field(default_factory=list)
    trust_score: float = 0.0
    trust_factors: dict[str, Any] = Field(default_factory=dict)
    server_count: int = 0
    package_count: int = 0
    credential_count: int = 0
    vuln_count: int = 0
    tenant_id: str = "default"
    last_discovery: str | None = None
    last_scan: str | None = None
    created_at: str = ""
    updated_at: str = ""
    notes: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def agent_name(self) -> str:
        """Published fleet snapshot alias for the canonical display name."""
        return self.name

    @computed_field  # type: ignore[prop-decorator]
    @property
    def last_seen(self) -> str | None:
        """Latest observed scan/discovery; registry edits are not sightings."""
        observed = [value for value in (self.last_discovery, self.last_scan) if value]
        return max(observed, key=lambda value: datetime.fromisoformat(value.replace("Z", "+00:00"))) if observed else None

    @field_validator("tenant_id", mode="before")
    @classmethod
    def _normalize_tenant_id(cls, value: str | None) -> str:
        normalized: str = normalize_tenant_id(value)
        return normalized

    @field_validator("last_discovery", "last_scan", "created_at", "updated_at", mode="before")
    @classmethod
    def _normalize_timestamps(cls, value: str | None) -> str | None:
        normalized: str | None = normalize_timestamp(value)
        return normalized

    @model_validator(mode="after")
    def _apply_defaults(self) -> FleetAgent:
        if not self.created_at:
            self.created_at = now_utc_iso()
        if not self.updated_at:
            self.updated_at = self.created_at
        if not self.canonical_id:
            self.canonical_id = canonical_agent_id(
                self.agent_type,
                self.name,
                source_id=self.source_id,
                device_fingerprint=self.device_fingerprint,
            )
        return self
