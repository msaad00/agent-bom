"""Portable, content-addressed evidence about one agent, not a fleet rollup.

This is an experimental agent-bom profile, not a claim of standards-body
adoption. Digests detect document changes; they do not authenticate a producer.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_bom.models import Agent
from agent_bom.security import sanitize_text

Identifier = Annotated[str, Field(min_length=1, max_length=512)]
Label = Annotated[str, Field(min_length=1, max_length=200)]
Area = Literal["composition", "models", "data", "identity", "authority", "runtime", "vulnerabilities", "controls", "cost"]
Relationship = Literal["configured_with", "provides_tool", "contains_package", "uses_model", "uses_data", "delegates_to"]
AREAS: tuple[Area, ...] = ("composition", "models", "data", "identity", "authority", "runtime", "vulnerabilities", "controls", "cost")
MAX_AGENT_BOM_BYTES = 8 * 1024 * 1024


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AgentBomSubject(_Record):
    agent_id: Identifier
    name: Label
    agent_type: Label
    version: str | None = Field(default=None, max_length=200)
    source_id: str | None = Field(default=None, max_length=512)
    identity_status: Literal["observed", "verified"]


class AgentBomReceipt(_Record):
    evidence_id: Identifier
    source: Label
    method: Literal["configuration", "inventory", "scan", "runtime", "provider_api"]
    observed_at: datetime | None = None
    # Producer claims remain claims until a consumer verifies their provenance.
    assurance: Literal["producer_asserted", "collector_observed"]

    @field_validator("observed_at")
    @classmethod
    def aware_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("observation time must include a timezone")
        return value


class AgentBomComponent(_Record):
    component_id: Identifier
    kind: Literal["mcp_server", "tool", "package", "model", "data"]
    name: Label
    version: str | None = Field(default=None, max_length=200)
    ecosystem: str | None = Field(default=None, max_length=100)
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=100)


class AgentBomRelationship(_Record):
    source: Identifier
    target: Identifier
    relationship: Relationship
    basis: Literal["declared", "observed", "evaluated"]
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=100)


class AgentBomCoverage(_Record):
    area: Area
    status: Literal["complete", "partial", "not_assessed", "unsupported", "failed"]
    reason: Annotated[str, Field(min_length=1, max_length=300)]
    evidence_ids: tuple[Identifier, ...] = Field(default=(), max_length=100)


class AgentBomContent(_Record):
    tenant_id: Identifier
    subject: AgentBomSubject
    components: tuple[AgentBomComponent, ...] = Field(max_length=10000)
    relationships: tuple[AgentBomRelationship, ...] = Field(max_length=20000)
    evidence: tuple[AgentBomReceipt, ...] = Field(min_length=1, max_length=10000)
    coverage: tuple[AgentBomCoverage, ...] = Field(min_length=9, max_length=9)

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        component_ids = [item.component_id for item in self.components]
        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(set(component_ids)) != len(component_ids) or self.subject.agent_id in component_ids:
            raise ValueError("component identifiers must be unique and distinct from the subject")
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("evidence identifiers must be unique")
        if {item.area for item in self.coverage} != set(AREAS):
            raise ValueError("each coverage area must occur exactly once")
        nodes = {self.subject.agent_id, *component_ids}
        receipts = set(evidence_ids)
        edges: set[tuple[str, str, str]] = set()
        for edge in self.relationships:
            if edge.source not in nodes or edge.target not in nodes:
                raise ValueError("relationship endpoint is outside this agent BOM")
            key = (edge.source, edge.target, edge.relationship)
            if key in edges:
                raise ValueError("duplicate relationship")
            edges.add(key)
        references = [item.evidence_ids for item in self.components]
        references.extend(item.evidence_ids for item in self.relationships)
        references.extend(item.evidence_ids for item in self.coverage)
        for reference_ids in references:
            if not set(reference_ids) <= receipts:
                raise ValueError("unknown evidence reference")
        for item in self.coverage:
            if item.status == "complete" and not item.evidence_ids:
                raise ValueError("complete coverage requires evidence")
        return self


def content_digest(content: AgentBomContent) -> str:
    """Profile-specific sorted-key JSON encoding; deliberately not called JCS."""
    raw = json.dumps(content.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AgentBomDocument(_Record):
    schema_version: Literal["agent-bom.profile/v1"] = "agent-bom.profile/v1"
    maturity: Literal["experimental"] = "experimental"
    generated_at: datetime
    snapshot_id: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    content: AgentBomContent

    @model_validator(mode="after")
    def validate_document(self) -> Self:
        if self.generated_at.utcoffset() is None:
            raise ValueError("generation time must include a timezone")
        if self.snapshot_id != content_digest(self.content):
            raise ValueError("agent BOM content digest mismatch")
        return self


def _key(*parts: str) -> str:
    raw = json.dumps(parts, separators=(",", ":"), ensure_ascii=False)
    return "component:" + hashlib.sha256(raw.encode()).hexdigest()


def validate_agent_bom_json(payload: bytes | str) -> AgentBomDocument:
    """Bound input and reject ambiguous JSON before semantic validation."""
    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    if len(raw) > MAX_AGENT_BOM_BYTES:
        raise ValueError("agent BOM exceeds 8 MiB")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        data = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("invalid JSON encoding or nesting") from exc
    return AgentBomDocument.model_validate(data)


def build_agent_bom(agent: Agent, *, tenant_id: str = "local", generated_at: datetime | None = None) -> AgentBomDocument:
    """Export selected inventory without copying credentials, prompts or metadata.

    Configuration membership is declared composition, never verified runtime
    authority. Missing evidence stays not_assessed even when a list is empty.
    """
    observed_at: datetime | None = None
    try:
        parsed = datetime.fromisoformat(agent.last_seen or agent.discovered_at)
        if parsed.utcoffset() is not None:
            observed_at = parsed
    except (ValueError, TypeError):
        pass
    receipt = AgentBomReceipt(
        evidence_id="inventory:agent",
        source=sanitize_text(agent.source or "local-discovery", max_len=200),
        method="inventory",
        observed_at=observed_at,
        assurance="producer_asserted",
    )
    evidence_ids = (receipt.evidence_id,)
    components: dict[str, AgentBomComponent] = {}
    relationships: dict[tuple[str, str, str], AgentBomRelationship] = {}

    def add(component: AgentBomComponent, parent: str, relation: Relationship) -> None:
        previous = components.get(component.component_id)
        if previous is not None and previous != component:
            raise ValueError("conflicting component evidence")
        components[component.component_id] = component
        edge = AgentBomRelationship(
            source=parent, target=component.component_id, relationship=relation, basis="declared", evidence_ids=evidence_ids
        )
        relationships[(parent, component.component_id, relation)] = edge

    for server in agent.mcp_servers:
        server_id = _key("mcp_server", server.canonical_id)
        add(
            AgentBomComponent(
                component_id=server_id, kind="mcp_server", name=sanitize_text(server.name, max_len=200), evidence_ids=evidence_ids
            ),
            agent.stable_id,
            "configured_with",
        )
        for tool in server.tools:
            add(
                AgentBomComponent(
                    component_id=_key("tool", server_id, tool.name),
                    kind="tool",
                    name=sanitize_text(tool.name, max_len=200),
                    evidence_ids=evidence_ids,
                ),
                server_id,
                "provides_tool",
            )
        for package in server.packages:
            add(
                AgentBomComponent(
                    component_id=_key("package", package.ecosystem, package.name, package.version),
                    kind="package",
                    name=sanitize_text(package.name, max_len=200),
                    version=sanitize_text(package.version, max_len=200) or None,
                    ecosystem=sanitize_text(package.ecosystem, max_len=100),
                    evidence_ids=evidence_ids,
                ),
                server_id,
                "contains_package",
            )

    coverage = tuple(
        AgentBomCoverage(
            area=area,
            status="partial" if area == "composition" else "not_assessed",
            reason="selected_inventory_only" if area == "composition" else "no_assessment_evidence_in_export",
            evidence_ids=evidence_ids if area == "composition" else (),
        )
        for area in AREAS
    )
    content = AgentBomContent(
        tenant_id=tenant_id,
        subject=AgentBomSubject(
            agent_id=agent.stable_id,
            name=sanitize_text(agent.name, max_len=200),
            agent_type=agent.agent_type.value,
            version=sanitize_text(agent.version, max_len=200) if agent.version else None,
            source_id=sanitize_text(agent.source_id, max_len=512) if agent.source_id else None,
            identity_status="observed",
        ),
        components=tuple(components[key] for key in sorted(components)),
        relationships=tuple(relationships[key] for key in sorted(relationships)),
        evidence=(receipt,),
        coverage=coverage,
    )
    return AgentBomDocument(generated_at=generated_at or datetime.now(timezone.utc), snapshot_id=content_digest(content), content=content)
