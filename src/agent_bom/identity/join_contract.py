"""Provider-neutral identity and resource join contract.

The contract is intentionally additive: collectors can normalize authoritative
identity/resource references without changing the existing graph builders. It
does not infer aliases or permissions. Only complete, directly observed
structural relationships are asserted; partial and unavailable attempts remain
explicit non-edges with bounded reason codes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from itertools import chain
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_bom.evidence.semantics import (
    ComponentName,
    EvidenceBasis,
    EvidenceCompletenessLedger,
    EvidenceFreshness,
    EvidenceProvenance,
    EvidenceStatus,
    FreshnessStatus,
    Identifier,
    ReasonCode,
)

CanonicalIdentifier = Annotated[str, Field(min_length=1, max_length=500, pattern=r"^[^\s]+$")]
NativeIdentifier = Annotated[str, Field(min_length=1, max_length=2048, pattern=r"^[^\s]+$")]
DisplayName = Annotated[str, Field(min_length=1, max_length=300)]

MAX_IDENTITY_JOIN_EVIDENCE_REFERENCES = 100_000
MAX_IDENTITY_JOIN_NATIVE_IDENTIFIERS = 100_000
MAX_IDENTITY_JOIN_FRESHNESS_SECONDS = 31_536_000


class IdentitySourceKind(StrEnum):
    """Supported identity-source families; ``provider`` keeps the exact vendor."""

    OKTA = "okta"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    SAAS = "saas"


class CanonicalIdentityType(StrEnum):
    """Provider-neutral identity entities used by the join contract."""

    PERSON = "person"
    SERVICE_ACCOUNT = "service_account"
    WORKLOAD_IDENTITY = "workload_identity"
    ROLE = "role"
    GROUP = "group"


class IdentityRelationshipType(StrEnum):
    """Structural relationships only; permissions are deliberately excluded."""

    MEMBER_OF = "member_of"
    ASSUMES = "assumes"
    TRUSTS = "trusts"
    RUNS_AS = "runs_as"
    OWNS = "owns"


class IdentityJoinMethod(StrEnum):
    """Authoritative provider mechanism that established a structural join."""

    DIRECTORY_MEMBERSHIP = "directory_membership"
    ROLE_ASSIGNMENT = "role_assignment"
    TRUST_POLICY = "trust_policy"
    WORKLOAD_BINDING = "workload_binding"
    OWNERSHIP_RECORD = "ownership_record"


_JOIN_METHOD_BY_RELATIONSHIP = {
    IdentityRelationshipType.MEMBER_OF: IdentityJoinMethod.DIRECTORY_MEMBERSHIP,
    IdentityRelationshipType.ASSUMES: IdentityJoinMethod.ROLE_ASSIGNMENT,
    IdentityRelationshipType.TRUSTS: IdentityJoinMethod.TRUST_POLICY,
    IdentityRelationshipType.RUNS_AS: IdentityJoinMethod.WORKLOAD_BINDING,
    IdentityRelationshipType.OWNS: IdentityJoinMethod.OWNERSHIP_RECORD,
}


class _StrictIdentityModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


_SOURCE_PROVIDERS: dict[IdentitySourceKind, frozenset[str]] = {
    IdentitySourceKind.OKTA: frozenset({"okta"}),
    IdentitySourceKind.AWS: frozenset({"aws"}),
    IdentitySourceKind.AZURE: frozenset({"azure", "entra"}),
    IdentitySourceKind.GCP: frozenset({"gcp"}),
}
_RESERVED_PROVIDERS = frozenset(chain.from_iterable(_SOURCE_PROVIDERS.values()))
_PROVIDER_NATIVE_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "allOf": [
        *(
            {
                "if": {"properties": {"source": {"const": source.value}}, "required": ["source"]},
                "then": {"properties": {"provider": {"enum": sorted(providers)}}},
            }
            for source, providers in _SOURCE_PROVIDERS.items()
        ),
        {
            "if": {"properties": {"source": {"const": "saas"}}, "required": ["source"]},
            "then": {"properties": {"provider": {"not": {"enum": sorted(_RESERVED_PROVIDERS)}}}},
        },
    ]
}


def _native_key(value: ProviderNativeId) -> tuple[IdentitySourceKind, str, str, str, str]:
    return (value.source, value.provider, value.account or "", value.id_type, value.value)


class ProviderNativeId(_StrictIdentityModel):
    """One exact provider identifier retained for deterministic correlation."""

    model_config = ConfigDict(json_schema_extra=_PROVIDER_NATIVE_JSON_SCHEMA_EXTRA)

    source: IdentitySourceKind
    provider: ComponentName
    id_type: ComponentName
    value: NativeIdentifier
    account: NativeIdentifier | None = None

    @model_validator(mode="after")
    def validate_provider_family(self) -> Self:
        expected = _SOURCE_PROVIDERS.get(self.source)
        if expected is not None and self.provider not in expected:
            raise ValueError("provider must match its source family")
        if self.source is IdentitySourceKind.SAAS and self.provider in _RESERVED_PROVIDERS:
            raise ValueError("provider must match its source family")
        return self


_CATALOG_ROW_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "allOf": [
        {"properties": {"status": {"enum": ["complete", "partial"]}}},
        {
            "if": {"properties": {"status": {"const": "partial"}}, "required": ["status"]},
            "then": {"properties": {"reason_codes": {"minItems": 1}}},
        },
    ]
}


class _ObservedCatalogReference(_StrictIdentityModel):
    """Shared completeness and provenance rules for normalized catalog rows."""

    model_config = ConfigDict(json_schema_extra=_CATALOG_ROW_JSON_SCHEMA_EXTRA)

    display_name: DisplayName
    native_ids: tuple[ProviderNativeId, ...] = Field(min_length=1, max_length=20)
    status: EvidenceStatus = EvidenceStatus.COMPLETE
    evidence_refs: tuple[CanonicalIdentifier, ...] = Field(min_length=1, max_length=50)
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=20)

    @field_validator("native_ids")
    @classmethod
    def unique_native_ids(cls, value: tuple[ProviderNativeId, ...]) -> tuple[ProviderNativeId, ...]:
        keys = {_native_key(item) for item in value}
        if len(keys) != len(value):
            raise ValueError("provider-native identifiers must be unique within one canonical row")
        return value

    @field_validator("evidence_refs", "reason_codes")
    @classmethod
    def dedupe_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _dedupe(value)

    @model_validator(mode="after")
    def validate_observed_row(self) -> Self:
        if self.status not in {EvidenceStatus.COMPLETE, EvidenceStatus.PARTIAL}:
            raise ValueError("unavailable or failed inventory must not emit a fabricated catalog row")
        if self.status is EvidenceStatus.PARTIAL and not self.reason_codes:
            raise ValueError("partial catalog rows require a reason code")
        return self


class CanonicalIdentityEntity(_ObservedCatalogReference):
    """Canonical identity with one or more authoritative provider-native IDs."""

    entity_id: CanonicalIdentifier
    entity_type: CanonicalIdentityType


class CanonicalResourceReference(_ObservedCatalogReference):
    """Bounded resource reference that an observed identity relationship targets."""

    resource_id: CanonicalIdentifier
    resource_type: ComponentName


_RELATIONSHIP_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "allOf": [
        *(
            {
                "if": {
                    "properties": {"relationship_type": {"const": relationship_type.value}},
                    "required": ["relationship_type"],
                },
                "then": {"properties": {"join_method": {"const": join_method.value}}},
            }
            for relationship_type, join_method in _JOIN_METHOD_BY_RELATIONSHIP.items()
        ),
        {
            "if": {"properties": {"status": {"const": "complete"}}, "required": ["status"]},
            "then": {
                "required": [
                    "source_ref",
                    "target_ref",
                    "evidence_refs",
                    "source_native_id",
                    "target_native_id",
                    "provider_assertion_ids",
                ],
                "properties": {
                    "source_ref": {"type": "string"},
                    "target_ref": {"type": "string"},
                    "evidence_refs": {"minItems": 1},
                    "source_native_id": {"type": "object"},
                    "target_native_id": {"type": "object"},
                    "provider_assertion_ids": {"minItems": 1},
                },
            },
        },
        {
            "if": {"properties": {"status": {"const": "partial"}}, "required": ["status"]},
            "then": {
                "properties": {
                    "reason_codes": {"minItems": 1},
                    "evidence_refs": {"minItems": 1},
                },
                "anyOf": [
                    {"required": ["source_ref"], "properties": {"source_ref": {"type": "string"}}},
                    {"required": ["target_ref"], "properties": {"target_ref": {"type": "string"}}},
                ],
            },
        },
        {
            "if": {
                "properties": {"status": {"enum": ["partial", "unavailable", "failed"]}},
                "required": ["status"],
            },
            "then": {"properties": {"reason_codes": {"minItems": 1}}},
        },
    ]
}


class IdentityRelationship(_StrictIdentityModel):
    """One structural join assertion or an explicit incomplete join attempt."""

    model_config = ConfigDict(json_schema_extra=_RELATIONSHIP_JSON_SCHEMA_EXTRA)

    relationship_id: CanonicalIdentifier
    relationship_type: IdentityRelationshipType
    join_method: IdentityJoinMethod
    source_ref: CanonicalIdentifier | None = None
    target_ref: CanonicalIdentifier | None = None
    source_native_id: ProviderNativeId | None = None
    target_native_id: ProviderNativeId | None = None
    provider_assertion_ids: tuple[Identifier, ...] = Field(default=(), max_length=20)
    status: EvidenceStatus
    evidence_refs: tuple[CanonicalIdentifier, ...] = Field(default=(), max_length=50)
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=20)

    @field_validator("evidence_refs", "reason_codes")
    @classmethod
    def dedupe_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _dedupe(value)

    @field_validator("provider_assertion_ids")
    @classmethod
    def canonicalize_assertion_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(value)))

    @model_validator(mode="after")
    def validate_join_state(self) -> Self:
        if self.status is EvidenceStatus.COMPLETE:
            if not self.source_ref or not self.target_ref:
                raise ValueError("complete relationships require both canonical endpoints")
            if not self.evidence_refs:
                raise ValueError("complete relationships require evidence references")
            if self.source_native_id is None or self.target_native_id is None:
                raise ValueError("complete relationships require exact provider-native evidence anchors")
            if not self.provider_assertion_ids:
                raise ValueError("complete relationships require provider assertion evidence anchors")
            return self
        if not self.reason_codes:
            raise ValueError("incomplete relationships require a reason code")
        if self.status is EvidenceStatus.PARTIAL:
            if not self.source_ref and not self.target_ref:
                raise ValueError("partial relationships require at least one known endpoint")
            if not self.evidence_refs:
                raise ValueError("partial relationships require evidence references")
        return self

    @property
    def asserted(self) -> bool:
        """Only complete joins are eligible to become graph edges."""

        return self.status is EvidenceStatus.COMPLETE and bool(self.source_ref and self.target_ref)


def _relationship_semantic_material(relationship: IdentityRelationship) -> dict[str, object]:
    return {
        "join_method": relationship.join_method.value,
        "provider_assertion_ids": list(relationship.provider_assertion_ids),
        "relationship_type": relationship.relationship_type.value,
        "source_native_id": (relationship.source_native_id.model_dump(mode="json") if relationship.source_native_id is not None else None),
        "source_ref": relationship.source_ref,
        "target_native_id": (relationship.target_native_id.model_dump(mode="json") if relationship.target_native_id is not None else None),
        "target_ref": relationship.target_ref,
    }


def canonical_identity_relationship_id(*, tenant_id: str, relationship: IdentityRelationship) -> str:
    """Return the tenant-scoped deterministic ID for one semantic relationship."""

    material = {"tenant_id": tenant_id, **_relationship_semantic_material(relationship)}
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "join:sha256:" + hashlib.sha256(encoded).hexdigest()


_MEMBER_SOURCES = {
    CanonicalIdentityType.PERSON,
    CanonicalIdentityType.SERVICE_ACCOUNT,
    CanonicalIdentityType.WORKLOAD_IDENTITY,
    CanonicalIdentityType.GROUP,
}
_ASSUME_SOURCES = set(_MEMBER_SOURCES)
_TRUST_TARGETS = {
    CanonicalIdentityType.PERSON,
    CanonicalIdentityType.SERVICE_ACCOUNT,
    CanonicalIdentityType.WORKLOAD_IDENTITY,
    CanonicalIdentityType.ROLE,
}
_OWNER_SOURCES = set(_MEMBER_SOURCES)
_RESOURCE_TYPE = "resource"


class IdentityResourceJoinContract(_StrictIdentityModel):
    """Versioned cross-provider identity/resource catalog and structural joins.

    The generated JSON Schema enforces local shape and status conditions. Its
    cross-record uniqueness, referential, freshness, and evidence-anchor rules
    require this class's executable ``model_validate`` validator.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "$comment": (
                "Cross-record identity, resource, relationship, freshness, and evidence-anchor invariants "
                "require IdentityResourceJoinContract.model_validate; JSON Schema alone is not sufficient."
            )
        }
    )

    schema_version: Literal["identity-resource-joins.v1"] = "identity-resource-joins.v1"
    tenant_id: CanonicalIdentifier
    evaluated_at: datetime
    freshness_max_age_seconds: int = Field(ge=1, le=MAX_IDENTITY_JOIN_FRESHNESS_SECONDS)
    identities: tuple[CanonicalIdentityEntity, ...] = Field(default=(), max_length=10_000)
    resources: tuple[CanonicalResourceReference, ...] = Field(default=(), max_length=10_000)
    relationships: tuple[IdentityRelationship, ...] = Field(default=(), max_length=50_000)
    evidence: tuple[EvidenceProvenance, ...] = Field(default=(), max_length=5_000)
    completeness: EvidenceCompletenessLedger

    @property
    def overall_status(self) -> EvidenceStatus:
        return self.completeness.overall_status

    @field_validator("evaluated_at")
    @classmethod
    def require_aware_evaluation_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluated_at must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        identity_by_id = {item.entity_id: item for item in self.identities}
        resource_by_id = {item.resource_id: item for item in self.resources}
        if len(identity_by_id) != len(self.identities):
            raise ValueError("canonical identity IDs must be unique")
        if len(resource_by_id) != len(self.resources):
            raise ValueError("canonical resource IDs must be unique")
        if set(identity_by_id) & set(resource_by_id):
            raise ValueError("identity and resource canonical IDs must not collide")

        total_native_ids = sum(len(item.native_ids) for item in chain(self.identities, self.resources))
        if total_native_ids > MAX_IDENTITY_JOIN_NATIVE_IDENTIFIERS:
            raise ValueError("contract exceeds the aggregate provider-native identifier budget")

        total_evidence_refs = (
            sum(len(item.evidence_refs) for item in self.identities)
            + sum(len(item.evidence_refs) for item in self.resources)
            + sum(len(item.evidence_refs) for item in self.relationships)
        )
        if total_evidence_refs > MAX_IDENTITY_JOIN_EVIDENCE_REFERENCES:
            raise ValueError("contract exceeds the aggregate evidence-reference budget")

        relationship_ids = {item.relationship_id for item in self.relationships}
        if len(relationship_ids) != len(self.relationships):
            raise ValueError("relationship IDs must be unique")

        native_owner: dict[tuple[IdentitySourceKind, str, str, str, str], str] = {}
        for identity in self.identities:
            for native_id in identity.native_ids:
                key = _native_key(native_id)
                owner = native_owner.setdefault(key, identity.entity_id)
                if owner != identity.entity_id:
                    raise ValueError("one provider-native identity cannot resolve to two canonical entities")

        resource_native_owner: dict[tuple[IdentitySourceKind, str, str, str, str], str] = {}
        for resource in self.resources:
            for native_id in resource.native_ids:
                key = _native_key(native_id)
                owner = resource_native_owner.setdefault(key, resource.resource_id)
                if owner != resource.resource_id:
                    raise ValueError("one provider-native resource cannot resolve to two canonical resources")

        evidence_by_id = {item.evidence_id: item for item in self.evidence}
        if len(evidence_by_id) != len(self.evidence):
            raise ValueError("evidence IDs must be unique")
        referenced_evidence: set[str] = set()
        for identity in self.identities:
            referenced_evidence.update(identity.evidence_refs)
        for resource in self.resources:
            referenced_evidence.update(resource.evidence_refs)
        for relationship in self.relationships:
            referenced_evidence.update(relationship.evidence_refs)
        if missing_evidence := referenced_evidence - set(evidence_by_id):
            sample = sorted(missing_evidence)[:10]
            raise ValueError(f"contract references {len(missing_evidence)} unknown evidence records; sample={sample}")

        for row in chain(self.identities, self.resources):
            if row.status is not EvidenceStatus.COMPLETE:
                continue
            row_evidence = [evidence_by_id[ref] for ref in row.evidence_refs]
            if any(
                item.status is not EvidenceStatus.COMPLETE or item.basis not in {EvidenceBasis.OBSERVED, EvidenceBasis.RUNTIME_OBSERVED}
                for item in row_evidence
            ):
                raise ValueError("complete catalog rows require complete, authoritative evidence")

        endpoint_types: dict[str, CanonicalIdentityType | str] = {
            **{item.entity_id: item.entity_type for item in self.identities},
            **{item.resource_id: _RESOURCE_TYPE for item in self.resources},
        }
        endpoint_native_ids: dict[str, tuple[ProviderNativeId, ...]] = {
            **{item.entity_id: item.native_ids for item in self.identities},
            **{item.resource_id: item.native_ids for item in self.resources},
        }
        semantic_relationships: set[str] = set()
        for relationship in self.relationships:
            for endpoint in (relationship.source_ref, relationship.target_ref):
                if endpoint is not None and endpoint not in endpoint_types:
                    raise ValueError("relationship references an unknown canonical endpoint")
            if (
                relationship.relationship_type is IdentityRelationshipType.MEMBER_OF
                and relationship.source_ref is not None
                and relationship.source_ref == relationship.target_ref
            ):
                raise ValueError("member_of self-loop is not a valid structural relationship")
            if relationship.source_ref and relationship.target_ref:
                self._validate_direction(
                    relationship.relationship_type,
                    endpoint_types[relationship.source_ref],
                    endpoint_types[relationship.target_ref],
                )
            expected_method = _JOIN_METHOD_BY_RELATIONSHIP[relationship.relationship_type]
            if relationship.join_method is not expected_method:
                raise ValueError("join method does not match the structural relationship type")

            semantic_key = json.dumps(
                _relationship_semantic_material(relationship),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            if semantic_key in semantic_relationships:
                raise ValueError("duplicate semantic relationship must be merged into one assertion")
            semantic_relationships.add(semantic_key)

            if relationship.source_ref is not None and relationship.source_native_id is not None:
                if relationship.source_native_id not in endpoint_native_ids[relationship.source_ref]:
                    raise ValueError("source evidence anchor does not match the canonical endpoint")
            if relationship.target_ref is not None and relationship.target_native_id is not None:
                if relationship.target_native_id not in endpoint_native_ids[relationship.target_ref]:
                    raise ValueError("target evidence anchor does not match the canonical endpoint")
            if relationship.asserted:
                join_evidence = [evidence_by_id[ref] for ref in relationship.evidence_refs]
                if any(
                    item.status is not EvidenceStatus.COMPLETE or item.basis not in {EvidenceBasis.OBSERVED, EvidenceBasis.RUNTIME_OBSERVED}
                    for item in join_evidence
                ):
                    raise ValueError("complete relationships require complete, directly observed evidence")
                evidence_anchor_ids = set(chain.from_iterable(item.source_ids for item in join_evidence))
                if not set(relationship.provider_assertion_ids).issubset(evidence_anchor_ids):
                    raise ValueError("complete relationship evidence anchors must match evidence source_ids")
                if any(
                    item.freshness is not None and item.freshness.observed_at is not None and item.freshness.observed_at > self.evaluated_at
                    for item in join_evidence
                ):
                    raise ValueError("complete relationships cannot use future evidence")
                if any(not self._is_fresh_for_decision(item) for item in join_evidence):
                    raise ValueError("complete relationships require fresh evidence under the contract policy")

            expected_relationship_id = canonical_identity_relationship_id(tenant_id=self.tenant_id, relationship=relationship)
            if relationship.relationship_id != expected_relationship_id:
                raise ValueError("relationship ID does not match its deterministic tenant-scoped identity")
        return self

    def _is_fresh_for_decision(self, evidence: EvidenceProvenance) -> bool:
        freshness = evidence.freshness
        if freshness is None or freshness.observed_at is None:
            return False
        expected = EvidenceFreshness.evaluate(
            observed_at=freshness.observed_at,
            evaluated_at=self.evaluated_at,
            max_age_seconds=self.freshness_max_age_seconds,
        )
        return freshness == expected and expected.status is FreshnessStatus.FRESH

    @staticmethod
    def _validate_direction(
        relationship_type: IdentityRelationshipType,
        source_type: CanonicalIdentityType | str,
        target_type: CanonicalIdentityType | str,
    ) -> None:
        valid = False
        if relationship_type is IdentityRelationshipType.MEMBER_OF:
            valid = source_type in _MEMBER_SOURCES and target_type is CanonicalIdentityType.GROUP
        elif relationship_type is IdentityRelationshipType.ASSUMES:
            valid = source_type in _ASSUME_SOURCES and target_type is CanonicalIdentityType.ROLE
        elif relationship_type is IdentityRelationshipType.TRUSTS:
            valid = source_type is CanonicalIdentityType.ROLE and target_type in _TRUST_TARGETS
        elif relationship_type is IdentityRelationshipType.RUNS_AS:
            valid = source_type == _RESOURCE_TYPE and target_type in {
                CanonicalIdentityType.SERVICE_ACCOUNT,
                CanonicalIdentityType.WORKLOAD_IDENTITY,
            }
        elif relationship_type is IdentityRelationshipType.OWNS:
            valid = source_type in _OWNER_SOURCES and target_type == _RESOURCE_TYPE
        if not valid:
            raise ValueError(f"invalid {relationship_type.value} relationship direction")
