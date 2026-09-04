"""Provider-neutral identity and resource join contract.

The contract is intentionally additive: collectors can normalize authoritative
identity/resource references without changing the existing graph builders. It
does not infer aliases or permissions. Only complete, directly observed
structural relationships are asserted; partial and unavailable attempts remain
explicit non-edges with bounded reason codes.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_bom.evidence.semantics import (
    ComponentName,
    EvidenceBasis,
    EvidenceCompletenessLedger,
    EvidenceProvenance,
    EvidenceStatus,
    ReasonCode,
)

CanonicalIdentifier = Annotated[str, Field(min_length=1, max_length=500, pattern=r"^[^\s]+$")]
NativeIdentifier = Annotated[str, Field(min_length=1, max_length=2048, pattern=r"^[^\s]+$")]
DisplayName = Annotated[str, Field(min_length=1, max_length=300)]


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


class _StrictIdentityModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


class ProviderNativeId(_StrictIdentityModel):
    """One exact provider identifier retained for deterministic correlation."""

    source: IdentitySourceKind
    provider: ComponentName
    id_type: ComponentName
    value: NativeIdentifier
    account: NativeIdentifier | None = None


class _ObservedCatalogReference(_StrictIdentityModel):
    """Shared completeness and provenance rules for normalized catalog rows."""

    display_name: DisplayName
    native_ids: tuple[ProviderNativeId, ...] = Field(min_length=1, max_length=20)
    status: EvidenceStatus = EvidenceStatus.COMPLETE
    evidence_refs: tuple[CanonicalIdentifier, ...] = Field(min_length=1, max_length=50)
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=20)

    @field_validator("native_ids")
    @classmethod
    def unique_native_ids(cls, value: tuple[ProviderNativeId, ...]) -> tuple[ProviderNativeId, ...]:
        keys = {(item.source, item.provider, item.id_type, item.value) for item in value}
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


class IdentityRelationship(_StrictIdentityModel):
    """One structural join assertion or an explicit incomplete join attempt."""

    relationship_id: CanonicalIdentifier
    relationship_type: IdentityRelationshipType
    source_ref: CanonicalIdentifier | None = None
    target_ref: CanonicalIdentifier | None = None
    status: EvidenceStatus
    evidence_refs: tuple[CanonicalIdentifier, ...] = Field(default=(), max_length=50)
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=20)

    @field_validator("evidence_refs", "reason_codes")
    @classmethod
    def dedupe_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _dedupe(value)

    @model_validator(mode="after")
    def validate_join_state(self) -> Self:
        if self.status is EvidenceStatus.COMPLETE:
            if not self.source_ref or not self.target_ref:
                raise ValueError("complete relationships require both canonical endpoints")
            if not self.evidence_refs:
                raise ValueError("complete relationships require evidence references")
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
    """Versioned cross-provider identity/resource catalog and structural joins."""

    schema_version: Literal["identity-resource-joins.v1"] = "identity-resource-joins.v1"
    tenant_id: CanonicalIdentifier
    identities: tuple[CanonicalIdentityEntity, ...] = Field(default=(), max_length=10_000)
    resources: tuple[CanonicalResourceReference, ...] = Field(default=(), max_length=10_000)
    relationships: tuple[IdentityRelationship, ...] = Field(default=(), max_length=50_000)
    evidence: tuple[EvidenceProvenance, ...] = Field(default=(), max_length=5_000)
    completeness: EvidenceCompletenessLedger

    @property
    def overall_status(self) -> EvidenceStatus:
        return self.completeness.overall_status

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

        relationship_ids = {item.relationship_id for item in self.relationships}
        if len(relationship_ids) != len(self.relationships):
            raise ValueError("relationship IDs must be unique")

        native_owner: dict[tuple[IdentitySourceKind, str, str, str], str] = {}
        for identity in self.identities:
            for native_id in identity.native_ids:
                key = (native_id.source, native_id.provider, native_id.id_type, native_id.value)
                owner = native_owner.setdefault(key, identity.entity_id)
                if owner != identity.entity_id:
                    raise ValueError("one provider-native identity cannot resolve to two canonical entities")

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
            raise ValueError(f"contract references unknown evidence: {sorted(missing_evidence)}")

        endpoint_types: dict[str, CanonicalIdentityType | str] = {
            **{item.entity_id: item.entity_type for item in self.identities},
            **{item.resource_id: _RESOURCE_TYPE for item in self.resources},
        }
        for relationship in self.relationships:
            for endpoint in (relationship.source_ref, relationship.target_ref):
                if endpoint is not None and endpoint not in endpoint_types:
                    raise ValueError("relationship references an unknown canonical endpoint")
            if relationship.source_ref and relationship.target_ref:
                self._validate_direction(
                    relationship.relationship_type,
                    endpoint_types[relationship.source_ref],
                    endpoint_types[relationship.target_ref],
                )
            if relationship.asserted:
                join_evidence = [evidence_by_id[ref] for ref in relationship.evidence_refs]
                if any(
                    item.status is not EvidenceStatus.COMPLETE or item.basis not in {EvidenceBasis.OBSERVED, EvidenceBasis.RUNTIME_OBSERVED}
                    for item in join_evidence
                ):
                    raise ValueError("complete relationships require complete, directly observed evidence")
        return self

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
