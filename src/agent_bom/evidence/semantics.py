"""Canonical truth dimensions for security evidence.

These types deliberately keep evidence basis, collection completeness,
freshness, reachability, exploitability, likelihood, impact, and risk
independent.  A missing assessment is represented as unavailable rather than
as a zero or a negative observation.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

ReasonCode = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.:-]{0,63}$")]
Identifier = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[^\s]+$")]
ComponentName = Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9_.:-]*$")]
BoundedLabel = Annotated[str, Field(min_length=1, max_length=100)]
RiskFactor = Literal["exposure", "reachability", "exploitability", "likelihood", "impact"]


class EvidenceBasis(StrEnum):
    """How an evidence record was established."""

    OBSERVED = "observed"
    RUNTIME_OBSERVED = "runtime_observed"
    INFERRED = "inferred"
    MODELED = "modeled"


class EvidenceStatus(StrEnum):
    """Whether a bounded evidence-producing operation completed."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class FreshnessStatus(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


class EvidenceStage(StrEnum):
    COLLECTION = "collection"
    NORMALIZATION = "normalization"
    CATALOG_LOOKUP = "catalog_lookup"
    PERSISTENCE = "persistence"
    GRAPH_JOIN = "graph_join"
    ANALYSIS = "analysis"


class ReachabilityVerdict(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNKNOWN = "unknown"
    UNLIKELY = "unlikely"


class ExploitabilityVerdict(StrEnum):
    EXPLOITABLE = "exploitable"
    NOT_EXPLOITABLE = "not_exploitable"
    UNKNOWN = "unknown"


class _StrictEvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


def _require_aware(value: datetime | None, *, field_name: str) -> None:
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise ValueError(f"{field_name} must include a timezone")


def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


class EvidenceFreshness(_StrictEvidenceModel):
    """Freshness evaluated at a caller-supplied decision time."""

    status: FreshnessStatus
    observed_at: datetime | None = None
    valid_until: datetime | None = None
    evaluated_at: datetime
    max_age_seconds: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_timestamps(self) -> Self:
        _require_aware(self.observed_at, field_name="observed_at")
        _require_aware(self.valid_until, field_name="valid_until")
        _require_aware(self.evaluated_at, field_name="evaluated_at")
        if self.observed_at is not None and self.valid_until is not None and self.valid_until < self.observed_at:
            raise ValueError("valid_until cannot precede observed_at")
        if self.valid_until is not None:
            expected = FreshnessStatus.FRESH if self.evaluated_at <= self.valid_until else FreshnessStatus.STALE
            if self.status is not expected:
                raise ValueError("freshness status does not match the explicit validity window")
        return self

    @classmethod
    def evaluate(
        cls,
        *,
        observed_at: datetime,
        evaluated_at: datetime,
        max_age_seconds: int,
    ) -> EvidenceFreshness:
        """Evaluate freshness without consulting the process clock."""

        if observed_at.tzinfo is None or observed_at.utcoffset() is None or evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            return cls(
                status=FreshnessStatus.UNKNOWN,
                observed_at=observed_at,
                evaluated_at=evaluated_at,
                max_age_seconds=max_age_seconds,
            )
        valid_until = observed_at + timedelta(seconds=max_age_seconds)
        status = FreshnessStatus.FRESH if evaluated_at <= valid_until else FreshnessStatus.STALE
        return cls(
            status=status,
            observed_at=observed_at,
            valid_until=valid_until,
            evaluated_at=evaluated_at,
            max_age_seconds=max_age_seconds,
        )


class EvidenceProvenance(_StrictEvidenceModel):
    """A bounded, referenceable evidence receipt."""

    schema_version: Literal["evidence-provenance.v1"] = "evidence-provenance.v1"
    evidence_id: Identifier
    basis: EvidenceBasis | None = None
    status: EvidenceStatus
    source: ComponentName
    source_ids: tuple[Identifier, ...] = Field(default=(), max_length=50)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    freshness: EvidenceFreshness | None = None
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=20)

    @field_validator("source_ids", "reason_codes")
    @classmethod
    def dedupe_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _dedupe(value)

    @model_validator(mode="after")
    def validate_availability(self) -> Self:
        if self.status in {EvidenceStatus.UNAVAILABLE, EvidenceStatus.FAILED} and not self.reason_codes:
            raise ValueError("unavailable or failed evidence requires a reason code")
        return self


class CompletenessEntry(_StrictEvidenceModel):
    """Completeness of one component at one processing stage."""

    stage: EvidenceStage
    component: ComponentName
    status: EvidenceStatus
    requested: bool = True
    affects_coverage: bool = True
    returned_count: int | None = Field(default=None, ge=0)
    expected_count: int | None = Field(default=None, ge=0)
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=20)

    @field_validator("reason_codes")
    @classmethod
    def dedupe_reasons(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _dedupe(value)

    @model_validator(mode="after")
    def validate_counts_and_reasons(self) -> Self:
        if self.expected_count is not None and self.returned_count is not None and self.returned_count > self.expected_count:
            raise ValueError("returned_count cannot exceed expected_count")
        if self.status in {EvidenceStatus.PARTIAL, EvidenceStatus.UNAVAILABLE, EvidenceStatus.FAILED} and not self.reason_codes:
            raise ValueError("incomplete evidence requires a reason code")
        return self


class EvidenceCompletenessLedger(_StrictEvidenceModel):
    """Deterministic aggregation of bounded component completeness."""

    schema_version: Literal["evidence-completeness.v1"] = "evidence-completeness.v1"
    entries: tuple[CompletenessEntry, ...] = Field(default=(), max_length=500)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def overall_status(self) -> EvidenceStatus:
        relevant = tuple(entry for entry in self.entries if entry.requested and entry.affects_coverage)
        if not self.entries:
            return EvidenceStatus.UNAVAILABLE
        if not relevant:
            return EvidenceStatus.UNAVAILABLE
        if any(entry.status is EvidenceStatus.FAILED for entry in relevant):
            return EvidenceStatus.FAILED
        if any(entry.status is not EvidenceStatus.COMPLETE for entry in relevant):
            return EvidenceStatus.PARTIAL
        return EvidenceStatus.COMPLETE


class _Dimension(_StrictEvidenceModel):
    status: EvidenceStatus
    evidence_refs: tuple[Identifier, ...] = Field(default=(), max_length=100)
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=20)

    @field_validator("evidence_refs", "reason_codes")
    @classmethod
    def dedupe_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _dedupe(value)

    def _validate_common(self, *, has_facts: bool) -> None:
        if self.status in {EvidenceStatus.UNAVAILABLE, EvidenceStatus.FAILED}:
            if has_facts:
                raise ValueError("unavailable or failed dimensions cannot carry observed facts")
            if not self.reason_codes:
                raise ValueError("unavailable or failed dimensions require a reason code")
            return
        if self.status is EvidenceStatus.COMPLETE and not has_facts:
            raise ValueError("complete dimensions require an explicit assessed fact")
        if self.status is EvidenceStatus.PARTIAL and not self.reason_codes:
            raise ValueError("partial dimensions require a reason code")
        if has_facts and not self.evidence_refs:
            raise ValueError("observed dimension facts require evidence references")


class ExposureAssessment(_Dimension):
    internet_exposed: bool | None = None
    entry_point_ids: tuple[Identifier, ...] = Field(default=(), max_length=100)
    credential_ids: tuple[Identifier, ...] = Field(default=(), max_length=100)
    tool_ids: tuple[Identifier, ...] = Field(default=(), max_length=100)

    @model_validator(mode="after")
    def validate_dimension(self) -> Self:
        self._validate_common(
            has_facts=self.internet_exposed is not None or bool(self.entry_point_ids) or bool(self.credential_ids) or bool(self.tool_ids)
        )
        return self


class ReachabilityDimension(_Dimension):
    verdict: ReachabilityVerdict | None = None
    min_hops: int | None = Field(default=None, ge=0)
    path_ids: tuple[Identifier, ...] = Field(default=(), max_length=100)

    @model_validator(mode="after")
    def validate_dimension(self) -> Self:
        self._validate_common(has_facts=self.verdict is not None or self.min_hops is not None or bool(self.path_ids))
        return self


class ExploitabilityDimension(_Dimension):
    verdict: ExploitabilityVerdict | None = None
    attack_vector: BoundedLabel | None = None
    attack_complexity: BoundedLabel | None = None
    privileges_required: BoundedLabel | None = None
    user_interaction: BoundedLabel | None = None

    @model_validator(mode="after")
    def validate_dimension(self) -> Self:
        facts = (self.verdict, self.attack_vector, self.attack_complexity, self.privileges_required, self.user_interaction)
        self._validate_common(has_facts=any(value is not None for value in facts))
        return self


class LikelihoodDimension(_Dimension):
    probability: float | None = Field(default=None, ge=0.0, le=1.0)
    method: BoundedLabel | None = None
    model_version: BoundedLabel | None = None
    as_of: datetime | None = None
    known_exploited: bool | None = None

    @model_validator(mode="after")
    def validate_dimension(self) -> Self:
        _require_aware(self.as_of, field_name="as_of")
        facts = (self.probability, self.method, self.model_version, self.as_of, self.known_exploited)
        self._validate_common(has_facts=any(value is not None for value in facts))
        if self.probability is not None and (self.method is None or self.as_of is None):
            raise ValueError("probability requires a named method and as_of timestamp")
        return self


class ImpactDimension(_Dimension):
    technical_categories: tuple[BoundedLabel, ...] = Field(default=(), max_length=20)
    business_criticality: BoundedLabel | None = None
    data_sensitivity: BoundedLabel | None = None
    affected_asset_count: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_dimension(self) -> Self:
        facts = (
            bool(self.technical_categories),
            self.business_criticality is not None,
            self.data_sensitivity is not None,
            self.affected_asset_count is not None,
        )
        self._validate_common(has_facts=any(facts))
        return self


class RiskDimension(_Dimension):
    score: float | None = Field(default=None, ge=0.0, le=10.0)
    method: BoundedLabel | None = None
    method_version: BoundedLabel | None = None
    factor_dimensions: tuple[RiskFactor, ...] = Field(default=(), max_length=5)

    @model_validator(mode="after")
    def validate_dimension(self) -> Self:
        facts = (self.score, self.method, self.method_version, bool(self.factor_dimensions))
        self._validate_common(has_facts=any(value is not None and value is not False for value in facts))
        if self.score is not None and (self.method is None or self.method_version is None or not self.factor_dimensions):
            raise ValueError("risk score requires a versioned method and explicit factor dimensions")
        return self


class SecurityDimensions(_StrictEvidenceModel):
    """Independent security facts plus their provenance and completeness."""

    schema_version: Literal["security-dimensions.v1"] = "security-dimensions.v1"
    exposure: ExposureAssessment
    reachability: ReachabilityDimension
    exploitability: ExploitabilityDimension
    likelihood: LikelihoodDimension
    impact: ImpactDimension
    risk: RiskDimension
    evidence: tuple[EvidenceProvenance, ...] = Field(default=(), max_length=500)
    completeness: EvidenceCompletenessLedger

    @model_validator(mode="after")
    def validate_evidence_references(self) -> Self:
        known_ids = {item.evidence_id for item in self.evidence}
        dimensions = (self.exposure, self.reachability, self.exploitability, self.likelihood, self.impact, self.risk)
        referenced = {reference for dimension in dimensions for reference in dimension.evidence_refs}
        missing = referenced - known_ids
        if missing:
            raise ValueError("dimension references evidence outside this contract")
        return self
