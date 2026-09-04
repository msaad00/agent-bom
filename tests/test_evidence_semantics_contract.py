"""Canonical evidence semantics keep truth dimensions independent."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agent_bom.evidence.semantics import (
    CompletenessEntry,
    EvidenceBasis,
    EvidenceCompletenessLedger,
    EvidenceFreshness,
    EvidenceProvenance,
    EvidenceStage,
    EvidenceStatus,
    ExploitabilityDimension,
    ExploitabilityVerdict,
    ExposureAssessment,
    FreshnessStatus,
    ImpactDimension,
    LikelihoodDimension,
    ReachabilityDimension,
    ReachabilityVerdict,
    RiskDimension,
    SecurityDimensions,
)

NOW = datetime(2026, 9, 3, 20, 0, tzinfo=timezone.utc)


def _evidence(*, status: EvidenceStatus = EvidenceStatus.COMPLETE) -> EvidenceProvenance:
    return EvidenceProvenance(
        evidence_id="evidence:scanner:1",
        basis=EvidenceBasis.RUNTIME_OBSERVED,
        status=status,
        source="runtime-gateway",
        source_ids=["snapshot:1"],
        confidence=0.95,
        freshness=EvidenceFreshness.evaluate(
            observed_at=NOW - timedelta(minutes=5),
            evaluated_at=NOW,
            max_age_seconds=3600,
        ),
        reason_codes=[] if status is EvidenceStatus.COMPLETE else ["source_partial"],
    )


def test_basis_and_coverage_status_are_orthogonal() -> None:
    evidence = _evidence(status=EvidenceStatus.PARTIAL)

    assert evidence.basis is EvidenceBasis.RUNTIME_OBSERVED
    assert evidence.status is EvidenceStatus.PARTIAL
    assert evidence.freshness.status is FreshnessStatus.FRESH


def test_freshness_is_evaluated_at_an_explicit_decision_time() -> None:
    observed = NOW - timedelta(hours=2)
    freshness = EvidenceFreshness.evaluate(
        observed_at=observed,
        evaluated_at=NOW,
        max_age_seconds=3600,
    )

    assert freshness.status is FreshnessStatus.STALE
    assert freshness.valid_until == observed + timedelta(hours=1)


def test_freshness_rejects_naive_timestamps() -> None:
    with pytest.raises(ValidationError):
        EvidenceFreshness.evaluate(
            observed_at=datetime(2026, 9, 3, 18, 0),
            evaluated_at=NOW,
            max_age_seconds=3600,
        )


def test_unknown_dimensions_cannot_smuggle_zero_as_observed_fact() -> None:
    with pytest.raises(ValidationError):
        RiskDimension(status=EvidenceStatus.UNAVAILABLE, score=0.0, reason_codes=["not_evaluated"])

    risk = RiskDimension(status=EvidenceStatus.UNAVAILABLE, reason_codes=["not_evaluated"])
    assert risk.score is None


def test_complete_and_partial_dimensions_require_explicit_facts_or_reasons() -> None:
    with pytest.raises(ValidationError):
        ReachabilityDimension(status=EvidenceStatus.COMPLETE)
    with pytest.raises(ValidationError):
        ReachabilityDimension(status=EvidenceStatus.PARTIAL)

    partial = ReachabilityDimension(status=EvidenceStatus.PARTIAL, reason_codes=["path_budget_exceeded"])
    assert partial.verdict is None


def test_security_dimensions_do_not_derive_one_dimension_from_another() -> None:
    evidence = _evidence()
    dimensions = SecurityDimensions(
        exposure=ExposureAssessment(
            status=EvidenceStatus.COMPLETE,
            internet_exposed=True,
            entry_point_ids=["service:public"],
            evidence_refs=[evidence.evidence_id],
        ),
        reachability=ReachabilityDimension(
            status=EvidenceStatus.COMPLETE,
            verdict=ReachabilityVerdict.CONFIRMED,
            min_hops=3,
            path_ids=["path:1"],
            evidence_refs=[evidence.evidence_id],
        ),
        exploitability=ExploitabilityDimension(
            status=EvidenceStatus.UNAVAILABLE,
            reason_codes=["symbol_analysis_not_run"],
        ),
        likelihood=LikelihoodDimension(
            status=EvidenceStatus.UNAVAILABLE,
            reason_codes=["epss_unavailable"],
        ),
        impact=ImpactDimension(
            status=EvidenceStatus.PARTIAL,
            technical_categories=["data-access"],
            affected_asset_count=1,
            evidence_refs=[evidence.evidence_id],
            reason_codes=["business_context_unavailable"],
        ),
        risk=RiskDimension(
            status=EvidenceStatus.UNAVAILABLE,
            reason_codes=["risk_model_not_run"],
        ),
        evidence=[evidence],
        completeness=EvidenceCompletenessLedger(
            entries=[
                CompletenessEntry(
                    stage=EvidenceStage.ANALYSIS,
                    component="reachability",
                    status=EvidenceStatus.COMPLETE,
                )
            ]
        ),
    )

    assert dimensions.reachability.verdict is ReachabilityVerdict.CONFIRMED
    assert dimensions.exploitability.verdict is None
    assert dimensions.likelihood.probability is None
    assert dimensions.risk.score is None


def test_likelihood_and_risk_use_distinct_scales_and_methods() -> None:
    evidence = _evidence()
    likelihood = LikelihoodDimension(
        status=EvidenceStatus.COMPLETE,
        probability=0.91,
        method="epss",
        model_version="2026.08",
        as_of=NOW,
        known_exploited=True,
        evidence_refs=[evidence.evidence_id],
    )
    risk = RiskDimension(
        status=EvidenceStatus.COMPLETE,
        score=8.4,
        method="agent-bom-contextual-risk",
        method_version="1",
        factor_dimensions=["exposure", "reachability", "likelihood", "impact"],
        evidence_refs=[evidence.evidence_id],
    )

    assert likelihood.probability == 0.91
    assert risk.score == 8.4
    with pytest.raises(ValidationError):
        LikelihoodDimension(
            status=EvidenceStatus.COMPLETE,
            probability=8.4,
            method="risk-score-copy",
            as_of=NOW,
            evidence_refs=[evidence.evidence_id],
        )


def test_exploitability_is_categorical_not_a_reused_risk_number() -> None:
    evidence = _evidence()
    exploitability = ExploitabilityDimension(
        status=EvidenceStatus.COMPLETE,
        verdict=ExploitabilityVerdict.EXPLOITABLE,
        attack_vector="network",
        evidence_refs=[evidence.evidence_id],
    )

    assert exploitability.verdict is ExploitabilityVerdict.EXPLOITABLE
    assert "score" not in exploitability.model_dump()


def test_risk_requires_versioned_method_and_nonrecursive_factors() -> None:
    with pytest.raises(ValidationError):
        RiskDimension(status=EvidenceStatus.COMPLETE, score=7.0, evidence_refs=["evidence:1"])
    with pytest.raises(ValidationError):
        RiskDimension(
            status=EvidenceStatus.COMPLETE,
            score=7.0,
            method="model",
            method_version="1",
            factor_dimensions=["risk"],
            evidence_refs=["evidence:1"],
        )


def test_completeness_ledger_is_fail_closed_and_deterministic() -> None:
    complete = CompletenessEntry(
        stage=EvidenceStage.COLLECTION,
        component="inventory",
        status=EvidenceStatus.COMPLETE,
        returned_count=3,
        expected_count=3,
    )
    partial = CompletenessEntry(
        stage=EvidenceStage.GRAPH_JOIN,
        component="finding-asset-join",
        status=EvidenceStatus.UNAVAILABLE,
        reason_codes=["authoritative_id_missing"],
    )
    failed = CompletenessEntry(
        stage=EvidenceStage.PERSISTENCE,
        component="graph-store",
        status=EvidenceStatus.FAILED,
        reason_codes=["write_failed"],
    )

    assert EvidenceCompletenessLedger(entries=[]).overall_status is EvidenceStatus.UNAVAILABLE
    assert EvidenceCompletenessLedger(entries=[complete]).overall_status is EvidenceStatus.COMPLETE
    assert EvidenceCompletenessLedger(entries=[complete, partial]).overall_status is EvidenceStatus.PARTIAL
    assert EvidenceCompletenessLedger(entries=[complete, failed]).overall_status is EvidenceStatus.FAILED

    not_requested = CompletenessEntry(
        stage=EvidenceStage.COLLECTION,
        component="optional-source",
        status=EvidenceStatus.UNAVAILABLE,
        requested=False,
        affects_coverage=False,
        reason_codes=["skipped"],
    )
    assert EvidenceCompletenessLedger(entries=[not_requested]).overall_status is EvidenceStatus.UNAVAILABLE


def test_models_reject_unknown_fields_and_unbounded_reason_text() -> None:
    with pytest.raises(ValidationError):
        CompletenessEntry.model_validate(
            {
                "stage": "collection",
                "component": "inventory",
                "status": "complete",
                "surprise": "field",
            }
        )
    with pytest.raises(ValidationError):
        CompletenessEntry(
            stage=EvidenceStage.COLLECTION,
            component="inventory",
            status=EvidenceStatus.PARTIAL,
            reason_codes=["contains spaces and potentially arbitrary diagnostic text"],
        )


def test_api_models_publish_standalone_contract_wrappers() -> None:
    from agent_bom.api.models import EvidenceCompletenessLedger as PublicLedger
    from agent_bom.api.models import SecurityDimensions as PublicDimensions

    assert issubclass(PublicLedger, EvidenceCompletenessLedger)
    assert issubclass(PublicDimensions, SecurityDimensions)
    assert PublicLedger.model_json_schema()["title"] == "EvidenceCompletenessLedger"
    assert PublicDimensions.model_json_schema()["title"] == "SecurityDimensions"
