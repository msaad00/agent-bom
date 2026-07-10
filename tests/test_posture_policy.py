"""Posture scorecard policy — defaults plus adopter overrides."""

from __future__ import annotations

import json

from agent_bom.models import AIBOMReport
from agent_bom.posture import (
    DEFAULT_DIMENSION_WEIGHTS,
    compute_posture_scorecard,
    load_posture_policy,
)


def test_default_policy_weights_sum_to_one() -> None:
    policy = load_posture_policy()
    assert policy.source == "default"
    assert abs(sum(policy.weights.values()) - 1.0) < 1e-6
    assert set(policy.weights) == set(DEFAULT_DIMENSION_WEIGHTS)


def test_env_policy_overrides_weights_and_thresholds(monkeypatch) -> None:
    monkeypatch.setenv(
        "AGENT_BOM_POSTURE_POLICY",
        json.dumps(
            {
                "weights": {
                    "vulnerability_posture": 0.5,
                    "credential_hygiene": 0.1,
                    "supply_chain_quality": 0.1,
                    "compliance_coverage": 0.1,
                    "active_exploitation": 0.1,
                    "configuration_quality": 0.1,
                },
                "grade_thresholds": {"A": 95, "B": 85, "C": 75, "D": 65},
            }
        ),
    )
    policy = load_posture_policy()
    assert policy.source.startswith("env:")
    assert abs(policy.weights["vulnerability_posture"] - 0.5) < 1e-6
    assert policy.grade_thresholds["A"] == 95.0

    scorecard = compute_posture_scorecard(AIBOMReport(agents=[], blast_radii=[]), policy=policy)
    assert scorecard.policy_source.startswith("env:")
    assert scorecard.dimensions["vulnerability_posture"].weight == policy.weights["vulnerability_posture"]


def test_partial_weight_override_keeps_other_defaults() -> None:
    """Adopters can tweak one dimension; remaining defaults stay and renormalize."""
    policy = load_posture_policy(weights={"vulnerability_posture": 0.6})
    assert policy.source == "explicit"
    assert policy.weights["vulnerability_posture"] > DEFAULT_DIMENSION_WEIGHTS["vulnerability_posture"]
    assert abs(sum(policy.weights.values()) - 1.0) < 1e-6

    scorecard = compute_posture_scorecard(
        AIBOMReport(agents=[], blast_radii=[]),
        weights={"vulnerability_posture": 0.6},
    )
    assert scorecard.policy_source == "explicit"
