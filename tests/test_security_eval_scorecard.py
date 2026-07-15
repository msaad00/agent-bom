"""Tests for the security-eval scorecard artifact."""

from __future__ import annotations

from agent_bom.red_team import _ATTACKS, run_attacks
from agent_bom.security_eval_scorecard import (
    SCHEMA_VERSION,
    build_security_eval_scorecard,
)


def test_scorecard_full_catalog_shape() -> None:
    card = build_security_eval_scorecard()
    assert card["schema_version"] == SCHEMA_VERSION
    # Sits alongside quality evals: it is explicitly a security eval.
    assert card["eval_type"] == "security"
    # Coverage %, FP rate and per-category are the three required facets.
    assert card["coverage_pct"] == 100.0
    assert "false_positive_rate" in card
    assert card["catalog_size"] == len(_ATTACKS)
    assert card["attacks_run"] == len(_ATTACKS)
    assert card["per_category"], "per-category pass/fail must be populated"
    for cat, stats in card["per_category"].items():
        assert {"total", "detected", "passed", "failed", "pass"} <= set(stats)
        assert stats["passed"] + stats["failed"] == stats["total"]
        assert stats["pass"] is (stats["failed"] == 0)


def test_scorecard_is_deterministic() -> None:
    # No timestamps / randomness — the same run yields byte-identical artifacts.
    assert build_security_eval_scorecard() == build_security_eval_scorecard()


def test_coverage_reflects_partial_run() -> None:
    subset = _ATTACKS[:5]
    card = build_security_eval_scorecard(run_attacks(subset))
    assert card["attacks_run"] == 5
    assert card["catalog_size"] == len(_ATTACKS)
    assert card["coverage_pct"] < 100.0
    expected = round(5 / len(_ATTACKS) * 100, 1)
    assert card["coverage_pct"] == expected


def test_false_positive_rate_present_and_numeric() -> None:
    card = build_security_eval_scorecard()
    assert isinstance(card["false_positive_rate"], (int, float))
    assert isinstance(card["false_positives"], int)


def test_scorecard_embedded_in_accuracy_baseline() -> None:
    from agent_bom.accuracy_baseline import build_accuracy_baseline

    baseline = build_accuracy_baseline()
    card = baseline["security_eval_scorecard"]
    assert card["schema_version"] == SCHEMA_VERSION
    assert card["eval_type"] == "security"
