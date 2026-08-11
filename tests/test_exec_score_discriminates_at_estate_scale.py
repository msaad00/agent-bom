"""The exec grade must move when the estate improves.

`exec_score.py` documents its diminishing-returns curve as existing

    "so the grade discriminates across the full estate size instead of
     saturating"

and claims it "keeps assigning *distinct* failing scores to a 20-critical vs a
2000-critical estate (both F, but distinguishable)".

It saturates. `score = 100 x scale / (scale + pressure)` with a **constant**
`scale = 70`, against a `pressure` that grows linearly with estate size:

    demo estate pressure ~= 15,292  ->  0.46%  -> displays "0%"
    the same estate halved          ->  0.91%  -> displays "0%"
    a 90% reduction                 ->  4.38%  -> displays "4%"

So the first number on the first screen of the leadership view is pinned at
zero on any real estate, and eliminating **half** of everything moves it by
under one point. The scores are distinct in the arithmetic and identical to a
reader, which is the only place it matters. `scale = 70` is calibrated to the
3-finding anchor in the docstring, not to an estate of thousands.

The curve now compresses pressure logarithmically before the same
diminishing-returns mapping, so the grade responds to *orders of magnitude* of
risk rather than to raw counts. Three invariants the module guarantees are
preserved deliberately, and asserted here:

* a genuinely clean estate is still exactly 100 / grade A;
* the score is still monotonic — more findings never raise it;
* the documented anchor (2 critical + 1 high) still grades C.

What this does **not** do is let a large failing estate score well. Thousands of
open criticals remain an F; they simply stop being an *unreadable* F.
"""

from __future__ import annotations

import pytest

from agent_bom.exec_score import compute_exec_score


def score_for(**severity: int) -> float:
    return float(compute_exec_score(severity=severity)["score"])


def demo_estate_score(divisor: int = 1) -> float:
    """The measured demo estate, optionally reduced by ``divisor``."""
    return score_for(
        critical=440 // divisor,
        high=1337 // divisor,
        medium=628 // divisor,
        low=257 // divisor,
        unrated=69 // divisor,
    )


def test_a_clean_scanned_estate_is_still_a_perfect_hundred() -> None:
    """Zero findings WITH evidence. Zero findings and no evidence is `N/A`
    ("awaiting evidence"), which is a deliberate separate state — a grade must
    not be invented for an estate nobody has looked at."""
    result = compute_exec_score(
        severity={"critical": 0, "high": 0, "medium": 0, "low": 0, "unrated": 0},
        floor_score=100.0,
    )
    assert result["score"] == 100
    assert result["grade"] == "A"


def test_an_ungraded_estate_still_reports_no_evidence() -> None:
    result = compute_exec_score(severity={"critical": 0, "high": 0})
    assert result["grade"] == "N/A"


def test_the_documented_anchor_still_grades_c() -> None:
    """The docstring's own calibration point: 2 critical + 1 high."""
    result = compute_exec_score(severity={"critical": 2, "high": 1})
    assert result["grade"] == "C", result


def test_the_score_is_still_monotonic() -> None:
    """More findings may only ever lower the grade."""
    # From 1: zero findings is the separate `N/A` state, not a score.
    scores = [score_for(critical=n) for n in (1, 5, 50, 500, 5000)]
    assert scores == sorted(scores, reverse=True), scores
    assert len(set(scores)) == len(scores), f"two different estates scored identically: {scores}"


def test_a_real_estate_does_not_display_as_zero() -> None:
    """The defect: the leadership headline pinned at 0% on any real estate."""
    score = demo_estate_score()
    assert round(score) > 0, f"the demo estate still displays as {round(score)}%"


def test_halving_the_estate_visibly_moves_the_grade() -> None:
    """Eliminating half of everything used to move the dial from 0% to 1%."""
    full = demo_estate_score()
    halved = demo_estate_score(divisor=2)
    assert halved > full
    assert round(halved) - round(full) >= 1, f"halving the estate moved {full:.2f}% -> {halved:.2f}%"


def test_a_large_reduction_is_clearly_visible() -> None:
    full = demo_estate_score()
    reduced = demo_estate_score(divisor=10)
    assert reduced - full >= 5, f"a 90% reduction moved only {full:.2f}% -> {reduced:.2f}%"


def test_a_large_failing_estate_is_still_failing() -> None:
    """Legibility must not become leniency."""
    result = compute_exec_score(severity={"critical": 440, "high": 1337, "medium": 628, "low": 257})
    assert result["grade"] == "F", result
    assert result["score"] < 60


def test_two_failing_estates_of_different_size_are_distinguishable_to_a_reader() -> None:
    """Distinct in the arithmetic was never the point — distinct on screen is."""
    small = score_for(critical=20)
    large = score_for(critical=2000)
    assert round(small) != round(large), f"{small:.2f}% vs {large:.2f}% both render the same"


def test_the_floor_still_wins_when_it_is_worse() -> None:
    """A failing scan scorecard can never be laundered upward."""
    result = compute_exec_score(severity={"critical": 0, "high": 0}, floor_score=12.0)
    assert result["score"] <= 12.0, result


@pytest.mark.parametrize("weight_scale", [0.5, 2.0])
def test_adopters_can_still_steepen_or_soften_the_curve(weight_scale: float) -> None:
    """The documented tuning path must survive the change."""
    from agent_bom.exec_score import DEFAULT_EXEC_SCORE_WEIGHTS, ExecScoreConfig, load_exec_score_config

    base = load_exec_score_config()
    tuned = ExecScoreConfig(
        weights={k: v * weight_scale for k, v in DEFAULT_EXEC_SCORE_WEIGHTS.items()},
        grade_thresholds=base.grade_thresholds,
        display_format=base.display_format,
    )
    heavier = compute_exec_score(severity={"critical": 50}, config=tuned)["score"]
    default = compute_exec_score(severity={"critical": 50})["score"]
    if weight_scale > 1:
        assert heavier < default
    else:
        assert heavier > default
