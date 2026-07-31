"""The one derivation of "is this compliance score meaningful".

Six surfaces (REST aggregate, per-framework REST, MCP tool, HTML report,
evidence bundle, Overview cockpit) each grew their own answer to that question.
The guard that held on one was defeated on the other five. These tests pin the
shared primitive they now all route through.
"""

from __future__ import annotations

import pytest

from agent_bom.evidence.scoring import score_compliance


def test_nothing_evaluated_is_no_data_not_a_pass() -> None:
    verdict = score_compliance(passed=0, warned=0, failed=0)
    assert verdict.status == "no_data"
    assert verdict.score == 0.0


def test_detective_passes_alone_are_no_data() -> None:
    """The live P0 shape: 8 controls pass, every one of them detective.

    A detective pass establishes that we scan, not that the estate complies.
    ``passed / evaluated`` is 100% here, and that number is exactly what must
    NOT escape.
    """
    verdict = score_compliance(passed=8, warned=0, failed=0, detective_passes=8)
    assert verdict.status == "no_data"
    assert verdict.score == 0.0
    assert verdict.evaluated == 8
    assert verdict.substantive_evaluated == 0


def test_one_substantive_pass_makes_the_score_real() -> None:
    verdict = score_compliance(passed=9, warned=0, failed=0, detective_passes=8)
    assert verdict.status == "pass"
    assert verdict.score == 100.0
    assert verdict.substantive_evaluated == 1


def test_a_failure_outranks_everything() -> None:
    verdict = score_compliance(passed=8, warned=3, failed=1, detective_passes=8)
    assert verdict.status == "fail"
    assert verdict.score == round(8 / 12 * 100, 1)


def test_a_warning_or_an_unevaluable_error_is_never_a_clean_pass() -> None:
    assert score_compliance(passed=5, warned=1, failed=0).status == "warning"
    # An ERROR is an unevaluable control: it counts toward the denominator
    # (dragging the score down) but is never a pass.
    errored = score_compliance(passed=5, warned=0, failed=0, errored=1)
    assert errored.status == "warning"
    assert errored.score == round(5 / 6 * 100, 1)


def test_no_evidence_overrides_every_other_signal() -> None:
    """Zero completed scans cannot produce a verdict, whatever the counts say."""
    verdict = score_compliance(passed=99, warned=0, failed=0, has_evidence=False)
    assert verdict.status == "no_data"
    assert verdict.score == 0.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"passed": 0, "warned": 0, "failed": 0},
        {"passed": 8, "warned": 0, "failed": 0, "detective_passes": 8},
        {"passed": 3, "warned": 1, "failed": 2, "detective_passes": 3},
        {"passed": 99, "warned": 0, "failed": 0, "has_evidence": False},
        {"passed": 0, "warned": 0, "failed": 0, "errored": 4},
        {"passed": 10, "warned": 0, "failed": 0},
    ],
)
def test_the_invariant_no_data_never_carries_a_score(kwargs: dict) -> None:
    """The property, not the instance: status and score can never disagree."""
    verdict = score_compliance(**kwargs)
    if verdict.status == "no_data":
        assert verdict.score == 0.0
    else:
        assert verdict.substantive_evaluated > 0 or verdict.status in {"fail", "warning"}


def test_detective_passes_can_never_exceed_the_passes_they_came_from() -> None:
    with pytest.raises(ValueError):
        score_compliance(passed=2, warned=0, failed=0, detective_passes=5)
