"""Bias / Toxicity / Hallucination response detectors (Series B PR2)."""

import pytest

from agent_bom.runtime.detectors import (
    BiasTriggerDetector,
    HallucinationDetector,
    ToxicityDetector,
)


@pytest.mark.parametrize(
    "detector_cls, flagged, clean",
    [
        (
            BiasTriggerDetector,
            ["All immigrants are inherently dishonest.", "You shouldn't hire her because she is a woman."],
            ["Different teams bring different strengths.", "Immigration policy is complex."],
        ),
        (
            ToxicityDetector,
            ["You are a worthless idiot.", "I will hurt you if you don't comply.", "kill yourself"],
            ["I disagree with that approach.", "This code could be cleaner."],
        ),
        (
            HallucinationDetector,
            [
                "I fabricated this reference to support the point.",
                "According to a study by [citation needed], it is safe.",
            ],
            ["According to RFC 9110, the method is idempotent.", "See the docs for details."],
        ),
    ],
)
def test_detector_flags_pattern_and_passes_clean(detector_cls, flagged, clean):
    det = detector_cls()
    for text in flagged:
        assert det.check("llm_output", text), f"{detector_cls.__name__} missed: {text!r}"
    for text in clean:
        assert det.check("llm_output", text) == [], f"{detector_cls.__name__} false-positive: {text!r}"


def test_red_team_includes_new_categories():
    from agent_bom.red_team import run_red_team

    report = run_red_team()
    cats = report["by_category"]
    for cat in ("bias", "toxicity", "hallucination"):
        assert cat in cats and cats[cat]["total"] >= 2
    # The new attacks are detected by the wired detectors (coverage, not misses).
    for cat in ("bias", "toxicity", "hallucination"):
        assert cats[cat]["detected"] == cats[cat]["total"], (cat, cats[cat])


def test_detectors_wired_into_protection_engine():
    from agent_bom.runtime.protection import ProtectionEngine

    engine = ProtectionEngine()
    status = engine.status()
    for name in ("BiasTriggerDetector", "ToxicityDetector", "HallucinationDetector"):
        assert name in status["detectors"]
