"""Tests for proxy detector telemetry and sensitivity configuration."""

from __future__ import annotations

from agent_bom.runtime.detectors import (
    DetectorMetrics,
    all_detector_metrics,
    configure_detector_sensitivity,
    get_detector_metrics,
    get_detector_sensitivity,
    is_detector_enabled,
    reset_detector_metrics,
)


def setup_function():
    reset_detector_metrics()


def test_metrics_default_zero():
    m = DetectorMetrics()
    assert m.fires == 0
    assert m.suppressed == 0
    assert m.false_positives == 0
    assert m.false_positive_rate == 0.0


def test_record_fire():
    m = get_detector_metrics("ArgumentAnalyzer")
    m.record_fire()
    m.record_fire()
    assert m.fires == 2


def test_record_suppression():
    m = get_detector_metrics("RateLimitTracker")
    m.record_suppression()
    assert m.suppressed == 1


def test_false_positive_rate():
    m = DetectorMetrics()
    m.fires = 10
    m.false_positives = 2
    assert m.false_positive_rate == 0.2


def test_false_positive_rate_zero_fires():
    m = DetectorMetrics()
    assert m.false_positive_rate == 0.0


def test_all_detector_metrics():
    get_detector_metrics("A").record_fire()
    get_detector_metrics("B").record_fire()
    get_detector_metrics("B").record_fire()
    result = all_detector_metrics()
    assert result["A"]["fires"] == 1
    assert result["B"]["fires"] == 2


def test_to_dict():
    m = DetectorMetrics(fires=5, suppressed=1, false_positives=1)
    d = m.to_dict()
    assert d["fires"] == 5
    assert d["false_positive_rate"] == 0.2


def test_default_sensitivity_is_high():
    assert get_detector_sensitivity("UnknownDetector") == "high"


def test_configure_sensitivity():
    configure_detector_sensitivity(
        {
            "ArgumentAnalyzer": "low",
            "RateLimitTracker": "off",
        }
    )
    assert get_detector_sensitivity("ArgumentAnalyzer") == "low"
    assert get_detector_sensitivity("RateLimitTracker") == "off"
    assert is_detector_enabled("ArgumentAnalyzer")
    assert not is_detector_enabled("RateLimitTracker")


def test_is_detector_enabled_default():
    assert is_detector_enabled("ToolDriftDetector")


def test_invalid_sensitivity_ignored():
    configure_detector_sensitivity({"Test": "invalid_level"})
    assert get_detector_sensitivity("Test") == "high"  # unchanged
