"""Tests for agent_bom.cloud.gcp_cis_benchmark to improve coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.base import CloudDiscoveryError
from agent_bom.cloud.gcp_cis_benchmark import (
    GCPCISReport,
    run_benchmark,
)

# ---------------------------------------------------------------------------
# GCPCISReport
# ---------------------------------------------------------------------------


def test_report_empty():
    r = GCPCISReport()
    assert r.passed == 0
    assert r.failed == 0
    assert r.total == 0
    assert r.pass_rate == 0.0


def test_report_with_checks():
    r = GCPCISReport(
        checks=[
            CISCheckResult(check_id="1.4", title="t", status=CheckStatus.PASS, severity="medium"),
            CISCheckResult(check_id="1.5", title="t", status=CheckStatus.FAIL, severity="high"),
            CISCheckResult(check_id="1.6", title="t", status=CheckStatus.ERROR, severity="high"),
        ]
    )
    assert r.passed == 1
    assert r.failed == 1
    assert r.total == 3
    assert r.pass_rate == 50.0


def test_report_to_dict():
    r = GCPCISReport(
        project_id="proj-123",
        checks=[
            CISCheckResult(check_id="1.4", title="Test", status=CheckStatus.PASS, severity="medium"),
        ],
    )
    d = r.to_dict()
    assert d["benchmark"] == "CIS Google Cloud Platform Foundation"
    assert d["project_id"] == "proj-123"
    assert d["passed"] == 1
    assert len(d["checks"]) == 1
    assert "attack_techniques" in d["checks"][0]


# ---------------------------------------------------------------------------
# run_benchmark
# ---------------------------------------------------------------------------


def test_run_benchmark_no_project():
    with patch.dict("os.environ", {}, clear=True):
        # Remove GOOGLE_CLOUD_PROJECT if set
        import os

        old = os.environ.pop("GOOGLE_CLOUD_PROJECT", None)
        try:
            with pytest.raises(CloudDiscoveryError, match="project ID"):
                run_benchmark()
        finally:
            if old:
                os.environ["GOOGLE_CLOUD_PROJECT"] = old


def test_run_benchmark_no_sdk():
    """When no GCP SDK is importable, should raise CloudDiscoveryError."""
    import builtins

    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if any(name.startswith(m) for m in ("google.cloud", "googleapiclient")):
            raise ImportError("mocked")
        return original_import(name, *args, **kwargs)

    with patch.dict("os.environ", {"GOOGLE_CLOUD_PROJECT": "test-proj"}), patch("builtins.__import__", side_effect=mock_import):
        with pytest.raises(CloudDiscoveryError, match="GCP SDK"):
            run_benchmark(project_id="test-proj")


def _mock_gcp_sdk():
    """Context manager to fake having a GCP SDK installed."""
    import sys

    mock_mod = MagicMock()
    # Pre-populate sys.modules so __import__ finds them
    mods = {
        "google": mock_mod,
        "google.cloud": mock_mod,
        "google.cloud.compute_v1": mock_mod,
    }
    return patch.dict(sys.modules, mods)


def test_run_benchmark_with_check_filter():
    """Run benchmark with a check filter that matches nothing — should return empty."""
    with _mock_gcp_sdk():
        report = run_benchmark(project_id="test-proj", checks=["99.99"])
        assert report.total == 0


def test_run_benchmark_check_exception_handled():
    """When individual check raises, it should be caught and recorded as ERROR."""
    with _mock_gcp_sdk(), patch("agent_bom.cloud.gcp_cis_benchmark._check_1_4", side_effect=RuntimeError("boom")):
        report = run_benchmark(project_id="test-proj", checks=["1.4"])
        assert report.total == 1
        assert report.checks[0].status == CheckStatus.ERROR
