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


# ---------------------------------------------------------------------------
# Credential threading (fix/gcp-cis-credential-threading)
# ---------------------------------------------------------------------------


def test_creds_kwargs_empty_without_credentials():
    """Factory passes no credential kwarg by default — preserves ADC fallback."""
    from agent_bom.cloud import gcp_cis_benchmark as mod

    mod._clear_credentials()
    assert mod._creds_kwargs() == {}


def test_creds_kwargs_threads_explicit_credential():
    """When a credential is set, the factory surfaces it as a kwarg."""
    from agent_bom.cloud import gcp_cis_benchmark as mod

    sentinel = object()
    mod._set_credentials(sentinel)
    try:
        assert mod._creds_kwargs() == {"credentials": sentinel}
    finally:
        mod._clear_credentials()


def test_discovery_client_threads_credential(monkeypatch):
    """_discovery_client must pass the threaded credential into discovery.build."""
    from agent_bom.cloud import gcp_cis_benchmark as mod

    captured: dict = {}

    fake_built = MagicMock(name="discovery_client")

    def fake_build(service, version, **kwargs):
        captured["service"] = service
        captured["version"] = version
        captured["kwargs"] = kwargs
        return fake_built

    fake_discovery = MagicMock()
    fake_discovery.build = fake_build
    fake_googleapiclient = MagicMock()
    fake_googleapiclient.discovery = fake_discovery

    import sys

    creds = object()
    monkeypatch.setitem(sys.modules, "googleapiclient", fake_googleapiclient)
    monkeypatch.setitem(sys.modules, "googleapiclient.discovery", fake_discovery)
    mod._set_credentials(creds)
    try:
        client = mod._discovery_client("iam", "v1")
    finally:
        mod._clear_credentials()

    assert client is fake_built
    assert captured["service"] == "iam"
    assert captured["version"] == "v1"
    assert captured["kwargs"]["cache_discovery"] is False
    assert captured["kwargs"]["credentials"] is creds


def test_run_benchmark_accepts_credentials_and_clears_context():
    """run_benchmark accepts credentials and clears the module context afterward."""
    from agent_bom.cloud import gcp_cis_benchmark as mod

    creds = object()
    with _mock_gcp_sdk():
        report = run_benchmark(project_id="test-proj", credentials=creds, checks=["99.99"])
    assert report.total == 0
    # Context cleared in the finally block so a later ADC-only run is clean.
    assert mod._creds_kwargs() == {}


def test_failing_check_surfaces_sanitized_error_detail():
    """A discovery failure now carries a non-empty, sanitized error in evidence."""
    from agent_bom.cloud import gcp_cis_benchmark as mod

    def boom(*_args, **_kwargs):
        raise RuntimeError("permission denied: token expired for service account")

    with _mock_gcp_sdk(), patch.object(mod, "_discovery_client", side_effect=boom):
        report = run_benchmark(project_id="test-proj", credentials=object(), checks=["1.1"])

    assert report.total == 1
    check = report.checks[0]
    assert check.status == CheckStatus.ERROR
    # The error is surfaced (not swallowed) and routed through sanitization.
    assert check.evidence
    assert "permission denied" in check.evidence
