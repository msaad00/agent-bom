"""Tests for agent_bom.cloud.gcp to improve coverage."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.base import CloudDiscoveryError


def _mock_gcp_modules():
    """Create mock GCP SDK modules."""
    mock = MagicMock()
    return {
        "google": mock,
        "google.cloud": mock,
        "google.cloud.aiplatform": mock,
        "google.cloud.functions_v2": mock,
        "google.cloud.container_v1": mock,
        "google.cloud.run_v2": mock,
    }


# ---------------------------------------------------------------------------
# discover (top-level)
# ---------------------------------------------------------------------------


def test_discover_no_sdk():
    """Should raise CloudDiscoveryError if no GCP SDK installed."""
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name.startswith("google.cloud"):
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        with pytest.raises(CloudDiscoveryError, match="GCP SDK"):
            from agent_bom.cloud.gcp import discover

            discover()


def test_discover_no_project():
    """No project set should return warning."""
    mods = _mock_gcp_modules()
    with patch.dict(sys.modules, mods), patch.dict("os.environ", {}, clear=False):
        # Remove GOOGLE_CLOUD_PROJECT if set
        import os

        old = os.environ.pop("GOOGLE_CLOUD_PROJECT", None)
        try:
            from agent_bom.cloud import gcp

            agents, warnings = gcp.discover()
            assert any("GOOGLE_CLOUD_PROJECT" in w for w in warnings)
        finally:
            if old:
                os.environ["GOOGLE_CLOUD_PROJECT"] = old


def test_discover_with_project():
    """With project and mocked subsystems."""
    mods = _mock_gcp_modules()
    with (
        patch.dict(sys.modules, mods),
        patch("agent_bom.cloud.gcp._discover_vertex_ai", return_value=([], [])),
        patch("agent_bom.cloud.gcp._discover_cloud_functions", return_value=([], [])),
        patch("agent_bom.cloud.gcp._discover_gke_clusters", return_value=([], [])),
        patch("agent_bom.cloud.gcp._discover_cloud_run", return_value=([], [])),
    ):
        from agent_bom.cloud import gcp

        agents, warnings = gcp.discover(project_id="my-project")
        assert isinstance(agents, list)


def test_discover_subsystem_exception():
    """Subsystem exception should be caught as warning."""
    mods = _mock_gcp_modules()
    with (
        patch.dict(sys.modules, mods),
        patch("agent_bom.cloud.gcp._discover_vertex_ai", side_effect=RuntimeError("vertex error")),
        patch("agent_bom.cloud.gcp._discover_cloud_functions", return_value=([], [])),
        patch("agent_bom.cloud.gcp._discover_gke_clusters", return_value=([], [])),
        patch("agent_bom.cloud.gcp._discover_cloud_run", return_value=([], [])),
    ):
        from agent_bom.cloud import gcp

        agents, warnings = gcp.discover(project_id="my-project")
        assert any("Vertex AI" in w for w in warnings)


# ---------------------------------------------------------------------------
# _discover_vertex_ai
# ---------------------------------------------------------------------------


def test_vertex_ai_no_sdk():
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "aiplatform" in name:
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        from agent_bom.cloud.gcp import _discover_vertex_ai

        agents, warnings = _discover_vertex_ai("proj", "us-central1")
        assert len(agents) == 0
        assert any("aiplatform" in w for w in warnings)


def test_vertex_ai_exception():
    """Vertex AI discovery handles exceptions gracefully when aiplatform not installed."""
    # Already tested via test_vertex_ai_no_sdk above; this verifies the import-error path
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "aiplatform" in name:
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        from agent_bom.cloud.gcp import _discover_vertex_ai

        agents, warnings = _discover_vertex_ai("proj", "us-central1")
        assert len(agents) == 0


# ---------------------------------------------------------------------------
# _discover_cloud_functions
# ---------------------------------------------------------------------------


def test_cloud_functions_no_sdk():
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "functions_v2" in name:
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        from agent_bom.cloud.gcp import _discover_cloud_functions

        agents, warnings = _discover_cloud_functions("proj", "us-central1")
        assert any("functions" in w.lower() for w in warnings)
