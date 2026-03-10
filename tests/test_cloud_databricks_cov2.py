"""Tests for agent_bom.cloud.databricks to improve coverage."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.base import CloudDiscoveryError


def _mock_databricks_modules():
    """Create mock databricks SDK modules."""
    mock_sdk = MagicMock()
    mock_errors = MagicMock()
    mock_errors.PermissionDenied = type("PermissionDenied", (Exception,), {})
    mock_sdk.errors = mock_errors
    return {
        "databricks": mock_sdk,
        "databricks.sdk": mock_sdk,
        "databricks.sdk.errors": mock_errors,
    }


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


def test_discover_no_sdk():
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name.startswith("databricks"):
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        with pytest.raises(CloudDiscoveryError, match="databricks"):
            from agent_bom.cloud.databricks import discover

            discover()


def test_discover_connection_failure():
    mods = _mock_databricks_modules()
    mock_sdk = mods["databricks.sdk"]
    mock_sdk.WorkspaceClient.side_effect = RuntimeError("connection failed")

    with patch.dict(sys.modules, mods):
        from agent_bom.cloud import databricks

        agents, warnings = databricks.discover(host="https://test.cloud.databricks.com")
        assert any("Could not connect" in w for w in warnings)


def test_discover_empty_clusters():
    mods = _mock_databricks_modules()
    mock_sdk = mods["databricks.sdk"]

    mock_ws = MagicMock()
    mock_ws.clusters.list.return_value = []
    mock_ws.serving_endpoints.list.return_value = []
    mock_sdk.WorkspaceClient.return_value = mock_ws

    with patch.dict(sys.modules, mods):
        from agent_bom.cloud import databricks

        agents, warnings = databricks.discover(host="https://test.cloud.databricks.com")
        assert isinstance(agents, list)


def test_discover_with_host_and_token():
    """With host and token but SDK not installed, should raise."""
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name.startswith("databricks"):
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        with pytest.raises(CloudDiscoveryError):
            from agent_bom.cloud.databricks import discover

            discover(host="https://test.cloud.databricks.com", token="dapi123")
