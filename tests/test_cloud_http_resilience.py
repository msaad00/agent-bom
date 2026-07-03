"""Tests that cloud provider HTTP calls route through the resilient client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from agent_bom.cloud.base import CloudDiscoveryError


def test_crusoe_get_retries_via_resilient_client():
    from agent_bom.cloud import crusoe

    ok = httpx.Response(200, json={"items": []}, request=httpx.Request("GET", "https://example.com"))

    with patch("agent_bom.cloud.crusoe.http_client.sync_get", return_value=ok) as mock_get:
        result = crusoe._crusoe_get("/compute/vms", "test-key")

    mock_get.assert_called_once()
    assert result == {"items": []}


def test_crusoe_get_raises_on_exhausted_retries():
    from agent_bom.cloud import crusoe

    with patch("agent_bom.cloud.crusoe.http_client.sync_get", return_value=None):
        with pytest.raises(CloudDiscoveryError, match="failed after retries"):
            crusoe._crusoe_get("/compute/vms", "test-key")


def test_vast_get_retries_via_resilient_client():
    from agent_bom.cloud import vastai

    ok = httpx.Response(200, json={"instances": []}, request=httpx.Request("GET", "https://example.com"))

    with patch("agent_bom.cloud.vastai.http_client.sync_get", return_value=ok) as mock_get:
        result = vastai._vast_get("/instances/?owner=me", "test-key")

    mock_get.assert_called_once()
    assert result == {"instances": []}


def test_container_sbom_registry_get_uses_resilient_client():
    from agent_bom.cloud import container_sbom

    ok = httpx.Response(200, json={"token": "abc"}, request=httpx.Request("GET", "https://example.com"))

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)

    with (
        patch("agent_bom.cloud.container_sbom.http_client.create_sync_client", return_value=mock_client),
        patch("agent_bom.cloud.container_sbom.http_client.sync_request_with_retry", return_value=ok) as mock_retry,
    ):
        token = container_sbom._dockerhub_token("library", "ubuntu")

    mock_retry.assert_called_once()
    assert token == "abc"
