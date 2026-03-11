"""Tests for agent_bom.cloud.aws to improve coverage."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.base import CloudDiscoveryError


def _mock_boto3():
    """Create mock boto3 session and its clients."""
    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"
    mock_boto3 = MagicMock()
    mock_boto3.Session.return_value = mock_session
    return mock_boto3, mock_session


# ---------------------------------------------------------------------------
# discover — top level
# ---------------------------------------------------------------------------


def test_discover_no_boto3():
    """Should raise CloudDiscoveryError if boto3 is missing."""
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "boto3":
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        with pytest.raises(CloudDiscoveryError, match="boto3"):
            from agent_bom.cloud.aws import discover

            discover()


def test_discover_bedrock_empty():
    """Discover with no bedrock agents."""
    mock_boto3, mock_session = _mock_boto3()
    mock_botocore = MagicMock()

    # Empty bedrock paginator
    mock_bedrock = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"agentSummaries": []}]
    mock_bedrock.get_paginator.return_value = mock_paginator
    mock_session.client.return_value = mock_bedrock

    with patch.dict(sys.modules, {"boto3": mock_boto3, "botocore": mock_botocore, "botocore.exceptions": mock_botocore.exceptions}):
        mock_botocore.exceptions.ClientError = type("ClientError", (Exception,), {"response": {"Error": {"Code": "test"}}})
        mock_botocore.exceptions.NoCredentialsError = type("NoCredentialsError", (Exception,), {})
        from agent_bom.cloud import aws

        # Force reload to pick up mocked boto3
        agents, warnings = aws.discover(region="us-east-1", include_ecs=False)
        assert isinstance(agents, list)


def test_discover_with_bedrock_agent():
    """Discover with a bedrock agent that has action groups."""
    mock_boto3, mock_session = _mock_boto3()
    mock_botocore = MagicMock()
    mock_botocore.exceptions.ClientError = type("ClientError", (Exception,), {})
    mock_botocore.exceptions.NoCredentialsError = type("NoCredentialsError", (Exception,), {})

    # Bedrock client
    mock_bedrock = MagicMock()
    agent_summary = {
        "agentId": "agent-1",
        "agentName": "MyAgent",
        "agentStatus": "PREPARED",
    }
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"agentSummaries": [agent_summary]}]
    mock_bedrock.get_paginator.return_value = mock_paginator
    mock_bedrock.get_agent.return_value = {
        "agent": {
            "agentArn": "arn:aws:bedrock:us-east-1:agent/agent-1",
            "foundationModel": "anthropic.claude-v2",
        }
    }

    # Action group paginator
    ag_paginator = MagicMock()
    ag_paginator.paginate.return_value = [{"actionGroupSummaries": []}]

    def get_paginator(name):
        if name == "list_agents":
            return mock_paginator
        elif name == "list_agent_action_groups":
            return ag_paginator
        return MagicMock()

    mock_bedrock.get_paginator = get_paginator
    mock_session.client.return_value = mock_bedrock

    with patch.dict(sys.modules, {"boto3": mock_boto3, "botocore": mock_botocore, "botocore.exceptions": mock_botocore.exceptions}):
        from agent_bom.cloud import aws

        agents, warnings = aws.discover(region="us-east-1", include_ecs=False)
        assert len(agents) >= 1
        assert "bedrock:MyAgent" in agents[0].name


def test_discover_no_credentials():
    """When credentials are missing, should add warning and return."""
    mock_boto3, mock_session = _mock_boto3()
    mock_botocore = MagicMock()

    no_creds_err = type("NoCredentialsError", (Exception,), {})
    mock_botocore.exceptions.NoCredentialsError = no_creds_err
    mock_botocore.exceptions.ClientError = type("ClientError", (Exception,), {})

    mock_bedrock = MagicMock()
    mock_bedrock.get_paginator.side_effect = no_creds_err("no creds")
    mock_session.client.return_value = mock_bedrock

    with patch.dict(sys.modules, {"boto3": mock_boto3, "botocore": mock_botocore, "botocore.exceptions": mock_botocore.exceptions}):
        from agent_bom.cloud import aws

        agents, warnings = aws.discover(include_ecs=False)
        assert any("credentials" in w.lower() for w in warnings)


def test_discover_ecs_images_as_agents():
    """ECS image refs should be converted to Agent objects."""
    mock_boto3, mock_session = _mock_boto3()
    mock_botocore = MagicMock()
    mock_botocore.exceptions.ClientError = type("ClientError", (Exception,), {})
    mock_botocore.exceptions.NoCredentialsError = type("NoCredentialsError", (Exception,), {})

    # Empty bedrock
    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"agentSummaries": []}]
    mock_client.get_paginator.return_value = mock_paginator
    mock_session.client.return_value = mock_client

    with (
        patch.dict(sys.modules, {"boto3": mock_boto3, "botocore": mock_botocore, "botocore.exceptions": mock_botocore.exceptions}),
        patch("agent_bom.cloud.aws._discover_ecs_images", return_value=(["nginx:latest"], [])),
    ):
        from agent_bom.cloud import aws

        agents, warnings = aws.discover(include_ecs=True)
        ecs_agents = [a for a in agents if "ecs-image" in a.name]
        assert len(ecs_agents) >= 1


def test_discover_with_region_and_profile():
    """Test passing region and profile kwargs."""
    mock_boto3, mock_session = _mock_boto3()
    mock_botocore = MagicMock()
    mock_botocore.exceptions.ClientError = type("ClientError", (Exception,), {})
    mock_botocore.exceptions.NoCredentialsError = type("NoCredentialsError", (Exception,), {})

    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"agentSummaries": []}]
    mock_client.get_paginator.return_value = mock_paginator
    mock_session.client.return_value = mock_client

    with patch.dict(sys.modules, {"boto3": mock_boto3, "botocore": mock_botocore, "botocore.exceptions": mock_botocore.exceptions}):
        from agent_bom.cloud import aws

        agents, warnings = aws.discover(region="eu-west-1", profile="prod", include_ecs=False)
        mock_boto3.Session.assert_called_with(region_name="eu-west-1", profile_name="prod")
