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


def test_discover_persists_sts_account_scope_on_aws_origins():
    """Representative AWS assets carry normalized account scope from STS."""
    mock_boto3, mock_session = _mock_boto3()
    mock_botocore = MagicMock()
    mock_botocore.exceptions.ClientError = type("ClientError", (Exception,), {})
    mock_botocore.exceptions.NoCredentialsError = type("NoCredentialsError", (Exception,), {})

    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

    mock_bedrock = MagicMock()
    agents_paginator = MagicMock()
    agents_paginator.paginate.return_value = [
        {"agentSummaries": [{"agentId": "agent-1", "agentName": "SupportAgent", "agentStatus": "PREPARED"}]}
    ]
    action_groups_paginator = MagicMock()
    action_groups_paginator.paginate.return_value = [{"actionGroupSummaries": []}]
    mock_bedrock.get_paginator.side_effect = lambda op: {
        "list_agents": agents_paginator,
        "list_agent_action_groups": action_groups_paginator,
    }[op]
    mock_bedrock.get_agent.return_value = {
        "agent": {
            "agentArn": "arn:aws:bedrock:us-east-1:123456789012:agent/agent-1",
            "foundationModel": "anthropic.claude-3-sonnet",
        }
    }

    mock_ecs = MagicMock()
    clusters_paginator = MagicMock()
    clusters_paginator.paginate.return_value = [{"clusterArns": ["arn:aws:ecs:us-east-1:123456789012:cluster/prod"]}]
    tasks_paginator = MagicMock()
    tasks_paginator.paginate.return_value = [{"taskArns": ["arn:aws:ecs:us-east-1:123456789012:task/prod/task-1"]}]
    mock_ecs.get_paginator.side_effect = lambda op: {"list_clusters": clusters_paginator, "list_tasks": tasks_paginator}[op]
    mock_ecs.describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": "arn:aws:ecs:us-east-1:123456789012:task/prod/task-1",
                "containers": [{"name": "model-api", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/model-api:2026-04"}],
            }
        ]
    }

    mock_session.client.side_effect = lambda service, **_kwargs: {
        "sts": mock_sts,
        "bedrock-agent": mock_bedrock,
        "ecs": mock_ecs,
    }[service]

    with patch.dict(sys.modules, {"boto3": mock_boto3, "botocore": mock_botocore, "botocore.exceptions": mock_botocore.exceptions}):
        from agent_bom.cloud import aws

        agents, warnings = aws.discover(region="us-east-1", include_ecs=True)

    assert not warnings
    origins = {agent.source: agent.metadata["cloud_origin"] for agent in agents}
    assert origins["aws-bedrock"]["scope"]["account_id"] == "123456789012"
    assert origins["aws-bedrock"]["resource_id"] == "arn:aws:bedrock:us-east-1:123456789012:agent/agent-1"
    assert origins["aws-ecs"]["scope"]["account_id"] == "123456789012"
    assert origins["aws-ecs"]["raw_identity"]["cluster_arn"] == "arn:aws:ecs:us-east-1:123456789012:cluster/prod"


def test_discover_continues_when_sts_account_resolution_is_denied():
    """Denied STS permissions omit account scope without blocking discovery."""
    mock_boto3, mock_session = _mock_boto3()
    mock_botocore = MagicMock()
    mock_botocore.exceptions.ClientError = type("ClientError", (Exception,), {})
    mock_botocore.exceptions.NoCredentialsError = type("NoCredentialsError", (Exception,), {})

    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = RuntimeError("AccessDenied")

    mock_bedrock = MagicMock()
    agents_paginator = MagicMock()
    agents_paginator.paginate.return_value = [
        {"agentSummaries": [{"agentId": "agent-1", "agentName": "SupportAgent", "agentStatus": "PREPARED"}]}
    ]
    action_groups_paginator = MagicMock()
    action_groups_paginator.paginate.return_value = [{"actionGroupSummaries": []}]
    mock_bedrock.get_paginator.side_effect = lambda op: {
        "list_agents": agents_paginator,
        "list_agent_action_groups": action_groups_paginator,
    }[op]
    mock_bedrock.get_agent.return_value = {
        "agent": {
            "agentArn": "arn:aws:bedrock:us-east-1:123456789012:agent/agent-1",
            "foundationModel": "anthropic.claude-3-sonnet",
        }
    }
    mock_session.client.side_effect = lambda service, **_kwargs: {"sts": mock_sts, "bedrock-agent": mock_bedrock}[service]

    with patch.dict(sys.modules, {"boto3": mock_boto3, "botocore": mock_botocore, "botocore.exceptions": mock_botocore.exceptions}):
        from agent_bom.cloud import aws

        agents, warnings = aws.discover(region="us-east-1", include_ecs=False)

    assert warnings == []
    assert len(agents) == 1
    assert "scope" not in agents[0].metadata["cloud_origin"]


def test_bedrock_unknown_lifecycle_keeps_origin_without_cloud_state():
    """Unverified lifecycle values do not drop the resource or invent state."""
    from agent_bom.cloud.aws import _discover_bedrock

    mock_session = MagicMock()
    mock_bedrock = MagicMock()
    agents_paginator = MagicMock()
    agents_paginator.paginate.return_value = [
        {"agentSummaries": [{"agentId": "agent-1", "agentName": "SupportAgent", "agentStatus": "CREATING"}]}
    ]
    action_groups_paginator = MagicMock()
    action_groups_paginator.paginate.return_value = [{"actionGroupSummaries": []}]
    mock_bedrock.get_paginator.side_effect = lambda op: {
        "list_agents": agents_paginator,
        "list_agent_action_groups": action_groups_paginator,
    }[op]
    mock_bedrock.get_agent.return_value = {
        "agent": {
            "agentArn": "arn:aws:bedrock:us-east-1:123456789012:agent/agent-1",
            "foundationModel": "anthropic.claude-3-sonnet",
        }
    }
    mock_session.client.return_value = mock_bedrock

    agents, warnings = _discover_bedrock(mock_session, "us-east-1", account_id="123456789012")

    assert warnings == []
    assert len(agents) == 1
    assert agents[0].metadata["cloud_origin"]["scope"]["account_id"] == "123456789012"
    assert "cloud_state" not in agents[0].metadata


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
