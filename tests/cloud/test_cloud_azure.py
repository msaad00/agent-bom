"""Tests for agent_bom.cloud.azure to improve coverage."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.azure import (
    _discover_azure_functions,
    _discover_container_apps,
    _discover_container_instances,
    _discover_ml_endpoints,
    _discover_openai_deployments,
    discover,
)
from agent_bom.cloud.base import CloudDiscoveryError

# ---------------------------------------------------------------------------
# discover (top level)
# ---------------------------------------------------------------------------


def test_discover_no_azure_identity():
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "azure.identity":
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        with pytest.raises(CloudDiscoveryError, match="azure-identity"):
            discover()


def _mock_azure_identity():
    """Context manager to mock azure.identity in sys.modules."""
    import sys

    mock_mod = MagicMock()
    mods = {
        "azure": mock_mod,
        "azure.identity": mock_mod,
    }
    return patch.dict(sys.modules, mods)


def test_discover_no_subscription():
    import os

    old = os.environ.pop("AZURE_SUBSCRIPTION_ID", None)
    try:
        with _mock_azure_identity():
            agents, warnings = discover()
            assert len(agents) == 0
            assert any("AZURE_SUBSCRIPTION_ID" in w for w in warnings)
    finally:
        if old:
            os.environ["AZURE_SUBSCRIPTION_ID"] = old


def test_discover_auth_failure():
    import sys

    mock_az = MagicMock()
    mock_az.DefaultAzureCredential.side_effect = RuntimeError("auth failed")

    mods = {"azure": mock_az, "azure.identity": mock_az}
    with patch.dict(sys.modules, mods), patch.dict("os.environ", {"AZURE_SUBSCRIPTION_ID": "sub-123"}):
        agents, warnings = discover(subscription_id="sub-123")
        assert len(agents) == 0
        assert any("authentication failed" in w.lower() for w in warnings)


# ---------------------------------------------------------------------------
# _discover_container_apps
# ---------------------------------------------------------------------------


def test_container_apps_no_sdk():
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "appcontainers" in name:
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        agents, warnings = _discover_container_apps(MagicMock(), "sub", None)
        assert len(agents) == 0
        assert any("appcontainers" in w for w in warnings)


def test_container_apps_with_apps():
    import sys

    mock_sdk = MagicMock()
    container = SimpleNamespace(name="mycontainer", image="myimage:latest")
    template = SimpleNamespace(containers=[container])
    app = SimpleNamespace(name="myapp", template=template, id="app-id")

    mock_client = MagicMock()
    mock_client.container_apps.list_by_subscription.return_value = [app]
    mock_sdk.ContainerAppsAPIClient.return_value = mock_client

    with patch.dict(sys.modules, {"azure.mgmt.appcontainers": mock_sdk}):
        agents, warnings = _discover_container_apps(MagicMock(), "sub", None)
        assert len(agents) == 1
        assert "myapp" in agents[0].name


def test_container_apps_by_resource_group():
    import sys

    mock_sdk = MagicMock()
    container = SimpleNamespace(name="c", image="img:v1")
    template = SimpleNamespace(containers=[container])
    app = SimpleNamespace(name="a", template=template, id="id")

    mock_client = MagicMock()
    mock_client.container_apps.list_by_resource_group.return_value = [app]
    mock_sdk.ContainerAppsAPIClient.return_value = mock_client

    with patch.dict(sys.modules, {"azure.mgmt.appcontainers": mock_sdk}):
        agents, warnings = _discover_container_apps(MagicMock(), "sub", "my-rg")
        assert len(agents) == 1


# ---------------------------------------------------------------------------
# _discover_azure_functions
# ---------------------------------------------------------------------------


def test_azure_functions_no_sdk():
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "azure.mgmt.web" in name:
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        agents, warnings = _discover_azure_functions(MagicMock(), "sub")
        assert len(agents) == 0
        assert any("azure-mgmt-web" in w for w in warnings)


def test_azure_functions_found():
    import sys

    mock_sdk = MagicMock()
    func_app = SimpleNamespace(
        name="myfunc",
        kind="functionapp",
        id="/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Web/sites/myfunc",
        location="eastus",
    )

    config = SimpleNamespace(
        linux_fx_version="PYTHON|3.11",
        net_framework_version="",
        node_version="",
        python_version="",
        java_version="",
    )

    mock_client = MagicMock()
    mock_client.web_apps.list.return_value = [func_app]
    mock_client.web_apps.get_configuration.return_value = config
    mock_sdk.WebSiteManagementClient.return_value = mock_client

    with patch.dict(sys.modules, {"azure.mgmt.web": mock_sdk}):
        agents, warnings = _discover_azure_functions(MagicMock(), "sub")
        assert len(agents) == 1
        assert "myfunc" in agents[0].name


def test_azure_functions_non_functionapp():
    import sys

    mock_sdk = MagicMock()
    web_app = SimpleNamespace(name="webapp", kind="app", id="/sub/rg/sites/webapp", location="")

    mock_client = MagicMock()
    mock_client.web_apps.list.return_value = [web_app]
    mock_sdk.WebSiteManagementClient.return_value = mock_client

    with patch.dict(sys.modules, {"azure.mgmt.web": mock_sdk}):
        agents, warnings = _discover_azure_functions(MagicMock(), "sub")
        assert len(agents) == 0


# ---------------------------------------------------------------------------
# _discover_container_instances
# ---------------------------------------------------------------------------


def test_container_instances_no_sdk():
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "containerinstance" in name:
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        agents, warnings = _discover_container_instances(MagicMock(), "sub")
        assert any("containerinstance" in w for w in warnings)


def test_container_instances_found():
    import sys

    mock_sdk = MagicMock()
    container = SimpleNamespace(name="web", image="nginx:latest")
    group = SimpleNamespace(
        name="group1",
        id="/subscriptions/sub/resourceGroups/rg-aci/providers/Microsoft.ContainerInstance/containerGroups/group1",
        location="eastus",
        containers=[container],
    )

    mock_client = MagicMock()
    mock_client.container_groups.list.return_value = [group]
    mock_sdk.ContainerInstanceManagementClient.return_value = mock_client

    with patch.dict(sys.modules, {"azure.mgmt.containerinstance": mock_sdk}):
        agents, warnings = _discover_container_instances(MagicMock(), "sub")
        assert len(agents) == 1
        origin = agents[0].metadata["cloud_origin"]
        assert origin["scope"]["subscription_id"] == "sub"
        assert origin["resource_id"].endswith("/containerGroups/group1/web")
        scope = agents[0].metadata["cloud_scope"]
        assert scope["scope_type"] == "resource-group"
        assert scope["scope_id"] == "rg-aci"
        assert scope["parent_scope"] == {"type": "subscription", "id": "sub"}


# ---------------------------------------------------------------------------
# _discover_openai_deployments
# ---------------------------------------------------------------------------


def test_openai_no_sdk():
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "cognitiveservices" in name:
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        agents, warnings = _discover_openai_deployments(MagicMock(), "sub")
        assert any("cognitiveservices" in w for w in warnings)


def test_openai_found():
    import sys

    mock_sdk = MagicMock()
    account = SimpleNamespace(
        name="myoai",
        kind="OpenAI",
        id="/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.CognitiveServices/accounts/myoai",
        location="eastus",
    )
    model = SimpleNamespace(name="gpt-4", version="0613")
    sku = SimpleNamespace(name="Standard")
    props = SimpleNamespace(model=model)
    deployment = SimpleNamespace(
        name="gpt-4-deploy",
        properties=props,
        sku=sku,
        id="/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.CognitiveServices/accounts/myoai/deployments/gpt-4-deploy",
    )

    mock_client = MagicMock()
    mock_client.accounts.list.return_value = [account]
    mock_client.deployments.list.return_value = [deployment]
    mock_sdk.CognitiveServicesManagementClient.return_value = mock_client

    with patch.dict(sys.modules, {"azure.mgmt.cognitiveservices": mock_sdk}):
        agents, warnings = _discover_openai_deployments(MagicMock(), "sub")
        assert len(agents) == 1
        assert "gpt-4" in agents[0].name
        origin = agents[0].metadata["cloud_origin"]
        assert origin["scope"]["subscription_id"] == "sub"
        assert origin["resource_name"] == "gpt-4-deploy"
        scope = agents[0].metadata["cloud_scope"]
        assert scope["scope_type"] == "account"
        assert scope["scope_id"] == "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.CognitiveServices/accounts/myoai"
        assert scope["scope_name"] == "myoai"
        assert scope["parent_scope"] == {"type": "resource-group", "id": "rg1", "name": "rg1"}
        assert scope["location"] == "eastus"


# ---------------------------------------------------------------------------
# _discover_ml_endpoints
# ---------------------------------------------------------------------------


def test_ml_endpoint_scope_persists_workspace_context():
    import sys

    mock_sdk = MagicMock()
    workspace = SimpleNamespace(
        name="ml-ws",
        id="/subscriptions/sub/resourceGroups/rg-ml/providers/Microsoft.MachineLearningServices/workspaces/ml-ws",
        location="westus2",
    )
    endpoint = SimpleNamespace(
        name="prod-endpoint",
        id="/subscriptions/sub/resourceGroups/rg-ml/providers/Microsoft.MachineLearningServices/workspaces/ml-ws/onlineEndpoints/prod-endpoint",
        location="westus2",
        properties=SimpleNamespace(scoring_uri="https://prod-endpoint.westus2.inference.ml.azure.com/score"),
    )
    deployment = SimpleNamespace(
        name="blue",
        properties=SimpleNamespace(model="azureml://registries/models/fraud-detector/versions/7", instance_type="Standard_DS3_v2"),
    )

    mock_client = MagicMock()
    mock_client.workspaces.list_by_subscription.return_value = [workspace]
    mock_client.online_endpoints.list.return_value = [endpoint]
    mock_client.online_deployments.list.return_value = [deployment]
    mock_sdk.MachineLearningServicesMgmtClient.return_value = mock_client

    with patch.dict(sys.modules, {"azure.mgmt.machinelearningservices": mock_sdk}):
        agents, warnings = _discover_ml_endpoints(MagicMock(), "sub")

    assert warnings == []
    assert len(agents) == 1
    origin = agents[0].metadata["cloud_origin"]
    assert origin["scope"]["subscription_id"] == "sub"
    assert origin["resource_id"] == endpoint.id
    scope = agents[0].metadata["cloud_scope"]
    assert scope["scope_type"] == "workspace"
    assert scope["scope_id"] == workspace.id
    assert scope["scope_name"] == "ml-ws"
    assert scope["parent_scope"] == {"type": "resource-group", "id": "rg-ml", "name": "rg-ml"}
    assert scope["location"] == "westus2"
