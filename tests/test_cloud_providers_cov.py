"""Tests for cloud provider discovery modules — coverage expansion.

Covers: wandb_provider.py, mlflow_provider.py, openai_provider.py, huggingface.py
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

# ===
# W&B Provider
# ===


class TestWandbDiscover:
    def test_missing_wandb_raises(self):
        from agent_bom.cloud.base import CloudDiscoveryError
        from agent_bom.cloud.wandb_provider import discover

        with patch.dict(sys.modules, {"wandb": None}):
            with pytest.raises(CloudDiscoveryError):
                discover()

    def test_no_api_key_warns(self):
        mock_wandb = MagicMock()
        with patch.dict(sys.modules, {"wandb": mock_wandb}):
            from agent_bom.cloud import wandb_provider

            agents, warnings = wandb_provider.discover(api_key="", entity=None)
            assert any("WANDB_API_KEY" in w for w in warnings)

    def test_no_entity_warns(self):
        mock_wandb = MagicMock()
        with patch.dict(sys.modules, {"wandb": mock_wandb}):
            from agent_bom.cloud import wandb_provider

            agents, warnings = wandb_provider.discover(api_key="test-key", entity="")
            assert any("WANDB_ENTITY" in w for w in warnings)

    def test_discover_runs_with_project(self):
        mock_wandb = MagicMock()
        mock_run = MagicMock()
        mock_run.id = "abc123"
        mock_run.name = "test-run"
        mock_run.config = {"_wandb": {"requirements": ["torch==2.0.0"]}}
        mock_run.metadata = {}

        mock_api = MagicMock()
        mock_api.runs.return_value = [mock_run]
        mock_wandb.Api.return_value = mock_api

        with patch.dict(sys.modules, {"wandb": mock_wandb}):
            from agent_bom.cloud import wandb_provider

            agents, warnings = wandb_provider.discover(api_key="test-key", entity="testuser", project="testproj")
            assert len(agents) >= 1
            assert agents[0].name == "wandb-run:test-run"
            origin = agents[0].metadata["cloud_origin"]
            assert origin["provider"] == "wandb"
            assert origin["resource_type"] == "run"

    def test_discover_runs_without_project(self):
        mock_wandb = MagicMock()
        mock_project = MagicMock()
        mock_project.name = "my-project"

        mock_run = MagicMock()
        mock_run.id = "run1"
        mock_run.name = "run-name"
        mock_run.config = {}
        mock_run.metadata = {}

        mock_api = MagicMock()
        mock_api.projects.return_value = [mock_project]
        mock_api.runs.return_value = [mock_run]
        mock_wandb.Api.return_value = mock_api

        with patch.dict(sys.modules, {"wandb": mock_wandb}):
            from agent_bom.cloud import wandb_provider

            agents, warnings = wandb_provider.discover(api_key="test-key", entity="testuser", project=None)
            assert len(agents) >= 1

    def test_discover_artifacts(self):
        mock_wandb = MagicMock()
        mock_artifact = MagicMock()
        mock_artifact.name = "my-model"
        mock_artifact.version = "v3"
        mock_artifact.metadata = {}

        mock_api = MagicMock()
        mock_api.runs.return_value = []
        mock_api.artifact_versions.return_value = [mock_artifact]
        mock_wandb.Api.return_value = mock_api

        with patch.dict(sys.modules, {"wandb": mock_wandb}):
            from agent_bom.cloud import wandb_provider

            agents, warnings = wandb_provider.discover(api_key="test-key", entity="testuser", project="testproj")
            art_agents = [a for a in agents if "wandb-model:" in a.name or "wandb-dataset:" in a.name]
            assert len(art_agents) >= 1
            origin = art_agents[0].metadata["cloud_origin"]
            assert origin["provider"] == "wandb"
            assert origin["resource_type"] in {"model", "dataset"}

    def test_run_discovery_exception(self):
        mock_wandb = MagicMock()
        mock_api = MagicMock()
        mock_api.runs.side_effect = RuntimeError("API error")
        mock_wandb.Api.return_value = mock_api

        with patch.dict(sys.modules, {"wandb": mock_wandb}):
            from agent_bom.cloud import wandb_provider

            agents, warnings = wandb_provider.discover(api_key="test-key", entity="testuser", project="testproj")
            assert any("error" in w.lower() for w in warnings)


class TestWandbParseRequirement:
    def test_with_version_spec(self):
        from agent_bom.cloud.wandb_provider import _parse_requirement

        pkg = _parse_requirement("torch==2.0.0")
        assert pkg is not None
        assert pkg.name == "torch"
        assert pkg.version == "2.0.0"

    def test_gte_spec(self):
        from agent_bom.cloud.wandb_provider import _parse_requirement

        pkg = _parse_requirement("numpy>=1.20.0")
        assert pkg is not None
        assert pkg.name == "numpy"
        assert pkg.version == "1.20.0"

    def test_no_version(self):
        from agent_bom.cloud.wandb_provider import _parse_requirement

        pkg = _parse_requirement("requests")
        assert pkg is not None
        assert pkg.name == "requests"
        assert pkg.version == "unknown"

    def test_with_extras(self):
        from agent_bom.cloud.wandb_provider import _parse_requirement

        pkg = _parse_requirement("agent-bom[mcp-server]==1.0.0")
        assert pkg is not None
        assert pkg.name == "agent-bom"

    def test_comment_skipped(self):
        from agent_bom.cloud.wandb_provider import _parse_requirement

        assert _parse_requirement("# comment") is None

    def test_empty_skipped(self):
        from agent_bom.cloud.wandb_provider import _parse_requirement

        assert _parse_requirement("") is None

    def test_flag_skipped(self):
        from agent_bom.cloud.wandb_provider import _parse_requirement

        assert _parse_requirement("-e .") is None


class TestWandbExtractPackages:
    def test_from_requirements(self):
        from agent_bom.cloud.wandb_provider import _extract_packages_from_metadata

        config = {"_wandb": {"requirements": ["torch==2.0.0", "numpy>=1.20"]}}
        pkgs = _extract_packages_from_metadata(config, {})
        names = [p.name for p in pkgs]
        assert "torch" in names
        assert "numpy" in names

    def test_from_metadata_python(self):
        from agent_bom.cloud.wandb_provider import _extract_packages_from_metadata

        metadata = {"python": {"packages": [{"name": "scipy", "version": "1.11.0"}]}}
        pkgs = _extract_packages_from_metadata({}, metadata)
        assert any(p.name == "scipy" for p in pkgs)

    def test_transformers_hint(self):
        from agent_bom.cloud.wandb_provider import _extract_packages_from_metadata

        config = {"_name_or_path": "bert-base-uncased"}
        pkgs = _extract_packages_from_metadata(config, {})
        assert any(p.name == "transformers" for p in pkgs)


# ===
# MLflow Provider
# ===


class TestMlflowDiscover:
    def test_missing_mlflow_raises(self):
        from agent_bom.cloud.base import CloudDiscoveryError
        from agent_bom.cloud.mlflow_provider import discover

        with patch.dict(sys.modules, {"mlflow": None}):
            with pytest.raises(CloudDiscoveryError):
                discover()

    def test_no_tracking_uri_warns(self):
        mock_mlflow = MagicMock()
        with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
            from agent_bom.cloud import mlflow_provider

            agents, warnings = mlflow_provider.discover(tracking_uri="")
            assert any("MLFLOW_TRACKING_URI" in w for w in warnings)

    def test_discover_registered_models(self):
        mock_mlflow = MagicMock()
        mock_mv = MagicMock()
        mock_mv.version = "3"
        mock_mv.current_stage = "Production"
        mock_mv.run_id = "run123"
        mock_mv.source = "s3://bucket/sklearn/model"

        mock_model = MagicMock()
        mock_model.name = "my-model"
        mock_model.latest_versions = [mock_mv]
        mock_model.description = "A test model"

        mock_page = MagicMock()
        mock_page.__iter__ = lambda self: iter([mock_model])
        mock_page.token = None

        mock_client = MagicMock()
        mock_client.search_registered_models.return_value = mock_page
        mock_client.search_experiments.return_value = MagicMock(token=None, __iter__=lambda self: iter([]))
        mock_client.list_artifacts.return_value = []

        mock_mlflow.MlflowClient.return_value = mock_client

        with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
            from agent_bom.cloud import mlflow_provider

            agents, warnings = mlflow_provider.discover(tracking_uri="http://localhost:5000")
            model_agents = [a for a in agents if "mlflow-model:" in a.name]
            assert len(model_agents) >= 1
            origin = model_agents[0].metadata["cloud_origin"]
            assert origin["provider"] == "mlflow"
            assert origin["resource_type"] == "model"

    def test_discover_experiments(self):
        mock_mlflow = MagicMock()

        mock_exp = MagicMock()
        mock_exp.experiment_id = "1"
        mock_exp.name = "my-experiment"

        mock_run = MagicMock()
        mock_run.info.run_id = "run456"

        mock_model_page = MagicMock(token=None, __iter__=lambda self: iter([]))
        mock_exp_page = MagicMock(token=None, __iter__=lambda self: iter([mock_exp]))

        mock_client = MagicMock()
        mock_client.search_registered_models.return_value = mock_model_page
        mock_client.search_experiments.return_value = mock_exp_page
        mock_client.search_runs.return_value = [mock_run]
        mock_client.list_artifacts.return_value = []

        mock_mlflow.MlflowClient.return_value = mock_client

        with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
            from agent_bom.cloud import mlflow_provider

            agents, warnings = mlflow_provider.discover(tracking_uri="http://localhost:5000")
            exp_agents = [a for a in agents if "mlflow-exp:" in a.name]
            assert len(exp_agents) >= 1
            origin = exp_agents[0].metadata["cloud_origin"]
            assert origin["provider"] == "mlflow"
            assert origin["resource_type"] == "experiment"

    def test_model_discovery_exception(self):
        mock_mlflow = MagicMock()
        mock_client = MagicMock()
        mock_client.search_registered_models.side_effect = RuntimeError("conn refused")
        mock_client.search_experiments.return_value = MagicMock(token=None, __iter__=lambda self: iter([]))
        mock_mlflow.MlflowClient.return_value = mock_client

        with patch.dict(sys.modules, {"mlflow": mock_mlflow}):
            from agent_bom.cloud import mlflow_provider

            agents, warnings = mlflow_provider.discover(tracking_uri="http://localhost:5000")
            assert any("error" in w.lower() or "Could not" in w for w in warnings)


class TestMlflowHelpers:
    def test_extract_flavor_packages_sklearn(self):
        from agent_bom.cloud.mlflow_provider import _extract_flavor_packages

        pkgs = _extract_flavor_packages("s3://bucket/sklearn/model")
        assert any(p.name == "scikit-learn" for p in pkgs)

    def test_extract_flavor_packages_pytorch(self):
        from agent_bom.cloud.mlflow_provider import _extract_flavor_packages

        pkgs = _extract_flavor_packages("file:///models/pytorch/model.pth")
        assert any(p.name == "torch" for p in pkgs)

    def test_extract_flavor_packages_no_match(self):
        from agent_bom.cloud.mlflow_provider import _extract_flavor_packages

        pkgs = _extract_flavor_packages("s3://bucket/data/output.csv")
        assert pkgs == []

    def test_parse_requirements_txt(self):
        from agent_bom.cloud.mlflow_provider import _parse_requirements_txt

        content = "torch==2.0.0\nnumpy>=1.20\nrequests\n# comment\n-f https://example.com"
        pkgs = _parse_requirements_txt(content)
        names = [p.name for p in pkgs]
        assert "torch" in names
        assert "numpy" in names
        assert "requests" in names

    def test_parse_conda_yaml(self):
        from agent_bom.cloud.mlflow_provider import _parse_conda_yaml

        content = """
name: myenv
dependencies:
  - python=3.10
  - pip:
    - torch==2.0.0
    - numpy
"""
        pkgs = _parse_conda_yaml(content)
        names = [p.name for p in pkgs]
        assert "torch" in names
        assert "numpy" in names

    def test_parse_conda_yaml_no_pip_deps(self):
        from agent_bom.cloud.mlflow_provider import _parse_conda_yaml

        content = """
name: myenv
dependencies:
  - python=3.10
  - numpy=1.20
"""
        pkgs = _parse_conda_yaml(content)
        assert isinstance(pkgs, list)


# ===
# OpenAI Provider
# ===


class TestOpenAIDiscover:
    def test_missing_openai_raises(self):
        from agent_bom.cloud.base import CloudDiscoveryError
        from agent_bom.cloud.openai_provider import discover

        with patch.dict(sys.modules, {"openai": None}):
            with pytest.raises(CloudDiscoveryError):
                discover()

    def test_no_api_key_warns(self):
        mock_openai = MagicMock()
        with patch.dict(sys.modules, {"openai": mock_openai}):
            from agent_bom.cloud import openai_provider

            agents, warnings = openai_provider.discover(api_key="")
            assert any("OPENAI_API_KEY" in w for w in warnings)

    def test_discover_assistants(self):
        mock_openai = MagicMock()

        mock_tool_ci = MagicMock()
        mock_tool_ci.type = "code_interpreter"
        mock_tool_fs = MagicMock()
        mock_tool_fs.type = "file_search"
        mock_tool_fn = MagicMock()
        mock_tool_fn.type = "function"
        mock_tool_fn.function.name = "my_func"
        mock_tool_fn.function.description = "Does something"

        mock_asst = MagicMock()
        mock_asst.id = "asst_123"
        mock_asst.name = "Test Assistant"
        mock_asst.model = "gpt-4"
        mock_asst.tools = [mock_tool_ci, mock_tool_fs, mock_tool_fn]

        mock_list = MagicMock()
        mock_list.data = [mock_asst]
        mock_list.has_more = False

        mock_client = MagicMock()
        mock_client.beta.assistants.list.return_value = mock_list
        mock_client.fine_tuning.jobs.list.return_value = MagicMock(data=[], has_more=False)
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict(sys.modules, {"openai": mock_openai}):
            from agent_bom.cloud import openai_provider

            agents, warnings = openai_provider.discover(api_key="sk-test")
            asst_agents = [a for a in agents if "openai-asst:" in a.name]
            assert len(asst_agents) >= 1
            assert asst_agents[0].name == "openai-asst:Test Assistant"
            origin = asst_agents[0].metadata["cloud_origin"]
            assert origin["provider"] == "openai"
            assert origin["resource_type"] == "assistant"

    def test_discover_fine_tunes(self):
        mock_openai = MagicMock()

        mock_job = MagicMock()
        mock_job.id = "ft_123"
        mock_job.model = "gpt-3.5-turbo"
        mock_job.fine_tuned_model = "ft:gpt-3.5-turbo:org:custom:id"
        mock_job.status = "succeeded"
        mock_job.training_file = "file-abc123"

        mock_asst_list = MagicMock()
        mock_asst_list.data = []
        mock_asst_list.has_more = False

        mock_ft_list = MagicMock()
        mock_ft_list.data = [mock_job]
        mock_ft_list.has_more = False

        mock_client = MagicMock()
        mock_client.beta.assistants.list.return_value = mock_asst_list
        mock_client.fine_tuning.jobs.list.return_value = mock_ft_list
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict(sys.modules, {"openai": mock_openai}):
            from agent_bom.cloud import openai_provider

            agents, warnings = openai_provider.discover(api_key="sk-test")
            ft_agents = [a for a in agents if "openai-ft:" in a.name]
            assert len(ft_agents) >= 1
            origin = ft_agents[0].metadata["cloud_origin"]
            assert origin["provider"] == "openai"
            assert origin["resource_type"] == "job"

    def test_assistant_discovery_exception(self):
        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_client.beta.assistants.list.side_effect = RuntimeError("API down")
        mock_client.fine_tuning.jobs.list.return_value = MagicMock(data=[], has_more=False)
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict(sys.modules, {"openai": mock_openai}):
            from agent_bom.cloud import openai_provider

            agents, warnings = openai_provider.discover(api_key="sk-test")
            assert any("error" in w.lower() or "Could not" in w for w in warnings)


# ===
# Hugging Face Provider
# ===


class TestHuggingFaceDiscover:
    def test_missing_hf_hub_raises(self):
        from agent_bom.cloud.base import CloudDiscoveryError
        from agent_bom.cloud.huggingface import discover

        with patch.dict(sys.modules, {"huggingface_hub": None}):
            with pytest.raises(CloudDiscoveryError):
                discover()

    def test_no_token_no_author_warns(self):
        mock_hf = MagicMock()
        with patch.dict(sys.modules, {"huggingface_hub": mock_hf}):
            from agent_bom.cloud import huggingface

            agents, warnings = huggingface.discover(token="", username=None, organization=None)
            assert any("HF_TOKEN" in w for w in warnings)

    def test_discover_models(self):
        mock_hf = MagicMock()

        mock_model = MagicMock()
        mock_model.id = "user/my-model"
        mock_model.modelId = "user/my-model"
        mock_model.library_name = "transformers"
        mock_model.pipeline_tag = "text-classification"
        mock_model.tags = ["pytorch"]
        mock_model.card_data = None
        mock_model.downloads = 1000
        mock_model.likes = 50

        mock_api = MagicMock()
        mock_api.list_models.return_value = [mock_model]
        mock_api.list_spaces.return_value = []
        mock_hf.HfApi.return_value = mock_api

        with patch.dict(sys.modules, {"huggingface_hub": mock_hf}):
            from agent_bom.cloud import huggingface

            agents, warnings = huggingface.discover(token="hf_test", username="user")
            model_agents = [a for a in agents if "hf-model:" in a.name]
            assert len(model_agents) >= 1

    def test_discover_spaces(self):
        mock_hf = MagicMock()

        mock_space = MagicMock()
        mock_space.id = "user/my-space"
        mock_space.sdk = "gradio"

        mock_api = MagicMock()
        mock_api.list_models.return_value = []
        mock_api.list_spaces.return_value = [mock_space]
        mock_hf.HfApi.return_value = mock_api

        with patch.dict(sys.modules, {"huggingface_hub": mock_hf}):
            from agent_bom.cloud import huggingface

            agents, warnings = huggingface.discover(token="hf_test", username="user")
            space_agents = [a for a in agents if "hf-space:" in a.name]
            assert len(space_agents) >= 1

    def test_discover_inference_endpoints(self):
        mock_hf = MagicMock()

        mock_ep = MagicMock()
        mock_ep.name = "my-endpoint"
        mock_ep.status = "running"
        mock_ep.framework = "pytorch"

        mock_api = MagicMock()
        mock_api.list_models.return_value = []
        mock_api.list_spaces.return_value = []
        mock_api.list_inference_endpoints.return_value = [mock_ep]
        mock_hf.HfApi.return_value = mock_api

        with patch.dict(sys.modules, {"huggingface_hub": mock_hf}):
            from agent_bom.cloud import huggingface

            agents, warnings = huggingface.discover(token="hf_test", username="user")
            ep_agents = [a for a in agents if "hf-endpoint:" in a.name]
            assert len(ep_agents) >= 1


class TestHuggingFaceHelpers:
    def test_extract_framework_packages_transformers(self):
        from agent_bom.cloud.huggingface import _extract_framework_packages

        pkgs = _extract_framework_packages("transformers", [])
        assert any(p.name == "transformers" for p in pkgs)

    def test_extract_framework_packages_from_tags(self):
        from agent_bom.cloud.huggingface import _extract_framework_packages

        pkgs = _extract_framework_packages("", ["pytorch", "safetensors"])
        names = [p.name for p in pkgs]
        assert "torch" in names
        assert "safetensors" in names

    def test_extract_framework_packages_unknown(self):
        from agent_bom.cloud.huggingface import _extract_framework_packages

        pkgs = _extract_framework_packages("unknown-lib", [])
        assert pkgs == []

    def test_parse_model_card_with_metadata(self):
        from agent_bom.cloud.huggingface import _parse_model_card

        mock_model = MagicMock()
        mock_model.pipeline_tag = "text-generation"
        mock_model.tags = ["pytorch", "llm"]
        mock_model.downloads = 5000
        mock_model.likes = 100

        mock_card = MagicMock()
        mock_card.license = "apache-2.0"
        mock_card.datasets = ["squad"]
        mock_card.language = ["en"]
        mock_card.model_index = None
        mock_model.card_data = mock_card

        meta = _parse_model_card(mock_model)
        assert meta["license"] == "apache-2.0"
        assert meta["datasets"] == ["squad"]
        assert meta["pipeline_tag"] == "text-generation"
        assert meta["downloads"] == 5000

    def test_parse_model_card_no_card_data(self):
        from agent_bom.cloud.huggingface import _parse_model_card

        mock_model = MagicMock()
        mock_model.card_data = None
        mock_model.pipeline_tag = None
        mock_model.tags = None
        mock_model.downloads = None
        mock_model.likes = None

        meta = _parse_model_card(mock_model)
        assert meta == {}

    def test_spaces_streamlit_sdk(self):
        mock_hf = MagicMock()

        mock_space = MagicMock()
        mock_space.id = "user/streamlit-app"
        mock_space.sdk = "streamlit"

        mock_api = MagicMock()
        mock_api.list_models.return_value = []
        mock_api.list_spaces.return_value = [mock_space]
        mock_hf.HfApi.return_value = mock_api

        with patch.dict(sys.modules, {"huggingface_hub": mock_hf}):
            from agent_bom.cloud import huggingface

            agents, _ = huggingface.discover(token="hf_test", username="user")
            space_agents = [a for a in agents if "hf-space:" in a.name]
            assert len(space_agents) >= 1

    def test_spaces_docker_sdk(self):
        mock_hf = MagicMock()

        mock_space = MagicMock()
        mock_space.id = "user/docker-app"
        mock_space.sdk = "docker"

        mock_api = MagicMock()
        mock_api.list_models.return_value = []
        mock_api.list_spaces.return_value = [mock_space]
        mock_hf.HfApi.return_value = mock_api

        with patch.dict(sys.modules, {"huggingface_hub": mock_hf}):
            from agent_bom.cloud import huggingface

            agents, _ = huggingface.discover(token="hf_test", username="user")
            space_agents = [a for a in agents if "hf-space:" in a.name]
            assert len(space_agents) >= 1


# ===
# Cloud container image auto-scan (Step 1h2 in _cloud.py)
# ===

_CLOUD_DISCOVERY_NO_PROVIDERS = dict(
    skill_only=False,
    aws=False,
    aws_region=None,
    aws_profile=None,
    aws_include_lambda=False,
    aws_include_eks=False,
    aws_include_step_functions=False,
    aws_include_ec2=False,
    aws_ec2_tag=None,
    azure_flag=False,
    azure_subscription=None,
    gcp_flag=False,
    gcp_project=None,
    coreweave_flag=False,
    coreweave_context=None,
    coreweave_namespace=None,
    databricks_flag=False,
    snowflake_flag=False,
    snowflake_authenticator=None,
    nebius_flag=False,
    nebius_api_key=None,
    nebius_project_id=None,
    hf_flag=False,
    hf_token=None,
    hf_username=None,
    hf_organization=None,
    wandb_flag=False,
    wandb_api_key=None,
    wandb_entity=None,
    wandb_project=None,
    mlflow_flag=False,
    mlflow_tracking_uri=None,
    openai_flag=False,
    openai_api_key=None,
    openai_org_id=None,
    ollama_flag=False,
    ollama_host=None,
)


def test_cloud_container_image_autoscan_populates_packages():
    """When a cloud provider returns an agent with a docker image, packages are populated.

    Step 1h2 detects MCPServer objects with command="docker" args=["run", <image>]
    added during cloud discovery, calls scan_image(), and populates server.packages.
    """
    from unittest.mock import patch

    from rich.console import Console

    from agent_bom.cli.agents._cloud import run_cloud_discovery
    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

    server = MCPServer(
        name="container:my-app",
        command="docker",
        args=["run", "myregistry.io/my-app:v2"],
        transport=TransportType.STDIO,
        packages=[],
    )
    cloud_agent = Agent(
        name="gcp-cloud-run:my-service",
        agent_type=AgentType.CUSTOM,
        config_path="gcp://my-service",
        mcp_servers=[server],
    )

    fake_pkg = Package(name="requests", version="2.28.0", ecosystem="pypi")
    ctx = ScanContext(con=Console(quiet=True))

    # Patch at the module-level attribute in the source modules (lazy imports fetch from here)
    with patch("agent_bom.cloud.discover_from_provider", return_value=([cloud_agent], [])):
        with patch("agent_bom.image.scan_image", return_value=([fake_pkg], "native")) as mock_scan:
            run_cloud_discovery(ctx, **{**_CLOUD_DISCOVERY_NO_PROVIDERS, "azure_flag": True})

    mock_scan.assert_called_once_with("myregistry.io/my-app:v2")
    assert server.packages == [fake_pkg]


def test_cloud_container_image_autoscan_skips_already_populated():
    """If a cloud-discovered server already has packages, scan_image is NOT called."""
    from unittest.mock import patch

    from rich.console import Console

    from agent_bom.cli.agents._cloud import run_cloud_discovery
    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

    existing_pkg = Package(name="numpy", version="1.24.0", ecosystem="pypi")
    server = MCPServer(
        name="container:pre-scanned",
        command="docker",
        args=["run", "myregistry.io/pre-scanned:v1"],
        transport=TransportType.STDIO,
        packages=[existing_pkg],  # already populated
    )
    cloud_agent = Agent(
        name="azure-container-app:pre-scanned",
        agent_type=AgentType.CUSTOM,
        config_path="azure://pre-scanned",
        mcp_servers=[server],
    )

    ctx = ScanContext(con=Console(quiet=True))

    with patch("agent_bom.cloud.discover_from_provider", return_value=([cloud_agent], [])):
        with patch("agent_bom.image.scan_image") as mock_scan:
            run_cloud_discovery(ctx, **{**_CLOUD_DISCOVERY_NO_PROVIDERS, "azure_flag": True})

    mock_scan.assert_not_called()
    assert server.packages == [existing_pkg]  # unchanged
