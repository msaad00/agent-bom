"""Tests for CoreWeave + NVIDIA NIM cloud discovery."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from agent_bom.cloud.coreweave import _CRD_INFERENCESERVICE, _CRD_VIRTUALSERVER

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Provider registration
# ═══════════════════════════════════════════════════════════════════════════════


def test_coreweave_registered_in_providers():
    """CoreWeave should be a registered cloud provider."""
    from agent_bom.cloud import _PROVIDERS

    assert "coreweave" in _PROVIDERS
    assert _PROVIDERS["coreweave"] == "agent_bom.cloud.coreweave"


def test_coreweave_discover_importable():
    """CoreWeave discover function should be importable."""
    from agent_bom.cloud.coreweave import discover

    assert callable(discover)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. No kubectl graceful handling
# ═══════════════════════════════════════════════════════════════════════════════


def test_no_kubectl_returns_warning():
    """When kubectl is not found, return empty agents + warning."""
    with patch("shutil.which", return_value=None):
        from agent_bom.cloud.coreweave import discover

        agents, warnings = discover()
        assert agents == []
        assert len(warnings) == 1
        assert "kubectl not found" in warnings[0]


# ═══════════════════════════════════════════════════════════════════════════════
# 3. VirtualServer CRD discovery
# ═══════════════════════════════════════════════════════════════════════════════

_VIRTUALSERVER_JSON = json.dumps(
    {
        "items": [
            {
                "metadata": {
                    "name": "gpu-workstation-01",
                    "namespace": "ml-team",
                    "labels": {"topology.kubernetes.io/region": "LAS1"},
                },
                "spec": {
                    "region": "LAS1",
                    "resources": {
                        "gpu": {"type": "NVIDIA_H100_SXM", "count": 8},
                    },
                },
            }
        ]
    }
)

# Empty response for passes that shouldn't find anything
_EMPTY_JSON = json.dumps({"items": []})


def _mock_kubectl_run(cmd, **kwargs):
    """Mock subprocess.run for kubectl commands."""
    # VirtualServer CRD query
    if _CRD_VIRTUALSERVER in cmd:
        return subprocess.CompletedProcess(cmd, 0, stdout=_VIRTUALSERVER_JSON, stderr="")
    # InferenceService CRD query
    if _CRD_INFERENCESERVICE in cmd:
        return subprocess.CompletedProcess(cmd, 0, stdout=_EMPTY_JSON, stderr="")
    # Pods query (for GPU pods and InfiniBand)
    if "pods" in cmd:
        return subprocess.CompletedProcess(cmd, 0, stdout=_EMPTY_JSON, stderr="")
    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")


def test_virtualserver_discovery():
    """VirtualServer CRDs should create coreweave-gpu agents."""
    with (
        patch("shutil.which", return_value="/usr/bin/kubectl"),
        patch("subprocess.run", side_effect=_mock_kubectl_run),
    ):
        from agent_bom.cloud.coreweave import discover

        agents, warnings = discover()
        vs_agents = [a for a in agents if a.source == "coreweave-gpu"]
        assert len(vs_agents) == 1
        agent = vs_agents[0]
        assert "gpu-workstation-01" in agent.name
        assert agent.metadata["gpu_type"] == "NVIDIA_H100_SXM"
        assert agent.metadata["gpu_count"] == 8
        assert agent.metadata["region"] == "LAS1"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. InferenceService discovery
# ═══════════════════════════════════════════════════════════════════════════════

_INFERENCESERVICE_JSON = json.dumps(
    {
        "items": [
            {
                "metadata": {"name": "llama-70b", "namespace": "inference"},
                "spec": {
                    "predictor": {
                        "containers": [
                            {
                                "name": "vllm-server",
                                "image": "vllm/vllm-openai:0.4.0",
                            }
                        ]
                    }
                },
                "status": {"url": "https://llama-70b.inference.coreweave.cloud"},
            }
        ]
    }
)


def _mock_kubectl_inferenceservice(cmd, **kwargs):
    if _CRD_VIRTUALSERVER in cmd:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")
    if _CRD_INFERENCESERVICE in cmd:
        return subprocess.CompletedProcess(cmd, 0, stdout=_INFERENCESERVICE_JSON, stderr="")
    if "pods" in cmd:
        return subprocess.CompletedProcess(cmd, 0, stdout=_EMPTY_JSON, stderr="")
    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")


def test_inferenceservice_discovery():
    """InferenceService CRDs should create coreweave-inference agents."""
    with (
        patch("shutil.which", return_value="/usr/bin/kubectl"),
        patch("subprocess.run", side_effect=_mock_kubectl_inferenceservice),
    ):
        from agent_bom.cloud.coreweave import discover

        agents, _ = discover()
        is_agents = [a for a in agents if a.source == "coreweave-inference"]
        assert len(is_agents) == 1
        agent = is_agents[0]
        assert "llama-70b" in agent.name
        assert agent.metadata["runtime"] == "vllm"
        assert agent.metadata["serving_url"] == "https://llama-70b.inference.coreweave.cloud"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. NVIDIA NIM container detection
# ═══════════════════════════════════════════════════════════════════════════════

_NIM_POD_JSON = json.dumps(
    {
        "items": [
            {
                "metadata": {"name": "nim-llama3-pod", "namespace": "inference"},
                "spec": {
                    "containers": [
                        {
                            "name": "nim",
                            "image": "nvcr.io/nim/meta/llama3-70b-instruct:1.0.0",
                            "resources": {
                                "limits": {"nvidia.com/gpu": "4"},
                            },
                        }
                    ]
                },
            }
        ]
    }
)


def _mock_kubectl_nim(cmd, **kwargs):
    if _CRD_VIRTUALSERVER in cmd:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")
    if _CRD_INFERENCESERVICE in cmd:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")
    if "pods" in cmd:
        return subprocess.CompletedProcess(cmd, 0, stdout=_NIM_POD_JSON, stderr="")
    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")


def test_nim_container_detection():
    """NVIDIA NIM containers (nvcr.io/nim/*) should be detected with is_nim metadata."""
    with (
        patch("shutil.which", return_value="/usr/bin/kubectl"),
        patch("subprocess.run", side_effect=_mock_kubectl_nim),
    ):
        from agent_bom.cloud.coreweave import discover

        agents, _ = discover()
        # GPU pod pass finds it
        gpu_agents = [a for a in agents if a.metadata.get("is_nim")]
        assert len(gpu_agents) >= 1
        agent = gpu_agents[0]
        assert agent.metadata["is_nim"] is True
        assert agent.metadata["nim_model"] == "meta/llama3-70b-instruct"
        assert agent.metadata["gpu_count"] == 4


# ═══════════════════════════════════════════════════════════════════════════════
# 6. InfiniBand training job detection
# ═══════════════════════════════════════════════════════════════════════════════

_IB_POD_JSON = json.dumps(
    {
        "items": [
            {
                "metadata": {"name": "nccl-train-worker-0", "namespace": "training"},
                "spec": {
                    "containers": [
                        {
                            "name": "trainer",
                            "image": "my-org/nccl-benchmarks:latest",
                            "resources": {
                                "limits": {
                                    "nvidia.com/gpu": "8",
                                    "rdma/ib": "1",
                                },
                            },
                        }
                    ]
                },
            }
        ]
    }
)


def _mock_kubectl_ib(cmd, **kwargs):
    if _CRD_VIRTUALSERVER in cmd:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")
    if _CRD_INFERENCESERVICE in cmd:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")
    if "pods" in cmd:
        return subprocess.CompletedProcess(cmd, 0, stdout=_IB_POD_JSON, stderr="")
    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")


def test_infiniband_training_detection():
    """Pods with rdma/ib resources should be detected as InfiniBand training jobs."""
    with (
        patch("shutil.which", return_value="/usr/bin/kubectl"),
        patch("subprocess.run", side_effect=_mock_kubectl_ib),
    ):
        from agent_bom.cloud.coreweave import discover

        agents, _ = discover()
        ib_agents = [a for a in agents if a.metadata.get("infiniband")]
        assert len(ib_agents) == 1
        agent = ib_agents[0]
        assert agent.metadata["training_job"] is True
        assert agent.metadata["infiniband"] is True
        assert agent.metadata["gpu_count"] == 8
        assert agent.source == "coreweave-training"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. NIM InferenceService detection
# ═══════════════════════════════════════════════════════════════════════════════

_NIM_INFERENCESERVICE_JSON = json.dumps(
    {
        "items": [
            {
                "metadata": {"name": "nim-llama3", "namespace": "production"},
                "spec": {
                    "predictor": {
                        "containers": [
                            {
                                "name": "nim-container",
                                "image": "nvcr.io/nim/meta/llama3-8b-instruct:1.0.0",
                            }
                        ]
                    }
                },
                "status": {"url": "https://nim-llama3.production.coreweave.cloud"},
            }
        ]
    }
)


def _mock_kubectl_nim_isvc(cmd, **kwargs):
    if _CRD_VIRTUALSERVER in cmd:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")
    if _CRD_INFERENCESERVICE in cmd:
        return subprocess.CompletedProcess(cmd, 0, stdout=_NIM_INFERENCESERVICE_JSON, stderr="")
    if "pods" in cmd:
        return subprocess.CompletedProcess(cmd, 0, stdout=_EMPTY_JSON, stderr="")
    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")


def test_nim_inferenceservice_detection():
    """InferenceServices using NIM images should have is_nim metadata."""
    with (
        patch("shutil.which", return_value="/usr/bin/kubectl"),
        patch("subprocess.run", side_effect=_mock_kubectl_nim_isvc),
    ):
        from agent_bom.cloud.coreweave import discover

        agents, _ = discover()
        is_agents = [a for a in agents if a.source == "coreweave-inference"]
        assert len(is_agents) == 1
        assert is_agents[0].metadata["is_nim"] is True
        assert is_agents[0].metadata["nim_model"] == "meta/llama3-8b-instruct"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Context and namespace forwarding
# ═══════════════════════════════════════════════════════════════════════════════


def test_context_forwarded_to_kubectl():
    """kubectl --context should be passed when context is specified."""
    captured_cmds: list[list[str]] = []

    def capture_run(cmd, **kwargs):
        captured_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")

    with (
        patch("shutil.which", return_value="/usr/bin/kubectl"),
        patch("subprocess.run", side_effect=capture_run),
    ):
        from agent_bom.cloud.coreweave import discover

        discover(context="coreweave-prod")

    assert any("--context" in cmd and "coreweave-prod" in cmd for cmd in captured_cmds)


def test_namespace_forwarded_to_kubectl():
    """kubectl -n should be passed when namespace is specified."""
    captured_cmds: list[list[str]] = []

    def capture_run(cmd, **kwargs):
        captured_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")

    with (
        patch("shutil.which", return_value="/usr/bin/kubectl"),
        patch("subprocess.run", side_effect=capture_run),
    ):
        from agent_bom.cloud.coreweave import discover

        discover(namespace="ml-team")

    assert any("-n" in cmd and "ml-team" in cmd for cmd in captured_cmds)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. CLI integration
# ═══════════════════════════════════════════════════════════════════════════════


def test_cli_coreweave_flags():
    """CLI scan command should have --coreweave flags."""
    from click.testing import CliRunner

    from agent_bom.cli import scan

    runner = CliRunner()
    result = runner.invoke(scan, ["--help"])
    assert "--coreweave" in result.output
    assert "--coreweave-context" in result.output
    assert "--coreweave-namespace" in result.output


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Serving runtime detection
# ═══════════════════════════════════════════════════════════════════════════════


def test_detect_serving_runtime():
    """Serving runtime detection should identify vLLM, Triton, TGI, NIM."""
    from agent_bom.cloud.coreweave import _detect_serving_runtime

    assert _detect_serving_runtime("vllm/vllm-openai:0.4.0", "server") == "vllm"
    assert _detect_serving_runtime("nvcr.io/nvidia/tritonserver:24.03", "triton") == "triton"
    assert _detect_serving_runtime("ghcr.io/huggingface/text-generation-inference:2.0", "tgi") == "tgi"
    assert _detect_serving_runtime("nvcr.io/nim/meta/llama3:1.0", "nim") == "nim"
    assert _detect_serving_runtime("custom/image:latest", "server") == ""


# ═══════════════════════════════════════════════════════════════════════════════
# 11. pyproject.toml optional dep
# ═══════════════════════════════════════════════════════════════════════════════


def test_pyproject_has_coreweave_extra():
    """pyproject.toml should have coreweave in optional-dependencies."""
    from pathlib import Path

    content = (Path(__file__).parent.parent / "pyproject.toml").read_text()
    assert "coreweave" in content
