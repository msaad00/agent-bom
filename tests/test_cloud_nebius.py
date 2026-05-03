"""Tests for agent_bom.cloud.nebius to improve coverage."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.base import CloudDiscoveryError
from agent_bom.cloud.nebius import (
    _discover_ai_studio,
    _discover_container_services,
    _discover_gpu_instances,
    _discover_infiniband_jobs,
    _discover_k8s_gpu_pods,
    _nebius_get,
    discover,
)

# ---------------------------------------------------------------------------
# _nebius_get
# ---------------------------------------------------------------------------


def test_nebius_get_success():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"data": [1, 2, 3]}
    mock_resp.status_code = 200

    with patch("requests.get", return_value=mock_resp):
        result = _nebius_get("https://api.example.com/v1/test", "api-key-123")
        assert result == {"data": [1, 2, 3]}


# ---------------------------------------------------------------------------
# discover (top level)
# ---------------------------------------------------------------------------


def test_discover_no_requests():
    import builtins

    original = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "requests":
            raise ImportError("mocked")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        with pytest.raises(CloudDiscoveryError, match="requests"):
            discover()


def test_discover_no_api_key():
    with patch.dict("os.environ", {}, clear=False):
        import os

        old_key = os.environ.pop("NEBIUS_API_KEY", None)
        old_proj = os.environ.pop("NEBIUS_PROJECT_ID", None)
        try:
            agents, warnings = discover()
            assert any("NEBIUS_API_KEY" in w for w in warnings)
        finally:
            if old_key:
                os.environ["NEBIUS_API_KEY"] = old_key
            if old_proj:
                os.environ["NEBIUS_PROJECT_ID"] = old_proj


def test_discover_no_project_id():
    import os

    old = os.environ.pop("NEBIUS_PROJECT_ID", None)
    try:
        agents, warnings = discover(api_key="test-key")
        assert any("NEBIUS_PROJECT_ID" in w for w in warnings)
    finally:
        if old:
            os.environ["NEBIUS_PROJECT_ID"] = old


def test_discover_all_subsystems():
    with (
        patch("agent_bom.cloud.nebius._discover_ai_studio", return_value=([], [])),
        patch("agent_bom.cloud.nebius._discover_gpu_instances", return_value=([], [])),
        patch("agent_bom.cloud.nebius._discover_k8s_gpu_pods", return_value=([], [])),
        patch("agent_bom.cloud.nebius._discover_container_services", return_value=([], [])),
        patch("agent_bom.cloud.nebius._discover_infiniband_jobs", return_value=([], [])),
    ):
        agents, warnings = discover(api_key="key", project_id="proj")
        assert agents == []
        assert warnings == []


def test_discover_subsystem_exception():
    with (
        patch("agent_bom.cloud.nebius._discover_ai_studio", side_effect=RuntimeError("boom")),
        patch("agent_bom.cloud.nebius._discover_gpu_instances", return_value=([], [])),
        patch("agent_bom.cloud.nebius._discover_k8s_gpu_pods", return_value=([], [])),
        patch("agent_bom.cloud.nebius._discover_container_services", return_value=([], [])),
        patch("agent_bom.cloud.nebius._discover_infiniband_jobs", return_value=([], [])),
    ):
        agents, warnings = discover(api_key="key", project_id="proj")
        assert any("AI Studio" in w for w in warnings)


# ---------------------------------------------------------------------------
# _discover_ai_studio
# ---------------------------------------------------------------------------


def test_ai_studio_success():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"models": [{"id": "m1", "name": "llama-70b", "version": "1.0", "status": "ACTIVE"}]}
    mock_resp.status_code = 200

    with patch("requests.get", return_value=mock_resp):
        agents, warnings = _discover_ai_studio("key", "proj")
        assert len(agents) == 1
        assert "llama-70b" in agents[0].name


def test_ai_studio_error():
    with patch("requests.get", side_effect=RuntimeError("network error")):
        agents, warnings = _discover_ai_studio("key", "proj")
        assert len(agents) == 0
        assert len(warnings) == 1


# ---------------------------------------------------------------------------
# _discover_gpu_instances
# ---------------------------------------------------------------------------


def test_gpu_instances_found():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "instances": [
            {
                "id": "i1",
                "name": "gpu-node-1",
                "platform_id": "gpu-h100",
                "status": "RUNNING",
                "resources": {"gpus": 4, "gpu_type": "H100"},
                "boot_disk": {"image_id": "img1", "image_name": "nvidia-cuda-ubuntu"},
            }
        ]
    }
    mock_resp.status_code = 200

    with patch("requests.get", return_value=mock_resp):
        agents, warnings = _discover_gpu_instances("key", "proj")
        assert len(agents) == 1
        assert "gpu-node-1" in agents[0].name
        assert agents[0].metadata["ai_workload"] is True


def test_gpu_instances_non_gpu_filtered():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "instances": [
            {
                "id": "i1",
                "name": "cpu-node-1",
                "platform_id": "standard-v2",
                "status": "RUNNING",
                "resources": {"gpus": 0},
                "boot_disk": {"image_id": "img", "image_name": "ubuntu"},
            }
        ]
    }
    mock_resp.status_code = 200

    with patch("requests.get", return_value=mock_resp):
        agents, warnings = _discover_gpu_instances("key", "proj")
        assert len(agents) == 0


# ---------------------------------------------------------------------------
# _discover_k8s_gpu_pods
# ---------------------------------------------------------------------------


def test_k8s_gpu_pods_no_kubectl():
    with patch("shutil.which", return_value=None):
        agents, warnings = _discover_k8s_gpu_pods("key", "proj")
        assert len(agents) == 0


def test_k8s_gpu_pods_found():
    kubectl_output = json.dumps(
        {
            "items": [
                {
                    "metadata": {"name": "train-pod", "namespace": "ml"},
                    "spec": {
                        "containers": [
                            {
                                "name": "trainer",
                                "image": "pytorch/pytorch:2.0",
                                "resources": {"limits": {"nvidia.com/gpu": "1"}},
                            }
                        ],
                        "initContainers": [],
                    },
                }
            ]
        }
    )

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = kubectl_output

    with patch("shutil.which", return_value="/usr/bin/kubectl"), patch("subprocess.run", return_value=mock_result):
        agents, warnings = _discover_k8s_gpu_pods("key", "proj")
        assert len(agents) == 1
        assert "train-pod" in agents[0].name


def test_k8s_gpu_pods_kubectl_failure():
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "error connecting"

    with patch("shutil.which", return_value="/usr/bin/kubectl"), patch("subprocess.run", return_value=mock_result):
        agents, warnings = _discover_k8s_gpu_pods("key", "proj")
        assert len(agents) == 0
        assert len(warnings) == 1


def test_k8s_gpu_pods_timeout():
    import subprocess

    with (
        patch("shutil.which", return_value="/usr/bin/kubectl"),
        patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="kubectl", timeout=60)),
    ):
        agents, warnings = _discover_k8s_gpu_pods("key", "proj")
        assert any("timed out" in w for w in warnings)


# ---------------------------------------------------------------------------
# _discover_container_services
# ---------------------------------------------------------------------------


def test_container_services_with_image():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"containers": [{"id": "c1", "name": "web-svc", "image": "nginx:latest"}]}
    mock_resp.status_code = 200

    with patch("requests.get", return_value=mock_resp):
        agents, warnings = _discover_container_services("key", "proj")
        assert len(agents) == 1


def test_container_services_no_image():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"containers": [{"id": "c1", "name": "svc-no-img", "image": ""}]}
    mock_resp.status_code = 200

    with patch("requests.get", return_value=mock_resp):
        agents, warnings = _discover_container_services("key", "proj")
        assert len(agents) == 1  # Still created, just with UNKNOWN transport


def test_container_services_error():
    with patch("requests.get", side_effect=RuntimeError("fail")):
        agents, warnings = _discover_container_services("key", "proj")
        assert len(agents) == 0
        assert len(warnings) == 1


# ---------------------------------------------------------------------------
# _discover_infiniband_jobs
# ---------------------------------------------------------------------------


def test_infiniband_jobs_no_kubectl():
    with patch("shutil.which", return_value=None):
        agents, warnings = _discover_infiniband_jobs("key", "proj")
        assert agents == []
        assert warnings == []


def test_infiniband_jobs_with_rdma_pod():
    import json

    pod_list = {
        "items": [
            {
                "metadata": {"name": "nccl-train-0", "namespace": "training"},
                "spec": {
                    "containers": [
                        {
                            "name": "trainer",
                            "image": "nvcr.io/nvidia/pytorch:24.01-py3",
                            "resources": {
                                "limits": {"rdma/ib": "1", "nvidia.com/gpu": "8"},
                                "requests": {"rdma/ib": "1", "nvidia.com/gpu": "8"},
                            },
                        }
                    ]
                },
            }
        ]
    }
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps(pod_list)

    with patch("shutil.which", return_value="/usr/bin/kubectl"), patch("subprocess.run", return_value=mock_result):
        agents, warnings = _discover_infiniband_jobs("key", "proj")
        assert len(agents) == 1
        assert agents[0].metadata.get("infiniband") is True
        assert agents[0].metadata.get("training_job") is True
        assert agents[0].metadata.get("gpu_count") == 8
        assert "nebius-training:training/nccl-train-0" in agents[0].name
        assert warnings == []


def test_infiniband_jobs_skips_non_ib_pods():
    import json

    pod_list = {
        "items": [
            {
                "metadata": {"name": "inference-pod", "namespace": "default"},
                "spec": {
                    "containers": [
                        {
                            "name": "server",
                            "image": "vllm/vllm-openai:latest",
                            "resources": {
                                "limits": {"nvidia.com/gpu": "4"},
                                "requests": {"nvidia.com/gpu": "4"},
                            },
                        }
                    ]
                },
            }
        ]
    }
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = json.dumps(pod_list)

    with patch("shutil.which", return_value="/usr/bin/kubectl"), patch("subprocess.run", return_value=mock_result):
        agents, warnings = _discover_infiniband_jobs("key", "proj")
        assert agents == []


def test_infiniband_jobs_kubectl_failure():
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "connection refused"

    with patch("shutil.which", return_value="/usr/bin/kubectl"), patch("subprocess.run", return_value=mock_result):
        agents, warnings = _discover_infiniband_jobs("key", "proj")
        assert agents == []
        assert len(warnings) == 1


def test_infiniband_jobs_timeout():
    import subprocess

    with (
        patch("shutil.which", return_value="/usr/bin/kubectl"),
        patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="kubectl", timeout=60)),
    ):
        agents, warnings = _discover_infiniband_jobs("key", "proj")
        assert any("timed out" in w for w in warnings)
