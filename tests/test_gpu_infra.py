"""Tests for GPU/AI compute infrastructure scanner (cloud/gpu_infra.py).

Covers:
- NVIDIA image prefix detection
- CUDA/cuDNN label extraction
- Docker container discovery (mocked subprocess)
- Kubernetes GPU node discovery (mocked kubectl)
- DCGM endpoint probing (mocked HTTP)
- GpuInfraReport aggregation properties
- gpu_infra_to_agents() conversion
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.cloud.gpu_infra import (
    DcgmEndpoint,
    GpuContainer,
    GpuInfraReport,
    GpuNode,
    _extract_cuda_versions,
    _is_nvidia_image,
    discover_docker_gpu_containers,
    discover_k8s_gpu_nodes,
    gpu_infra_to_agents,
    probe_dcgm_endpoint,
    scan_gpu_infra,
)

# ─── Unit: helpers ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "image,expected",
    [
        ("nvcr.io/nvidia/cuda:12.3-base", True),
        ("nvcr.io/nim/llama-3.1-8b-instruct:latest", True),
        ("nvidia/cuda:11.8-cudnn8-runtime-ubuntu20.04", True),
        ("nvidia/tritonserver:24.01-py3", True),
        ("python:3.11-slim", False),
        ("ubuntu:22.04", False),
        ("pytorch/pytorch:2.1.0-cuda11.8-cudnn8-runtime", False),  # not nvcr.io prefix
    ],
)
def test_is_nvidia_image(image, expected):
    assert _is_nvidia_image(image) == expected


@pytest.mark.parametrize(
    "labels,exp_cuda,exp_cudnn",
    [
        (
            {"com.nvidia.cuda.version": "12.3.0", "com.nvidia.cudnn.version": "8.9.0"},
            "12.3.0",
            "8.9.0",
        ),
        ({"cuda_version": "11.8"}, "11.8", None),
        ({"some.other.label": "value"}, None, None),
        ({}, None, None),
        (
            {
                "com.nvidia.cuda.version": "12.2",
                "unrelated": "x",
            },
            "12.2",
            None,
        ),
    ],
)
def test_extract_cuda_versions(labels, exp_cuda, exp_cudnn):
    cuda, cudnn = _extract_cuda_versions(labels)
    assert cuda == exp_cuda
    assert cudnn == exp_cudnn


# ─── Unit: GpuInfraReport properties ─────────────────────────────────────────


def test_gpu_infra_report_properties():
    containers = [
        GpuContainer(
            container_id="abc123",
            name="cuda-app",
            image="nvcr.io/nvidia/cuda:12.3",
            status="running",
            is_nvidia_base=True,
            cuda_version="12.3.0",
            cudnn_version=None,
            gpu_requested=True,
        ),
        GpuContainer(
            container_id="def456",
            name="vllm-server",
            image="vllm/vllm-openai:v0.4.0",
            status="running",
            is_nvidia_base=False,
            cuda_version="12.1.0",
            cudnn_version="8.9.0",
            gpu_requested=True,
        ),
    ]
    endpoints = [
        DcgmEndpoint(host="localhost", port=9400, url="http://localhost:9400/metrics", authenticated=False, gpu_count=4),
        DcgmEndpoint(host="10.0.0.5", port=9400, url="http://10.0.0.5:9400/metrics", authenticated=True, gpu_count=8),
    ]
    nodes = [GpuNode(name="gpu-node-1", gpu_capacity=8, gpu_allocatable=6, gpu_allocated=2, cuda_driver_version="525.85")]

    report = GpuInfraReport(gpu_containers=containers, dcgm_endpoints=endpoints, gpu_nodes=nodes, warnings=[])

    assert report.total_gpu_containers == 2
    assert report.nvidia_base_image_count == 1
    assert report.unauthenticated_dcgm_count == 1
    assert set(report.unique_cuda_versions) == {"12.1.0", "12.3.0"}
    summary = report.risk_summary
    assert summary["total_gpu_containers"] == 2
    assert summary["unauthenticated_dcgm"] == 1
    assert summary["gpu_k8s_nodes"] == 1


def test_gpu_infra_report_empty():
    report = GpuInfraReport(gpu_containers=[], dcgm_endpoints=[], gpu_nodes=[], warnings=[])
    assert report.total_gpu_containers == 0
    assert report.unauthenticated_dcgm_count == 0
    assert report.unique_cuda_versions == []


# ─── Unit: gpu_infra_to_agents ────────────────────────────────────────────────


def test_gpu_infra_to_agents_containers():
    containers = [
        GpuContainer(
            container_id="abc123",
            name="cuda-workload",
            image="nvcr.io/nvidia/cuda:12.3",
            status="running",
            is_nvidia_base=True,
            cuda_version="12.3.0",
            cudnn_version="8.9.0",
            gpu_requested=True,
        ),
    ]
    report = GpuInfraReport(gpu_containers=containers, dcgm_endpoints=[], gpu_nodes=[], warnings=[])
    agents = gpu_infra_to_agents(report)
    assert len(agents) == 1
    assert agents[0].name == "cuda-workload"
    assert agents[0].source == "gpu_infra"
    pkgs = agents[0].mcp_servers[0].packages
    pkg_names = [p.name for p in pkgs]
    assert "cuda-toolkit" in pkg_names
    assert "cudnn" in pkg_names


def test_gpu_infra_to_agents_k8s_nodes():
    nodes = [
        GpuNode(name="node-1", gpu_capacity=4, gpu_allocatable=4, gpu_allocated=0, cuda_driver_version="525"),
        GpuNode(name="node-2", gpu_capacity=8, gpu_allocatable=6, gpu_allocated=2, cuda_driver_version="525"),
    ]
    report = GpuInfraReport(gpu_containers=[], dcgm_endpoints=[], gpu_nodes=nodes, warnings=[])
    agents = gpu_infra_to_agents(report)
    # One synthetic k8s-gpu-cluster agent
    assert len(agents) == 1
    assert agents[0].name == "k8s-gpu-cluster"
    assert "12 GPUs" in agents[0].mcp_servers[0].name


def test_gpu_infra_to_agents_no_cuda_version():
    """Container without CUDA version produces agent with no packages."""
    containers = [
        GpuContainer(
            container_id="xyz",
            name="gpu-app",
            image="myapp:latest",
            status="running",
            is_nvidia_base=False,
            cuda_version=None,
            cudnn_version=None,
            gpu_requested=True,
        ),
    ]
    report = GpuInfraReport(gpu_containers=containers, dcgm_endpoints=[], gpu_nodes=[], warnings=[])
    agents = gpu_infra_to_agents(report)
    assert len(agents) == 1
    assert agents[0].mcp_servers[0].packages == []


# ─── Integration: discover_docker_gpu_containers (mocked) ─────────────────────


def _make_inspect(container_id, name, image, labels=None, env=None, runtime="runc", device_requests=None, port_bindings=None):
    return {
        "Id": container_id + "0" * 52,
        "Name": f"/{name}",
        "Config": {
            "Image": image,
            "Labels": labels or {},
            "Env": env or [],
        },
        "HostConfig": {
            "Runtime": runtime,
            "DeviceRequests": device_requests or [],
            "PortBindings": port_bindings or {},
        },
        "State": {"Status": "running"},
    }


def test_discover_docker_nvidia_runtime():
    """Containers with nvidia runtime are flagged as GPU containers."""
    container_data = [
        _make_inspect(
            "abc123",
            "vllm",
            "vllm/vllm-openai:v0.4",
            labels={"com.nvidia.cuda.version": "12.1.0"},
            runtime="nvidia",
        )
    ]

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("subprocess.run") as mock_run,
    ):
        # First call: docker ps
        ps_result = MagicMock()
        ps_result.returncode = 0
        ps_result.stdout = "abc123" + "0" * 52 + "\n"

        # Second call: docker inspect
        inspect_result = MagicMock()
        inspect_result.returncode = 0
        inspect_result.stdout = json.dumps(container_data)

        mock_run.side_effect = [ps_result, inspect_result]

        containers, warnings = discover_docker_gpu_containers()

    assert len(containers) == 1
    assert containers[0].cuda_version == "12.1.0"
    assert containers[0].gpu_requested is True
    assert containers[0].is_nvidia_base is False
    assert not warnings


def test_discover_docker_nvidia_base_image():
    """NVIDIA base image containers are discovered even without runtime flag."""
    container_data = [_make_inspect("ccc123", "cuda-app", "nvcr.io/nvidia/cuda:12.3-base")]

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("subprocess.run") as mock_run,
    ):
        ps_result = MagicMock()
        ps_result.returncode = 0
        ps_result.stdout = "ccc123" + "0" * 52 + "\n"

        inspect_result = MagicMock()
        inspect_result.returncode = 0
        inspect_result.stdout = json.dumps(container_data)

        mock_run.side_effect = [ps_result, inspect_result]

        containers, warnings = discover_docker_gpu_containers()

    assert len(containers) == 1
    assert containers[0].is_nvidia_base is True


def test_discover_docker_non_gpu_container_excluded():
    """Regular Python containers without GPU are not included."""
    container_data = [_make_inspect("ddd123", "webapp", "python:3.11-slim")]

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("subprocess.run") as mock_run,
    ):
        ps_result = MagicMock()
        ps_result.returncode = 0
        ps_result.stdout = "ddd123" + "0" * 52 + "\n"

        inspect_result = MagicMock()
        inspect_result.returncode = 0
        inspect_result.stdout = json.dumps(container_data)

        mock_run.side_effect = [ps_result, inspect_result]

        containers, _ = discover_docker_gpu_containers()

    assert containers == []


def test_discover_docker_not_installed():
    """Returns empty list with warning when docker is not on PATH."""
    with patch("shutil.which", return_value=None):
        containers, warnings = discover_docker_gpu_containers()

    assert containers == []
    assert any("docker" in w.lower() for w in warnings)


def test_discover_docker_ps_fails():
    """Returns empty list with warning when docker ps fails."""
    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("subprocess.run") as mock_run,
    ):
        ps_result = MagicMock()
        ps_result.returncode = 1
        ps_result.stdout = ""
        mock_run.return_value = ps_result

        containers, warnings = discover_docker_gpu_containers()

    assert containers == []
    assert len(warnings) >= 1


def test_discover_docker_env_var_cuda():
    """CUDA version from CUDA_VERSION env var is captured."""
    container_data = [
        _make_inspect(
            "eee123",
            "torch-app",
            "pytorch/pytorch:latest",
            env=["CUDA_VERSION=11.8.0", "PATH=/usr/bin"],
            device_requests=[{"Driver": "nvidia", "Capabilities": [["gpu"]]}],
        )
    ]

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("subprocess.run") as mock_run,
    ):
        ps_result = MagicMock()
        ps_result.returncode = 0
        ps_result.stdout = "eee123" + "0" * 52 + "\n"

        inspect_result = MagicMock()
        inspect_result.returncode = 0
        inspect_result.stdout = json.dumps(container_data)

        mock_run.side_effect = [ps_result, inspect_result]

        containers, _ = discover_docker_gpu_containers()

    assert len(containers) == 1
    assert containers[0].cuda_version == "11.8.0"


# ─── Integration: discover_k8s_gpu_nodes (mocked) ────────────────────────────


def _make_node(name, gpu_capacity, gpu_allocatable, cuda_driver=None):
    labels = {
        "kubernetes.io/hostname": name,
    }
    if cuda_driver:
        major, minor = (cuda_driver.split(".") + ["0"])[:2]
        labels["nvidia.com/cuda.driver.major"] = major
        labels["nvidia.com/cuda.driver.minor"] = minor

    return {
        "metadata": {"name": name, "labels": labels},
        "status": {
            "capacity": {"nvidia.com/gpu": str(gpu_capacity), "cpu": "32"},
            "allocatable": {"nvidia.com/gpu": str(gpu_allocatable), "cpu": "32"},
        },
    }


def test_discover_k8s_gpu_nodes():
    node_list = {
        "items": [
            _make_node("gpu-node-1", 8, 6, cuda_driver="525.85"),
            _make_node("cpu-node-1", 0, 0),  # not a GPU node
        ]
    }

    with (
        patch("shutil.which", return_value="/usr/bin/kubectl"),
        patch("subprocess.run") as mock_run,
    ):
        result = MagicMock()
        result.returncode = 0
        result.stdout = json.dumps(node_list)
        mock_run.return_value = result

        nodes, warnings = discover_k8s_gpu_nodes()

    assert len(nodes) == 1
    assert nodes[0].name == "gpu-node-1"
    assert nodes[0].gpu_capacity == 8
    assert nodes[0].gpu_allocatable == 6
    assert nodes[0].gpu_allocated == 2
    assert "525" in (nodes[0].cuda_driver_version or "")


def test_discover_k8s_no_gpu_nodes():
    """Cluster with no GPU nodes returns empty list."""
    node_list = {
        "items": [
            _make_node("cpu-node-1", 0, 0),
            _make_node("cpu-node-2", 0, 0),
        ]
    }

    with (
        patch("shutil.which", return_value="/usr/bin/kubectl"),
        patch("subprocess.run") as mock_run,
    ):
        result = MagicMock()
        result.returncode = 0
        result.stdout = json.dumps(node_list)
        mock_run.return_value = result

        nodes, _ = discover_k8s_gpu_nodes()

    assert nodes == []


def test_discover_k8s_kubectl_missing():
    with patch("shutil.which", return_value=None):
        nodes, warnings = discover_k8s_gpu_nodes()

    assert nodes == []
    assert any("kubectl" in w.lower() for w in warnings)


# ─── Integration: probe_dcgm_endpoint (mocked HTTP) ──────────────────────────

_DCGM_SAMPLE_METRICS = """\
# HELP DCGM_FI_DEV_GPU_TEMP GPU temperature (in C).
# TYPE DCGM_FI_DEV_GPU_TEMP gauge
DCGM_FI_DEV_GPU_TEMP{gpu="0",UUID="GPU-abc"} 45
DCGM_FI_DEV_COUNT{} 4
DCGM_FI_DEV_GPU_UTIL{gpu="0"} 87
"""


@pytest.mark.asyncio
async def test_probe_dcgm_unauthenticated():
    """DCGM endpoint returning metrics without auth is flagged unauthenticated."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = _DCGM_SAMPLE_METRICS

    with patch("agent_bom.cloud.gpu_infra.create_client") as mock_client:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=None)
        mock_client.return_value = mock_http

        with patch("agent_bom.cloud.gpu_infra.request_with_retry", return_value=mock_resp):
            ep = await probe_dcgm_endpoint("localhost", 9400)

    assert ep is not None
    assert ep.authenticated is False
    assert ep.gpu_count == 4
    assert "DCGM_FI_DEV_GPU_TEMP" in ep.sample_metric_keys


@pytest.mark.asyncio
async def test_probe_dcgm_not_found():
    """Non-DCGM endpoint returns None."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "# HELP some_other_metric\n"

    with patch("agent_bom.cloud.gpu_infra.create_client") as mock_client:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=None)
        mock_client.return_value = mock_http

        with patch("agent_bom.cloud.gpu_infra.request_with_retry", return_value=mock_resp):
            ep = await probe_dcgm_endpoint("localhost", 9400)

    assert ep is None


@pytest.mark.asyncio
async def test_probe_dcgm_connection_refused():
    """Connection failure returns None without raising."""
    with patch("agent_bom.cloud.gpu_infra.create_client") as mock_client:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=None)
        mock_client.return_value = mock_http

        with patch("agent_bom.cloud.gpu_infra.request_with_retry", side_effect=Exception("Connection refused")):
            ep = await probe_dcgm_endpoint("localhost", 9400)

    assert ep is None


# ─── Integration: scan_gpu_infra (mocked end-to-end) ─────────────────────────


@pytest.mark.asyncio
async def test_scan_gpu_infra_empty():
    """scan_gpu_infra with no Docker/K8s returns empty report."""
    with (
        patch("agent_bom.cloud.gpu_infra.discover_docker_gpu_containers", return_value=([], ["Docker not running"])),
        patch("agent_bom.cloud.gpu_infra.discover_k8s_gpu_nodes", return_value=([], ["kubectl missing"])),
        patch("agent_bom.cloud.gpu_infra.probe_dcgm_from_containers", return_value=[]),
    ):
        report = await scan_gpu_infra()

    assert report.total_gpu_containers == 0
    assert report.gpu_nodes == []
    assert report.dcgm_endpoints == []
    assert len(report.warnings) >= 1


@pytest.mark.asyncio
async def test_scan_gpu_infra_with_containers():
    """scan_gpu_infra aggregates containers and nodes into report."""
    containers = [
        GpuContainer(
            container_id="abc",
            name="cuda-app",
            image="nvcr.io/nvidia/cuda:12.3",
            status="running",
            is_nvidia_base=True,
            cuda_version="12.3.0",
            cudnn_version=None,
            gpu_requested=True,
        )
    ]
    nodes = [GpuNode(name="node-1", gpu_capacity=4, gpu_allocatable=4, gpu_allocated=0, cuda_driver_version="525")]

    with (
        patch("agent_bom.cloud.gpu_infra.discover_docker_gpu_containers", return_value=(containers, [])),
        patch("agent_bom.cloud.gpu_infra.discover_k8s_gpu_nodes", return_value=(nodes, [])),
        patch("agent_bom.cloud.gpu_infra.probe_dcgm_from_containers", return_value=[]),
    ):
        report = await scan_gpu_infra()

    assert report.total_gpu_containers == 1
    assert len(report.gpu_nodes) == 1
    assert report.unique_cuda_versions == ["12.3.0"]
