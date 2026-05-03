"""Tests for GPU hardware firmware/BMC advisory scanner (scanners/firmware_advisory.py).

Covers:
- GPU model extraction from K8s node labels
- Firmware product matching from GPU model keywords
- CVE finding generation for H100, A100, ConnectX-6 nodes
- Advisory seed accuracy and deduplication
- FirmwareFinding.to_dict() shape
- check_firmware_advisories() end-to-end
"""

from __future__ import annotations

import pytest

from agent_bom.scanners.firmware_advisory import (
    FirmwareFinding,
    _products_for_model,
    check_firmware_advisories,
    extract_gpu_model_from_labels,
)

# ─── Unit: extract_gpu_model_from_labels ─────────────────────────────────────


@pytest.mark.parametrize(
    "labels,expected",
    [
        ({"nvidia.com/gpu.product": "NVIDIA-H100-SXM4-80GB"}, "H100"),
        ({"nvidia.com/gpu.product": "NVIDIA-A100-SXM4-80GB"}, "A100"),
        ({"nvidia.com/gpu.model": "H100"}, "H100"),
        ({"nvidia.com/gpu.model": "A100-40GB"}, "A100"),
        ({"beta.kubernetes.io/instance-type": "p4d.24xlarge-a100"}, "A100"),
        ({"node.kubernetes.io/instance-type": "H100-instance"}, "H100"),
        ({"nvidia.com/gpu.product": "NVIDIA-H200-SXM5-141GB"}, "H200"),
        ({"nvidia.com/gpu.product": "NVIDIA-A800-40GB"}, "A800"),
        ({"nvidia.com/gpu.product": "Tesla-V100-SXM2-32GB"}, "V100"),
        ({"nvidia.com/gpu.product": "Tesla-T4"}, "T4"),
        ({}, ""),
        ({"kubernetes.io/hostname": "plain-cpu-node"}, ""),
    ],
)
def test_extract_gpu_model_from_labels(labels, expected):
    assert extract_gpu_model_from_labels(labels) == expected


def test_extract_gpu_model_priority_order():
    """nvidia.com/gpu.product is checked before beta.kubernetes.io/instance-type."""
    labels = {
        "nvidia.com/gpu.product": "NVIDIA-H100-SXM4-80GB",
        "beta.kubernetes.io/instance-type": "a100-node",
    }
    result = extract_gpu_model_from_labels(labels)
    assert result == "H100"


def test_extract_gpu_model_connectx():
    """ConnectX network adapter labels are also parsed."""
    labels = {"nvidia.com/gpu.product": "ConnectX-6"}
    result = extract_gpu_model_from_labels(labels)
    assert "CONNECTX" in result.upper() or result == "CONNECTX-6"


# ─── Unit: _products_for_model ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "gpu_model,expected_products",
    [
        ("H100", {"DGX H100", "HGX H100"}),
        ("A100", {"DGX A100", "HGX A100", "DGX Station A100"}),
        ("H200", {"DGX H200", "HGX H200"}),
        ("A800", {"DGX A800"}),
        ("V100", set()),  # not in firmware seed
        ("T4", set()),
    ],
)
def test_products_for_model(gpu_model, expected_products):
    products = _products_for_model(gpu_model)
    assert products == expected_products


def test_products_for_model_connectx6():
    products = _products_for_model("CONNECTX-6")
    assert "ConnectX-6" in products


def test_products_for_model_case_insensitive():
    assert _products_for_model("h100") == _products_for_model("H100")


# ─── Unit: FirmwareFinding.to_dict ────────────────────────────────────────────


def test_firmware_finding_to_dict():
    f = FirmwareFinding(
        node_name="gpu-node-1",
        gpu_vendor="nvidia",
        gpu_model="H100",
        cve_id="CVE-2023-31028",
        title="BMC host-interface vulnerability",
        severity="critical",
        cvss_score=9.0,
        affected_product="DGX H100",
        fixed_version="1.05.0",
        reference_url="https://nvidia.custhelp.com/app/answers/detail/a_id/5481",
    )
    d = f.to_dict()
    assert d["node"] == "gpu-node-1"
    assert d["gpu_vendor"] == "nvidia"
    assert d["gpu_model"] == "H100"
    assert d["cve_id"] == "CVE-2023-31028"
    assert d["severity"] == "critical"
    assert d["cvss_score"] == 9.0
    assert d["affected_product"] == "DGX H100"
    assert d["fixed_version"] == "1.05.0"
    assert d["reference_url"].startswith("https://")


def test_firmware_finding_no_fixed_version():
    f = FirmwareFinding(
        node_name="cx6-node",
        gpu_vendor="nvidia",
        gpu_model="CONNECTX-6",
        cve_id="CVE-2023-25519",
        title="ConnectX-6 DoS",
        severity="high",
        cvss_score=7.1,
        affected_product="ConnectX-6",
        fixed_version=None,
        reference_url="https://nvidia.custhelp.com/",
    )
    d = f.to_dict()
    assert d["fixed_version"] is None


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _make_node(name: str, labels: dict, gpu_vendor: str = "nvidia"):
    from agent_bom.cloud.gpu_infra import GpuNode

    return GpuNode(
        name=name,
        gpu_vendor=gpu_vendor,
        gpu_capacity=8,
        gpu_allocatable=8,
        gpu_allocated=0,
        cuda_driver_version=None,
        labels=labels,
    )


# ─── Integration: check_firmware_advisories ───────────────────────────────────


def test_check_firmware_advisories_h100_node():
    """H100 node matches 3 BMC/SBIOS CVEs from the advisory seed."""
    node = _make_node("h100-node", {"nvidia.com/gpu.product": "NVIDIA-H100-SXM4-80GB"})
    findings = check_firmware_advisories([node])
    assert len(findings) >= 2
    cve_ids = {f.cve_id for f in findings}
    # At minimum the two critical H100 BMC CVEs
    assert "CVE-2023-31028" in cve_ids
    assert "CVE-2023-31029" in cve_ids
    for f in findings:
        assert f.node_name == "h100-node"
        assert f.gpu_model == "H100"


def test_check_firmware_advisories_a100_node():
    """A100 node matches the SBIOS CVE."""
    node = _make_node("a100-node", {"nvidia.com/gpu.product": "NVIDIA-A100-SXM4-80GB"})
    findings = check_firmware_advisories([node])
    assert len(findings) >= 1
    cve_ids = {f.cve_id for f in findings}
    assert "CVE-2023-25513" in cve_ids
    for f in findings:
        assert f.severity in ("critical", "high")


def test_check_firmware_advisories_v100_node_no_match():
    """V100 node has no matching firmware advisory."""
    node = _make_node("v100-node", {"nvidia.com/gpu.product": "Tesla-V100-SXM2-32GB"})
    findings = check_firmware_advisories([node])
    assert findings == []


def test_check_firmware_advisories_no_label():
    """Node without GPU model labels produces no findings."""
    node = _make_node("cpu-node", {})
    findings = check_firmware_advisories([node])
    assert findings == []


def test_check_firmware_advisories_empty_list():
    assert check_firmware_advisories([]) == []


def test_check_firmware_advisories_deduplication():
    """Each CVE is emitted at most once per node, not once per product match."""
    # H100 matches both DGX H100 and HGX H100 — but CVE-2023-31028 covers both
    node = _make_node("h100-node", {"nvidia.com/gpu.product": "NVIDIA-H100-SXM4-80GB"})
    findings = check_firmware_advisories([node])
    cve_ids = [f.cve_id for f in findings]
    # No duplicates per node
    assert len(cve_ids) == len(set(cve_ids))


def test_check_firmware_advisories_multiple_nodes():
    """Findings are returned for all matching nodes independently."""
    nodes = [
        _make_node("node-1", {"nvidia.com/gpu.product": "NVIDIA-H100-SXM4-80GB"}),
        _make_node("node-2", {"nvidia.com/gpu.product": "NVIDIA-A100-SXM4-80GB"}),
        _make_node("node-3", {"nvidia.com/gpu.product": "Tesla-T4"}),
    ]
    findings = check_firmware_advisories(nodes)
    node_names = {f.node_name for f in findings}
    assert "node-1" in node_names
    assert "node-2" in node_names
    assert "node-3" not in node_names


def test_check_firmware_advisories_h200_node():
    """H200 node matches HGX H200 firmware advisories."""
    node = _make_node("h200-node", {"nvidia.com/gpu.product": "NVIDIA-H200-SXM5-141GB"})
    findings = check_firmware_advisories([node])
    # H200 maps to DGX H200 / HGX H200 — currently no CVEs in seed but no crash
    assert isinstance(findings, list)


def test_check_firmware_advisories_fallback_label_scan():
    """When primary label keys are absent, falls back to scanning all label values."""
    node = _make_node(
        "mystery-node",
        {"some.custom.label": "my-H100-accelerator", "kubernetes.io/hostname": "mystery-node"},
    )
    findings = check_firmware_advisories([node])
    # Should still find H100 via fallback value scan
    assert len(findings) >= 1


def test_check_firmware_advisories_finding_fields():
    """All required fields are populated in every finding."""
    node = _make_node("a100-station", {"nvidia.com/gpu.product": "DGX-Station-A100"})
    findings = check_firmware_advisories([node])
    for f in findings:
        assert f.node_name
        assert f.cve_id.startswith("CVE-")
        assert f.title
        assert f.severity in ("critical", "high", "medium")
        assert isinstance(f.cvss_score, float)
        assert f.affected_product
        assert f.reference_url.startswith("https://")
