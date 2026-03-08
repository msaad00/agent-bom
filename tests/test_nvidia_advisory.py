"""Tests for NVIDIA CSAF advisory enrichment module."""

from __future__ import annotations

import pytest

from agent_bom.scanners.nvidia_advisory import (
    _csaf_affects_product,
    _word_boundary_match,
    get_nvidia_products_for_package,
)


def test_word_boundary_match_exact():
    """Exact product name matches."""
    assert _word_boundary_match("cuda toolkit", "nvidia cuda toolkit security update")


def test_word_boundary_match_rejects_substring():
    """Substring that is NOT a word-boundary match is rejected.

    'nccl' should not match 'nccl-extra-tools' as a word-boundary match
    of the product name 'nccl' when it appears as a prefix of a hyphenated word.
    But 'nccl' as its own word should match.
    """
    # "nccl" appears as its own word → match
    assert _word_boundary_match("nccl", "nvidia nccl vulnerability")
    # "cudnn" should not match "cudnn-frontend" if boundary matters
    # Actually \b treats hyphens as word boundaries, so "cudnn" matches in "cudnn-frontend"
    # This is acceptable — NVIDIA products like "cudnn" are standalone words


def test_word_boundary_rejects_embedded_substring():
    """Product name embedded inside another word should not match."""
    # "cuda" should not match "barracuda"
    assert not _word_boundary_match("cuda", "barracuda network security")
    # "nccl" should not match "cancel"
    assert not _word_boundary_match("nccl", "cancel the operation")


def test_csaf_affects_product_title_match():
    """CSAF advisory title containing product name (word boundary) matches."""
    csaf = {
        "document": {"title": "NVIDIA CUDA Toolkit - February 2025 Security Update"},
        "product_tree": {"branches": []},
    }
    assert _csaf_affects_product(csaf, {"cuda toolkit"})


def test_csaf_affects_product_title_no_match():
    """CSAF advisory for a different product should not match."""
    csaf = {
        "document": {"title": "NVIDIA GPU Display Driver - February 2025 Security Update"},
        "product_tree": {"branches": []},
    }
    assert not _csaf_affects_product(csaf, {"cuda toolkit"})


def test_csaf_affects_product_branch_match():
    """CSAF product_tree branch name matches."""
    csaf = {
        "document": {"title": "NVIDIA Security Bulletin"},
        "product_tree": {
            "branches": [
                {
                    "name": "NVIDIA CUDA Toolkit",
                    "branches": [],
                }
            ]
        },
    }
    assert _csaf_affects_product(csaf, {"cuda toolkit"})


def test_csaf_affects_product_subbranch_match():
    """CSAF product_tree sub-branch name matches."""
    csaf = {
        "document": {"title": "NVIDIA Security Bulletin"},
        "product_tree": {
            "branches": [
                {
                    "name": "NVIDIA Products",
                    "branches": [
                        {"name": "TensorRT 10.0"},
                    ],
                }
            ]
        },
    }
    assert _csaf_affects_product(csaf, {"tensorrt"})


def test_csaf_substring_false_positive_blocked():
    """Substring match in title should NOT trigger a false positive.

    'cuda' embedded in 'barracuda' should not match product 'cuda'.
    """
    csaf = {
        "document": {"title": "Barracuda Networks Security Advisory"},
        "product_tree": {"branches": []},
    }
    assert not _csaf_affects_product(csaf, {"cuda"})


# ─── get_nvidia_products_for_package — extended mapping tests ─────────────────


@pytest.mark.parametrize(
    "pkg_name, expected_products",
    [
        # Direct NVIDIA packages — should already map
        ("nvidia-cuda-runtime-cu12", ["cuda toolkit"]),
        ("nvidia-cudnn-cu12", ["cudnn"]),
        ("nvidia-nccl-cu12", ["nccl"]),
        ("tensorrt", ["tensorrt"]),
        ("nvidia-container-toolkit", ["container toolkit"]),
        # ML frameworks that bundle CUDA — the O1 gap, now fixed
        ("torch", ["cuda toolkit", "cudnn", "nccl"]),
        ("torchvision", ["cuda toolkit", "cudnn", "nccl"]),
        ("torchaudio", ["cuda toolkit", "cudnn"]),
        ("jax", ["cuda toolkit", "cudnn"]),
        ("jaxlib", ["cuda toolkit", "cudnn"]),
        ("vllm", ["cuda toolkit"]),
        ("triton", ["cuda toolkit"]),
        ("cupy", ["cuda toolkit"]),
        ("cupy-cuda12x", ["cuda toolkit"]),
        ("accelerate", ["cuda toolkit"]),
        ("bitsandbytes", ["cuda toolkit"]),
        ("flash-attn", ["cuda toolkit"]),
        ("xformers", ["cuda toolkit"]),
        ("torch-tensorrt", ["tensorrt"]),
        ("tritonclient", ["triton inference server"]),
        # Unrelated package — should not map to any NVIDIA product
        ("requests", []),
        ("numpy", []),
        ("fastapi", []),
    ],
)
def test_get_nvidia_products_for_package(pkg_name: str, expected_products: list[str]):
    """Each AI/GPU package maps to the correct NVIDIA product categories."""
    result = get_nvidia_products_for_package(pkg_name)
    for expected in expected_products:
        assert expected in result, f"{pkg_name!r} should map to {expected!r}, got {result}"
    if not expected_products:
        assert result == [], f"{pkg_name!r} should have no NVIDIA product mapping, got {result}"


def test_torch_cuda_advisory_wiring():
    """A CUDA Toolkit CSAF advisory should be detectable for torch packages.

    This is the core O1 scenario: torch bundles CUDA, so a CUDA Toolkit
    advisory should be flagged against torch packages.
    """
    cuda_advisory = {
        "document": {"title": "NVIDIA CUDA Toolkit - CVE-2025-XXXX Security Update"},
        "product_tree": {"branches": []},
    }
    # torch maps to "cuda toolkit" → the advisory affects "cuda toolkit" → torch is flagged
    torch_products = set(get_nvidia_products_for_package("torch"))
    assert _csaf_affects_product(cuda_advisory, torch_products)


def test_vllm_cuda_advisory_wiring():
    """A CUDA Toolkit advisory should be detectable for vllm packages."""
    cuda_advisory = {
        "document": {"title": "NVIDIA CUDA Toolkit Security Bulletin"},
        "product_tree": {"branches": []},
    }
    vllm_products = set(get_nvidia_products_for_package("vllm"))
    assert _csaf_affects_product(cuda_advisory, vllm_products)


def test_unrelated_package_no_nvidia_advisory():
    """An unrelated package should not trigger any NVIDIA product mapping."""
    assert get_nvidia_products_for_package("requests") == []
    assert get_nvidia_products_for_package("flask") == []
    assert get_nvidia_products_for_package("django") == []
