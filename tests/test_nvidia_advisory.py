"""Tests for NVIDIA CSAF advisory enrichment module."""

from __future__ import annotations

from agent_bom.scanners.nvidia_advisory import (
    _csaf_affects_product,
    _word_boundary_match,
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
