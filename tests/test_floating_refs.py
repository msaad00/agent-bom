from __future__ import annotations

from agent_bom.floating_refs import classify_image_reference, classify_model_revision


def test_classify_image_reference_flags_latest_and_missing_tag():
    latest = classify_image_reference("mcp/playwright:latest")
    implicit = classify_image_reference("mcp/github")

    assert latest is not None
    assert latest.reason == "moving tag 'latest'"
    assert implicit is not None
    assert implicit.reason == "implicit latest tag"


def test_classify_image_reference_allows_digest_and_version_tag():
    assert classify_image_reference("mcp/playwright@sha256:" + "a" * 64) is None
    assert classify_image_reference("mcp/playwright:1.2.3") is None


def test_classify_model_revision_flags_main_not_commit():
    floating = classify_model_revision("meta-llama/Llama-3", "main")

    assert floating is not None
    assert floating.type == "FLOATING_MODEL_REFERENCE"
    assert classify_model_revision("meta-llama/Llama-3", "a" * 40) is None
