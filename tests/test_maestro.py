"""Tests for maestro.py — MAESTRO KC1-KC6 layer tagging."""

from __future__ import annotations

import pytest

from agent_bom.maestro import (
    LAYER_DESCRIPTIONS,
    MaestroLayer,
    layer_label,
    layer_labels,
    tag_aisvs_check,
    tag_by_source,
    tag_cis_check,
    tag_provenance_result,
    tag_vector_db,
)

# ---------------------------------------------------------------------------
# MaestroLayer enum values
# ---------------------------------------------------------------------------


def test_all_six_layers_exist():
    layers = list(MaestroLayer)
    assert len(layers) == 6


def test_layer_values():
    assert MaestroLayer.KC1_AI_MODELS == "KC1: AI Models"
    assert MaestroLayer.KC4_MEMORY_CONTEXT == "KC4: Memory & Context"
    assert MaestroLayer.KC5_TOOLS_CAPABILITIES == "KC5: Tools & Capabilities"
    assert MaestroLayer.KC6_INFRASTRUCTURE == "KC6: Infrastructure"


def test_layer_descriptions_complete():
    for layer in MaestroLayer:
        assert layer in LAYER_DESCRIPTIONS
        assert LAYER_DESCRIPTIONS[layer]


# ---------------------------------------------------------------------------
# tag_by_source
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source, expected",
    [
        ("huggingface", MaestroLayer.KC1_AI_MODELS),
        ("ollama", MaestroLayer.KC1_AI_MODELS),
        ("model_file", MaestroLayer.KC1_AI_MODELS),
        ("model_provenance", MaestroLayer.KC1_AI_MODELS),
        ("blast_radius", MaestroLayer.KC2_AGENT_ARCHITECTURE),
        ("agent", MaestroLayer.KC2_AGENT_ARCHITECTURE),
        ("tool_drift", MaestroLayer.KC3_AGENTIC_PATTERNS),
        ("prompt_injection", MaestroLayer.KC3_AGENTIC_PATTERNS),
        ("vector_db", MaestroLayer.KC4_MEMORY_CONTEXT),
        ("qdrant", MaestroLayer.KC4_MEMORY_CONTEXT),
        ("weaviate", MaestroLayer.KC4_MEMORY_CONTEXT),
        ("chroma", MaestroLayer.KC4_MEMORY_CONTEXT),
        ("milvus", MaestroLayer.KC4_MEMORY_CONTEXT),
        ("pinecone", MaestroLayer.KC4_MEMORY_CONTEXT),
        ("mcp_server", MaestroLayer.KC5_TOOLS_CAPABILITIES),
        ("mcp_tool", MaestroLayer.KC5_TOOLS_CAPABILITIES),
        ("cis", MaestroLayer.KC6_INFRASTRUCTURE),
        ("aws_cis", MaestroLayer.KC6_INFRASTRUCTURE),
        ("azure_cis", MaestroLayer.KC6_INFRASTRUCTURE),
        ("gcp_cis", MaestroLayer.KC6_INFRASTRUCTURE),
        ("container", MaestroLayer.KC6_INFRASTRUCTURE),
    ],
)
def test_tag_by_source_known(source, expected):
    assert tag_by_source(source) == expected


def test_tag_by_source_unknown_defaults_to_kc6():
    assert tag_by_source("unknown_source_xyz") == MaestroLayer.KC6_INFRASTRUCTURE


def test_tag_by_source_case_insensitive():
    assert tag_by_source("HUGGINGFACE") == MaestroLayer.KC1_AI_MODELS
    assert tag_by_source("MCP_SERVER") == MaestroLayer.KC5_TOOLS_CAPABILITIES


# ---------------------------------------------------------------------------
# tag_provenance_result
# ---------------------------------------------------------------------------


def test_tag_provenance_huggingface():
    class FakeResult:
        source = "huggingface"

    assert tag_provenance_result(FakeResult()) == MaestroLayer.KC1_AI_MODELS


def test_tag_provenance_ollama():
    class FakeResult:
        source = "ollama"

    assert tag_provenance_result(FakeResult()) == MaestroLayer.KC1_AI_MODELS


def test_tag_provenance_unknown_defaults_kc1():
    class FakeResult:
        source = ""

    assert tag_provenance_result(FakeResult()) == MaestroLayer.KC1_AI_MODELS


# ---------------------------------------------------------------------------
# tag_vector_db
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("db_type", ["qdrant", "weaviate", "chroma", "milvus", "pinecone"])
def test_tag_vector_db_always_kc4(db_type):
    assert tag_vector_db(db_type) == MaestroLayer.KC4_MEMORY_CONTEXT


# ---------------------------------------------------------------------------
# tag_cis_check
# ---------------------------------------------------------------------------


def test_tag_cis_check_always_kc6():
    class FakeCheck:
        pass

    assert tag_cis_check(FakeCheck()) == MaestroLayer.KC6_INFRASTRUCTURE
    assert tag_cis_check(None) == MaestroLayer.KC6_INFRASTRUCTURE


# ---------------------------------------------------------------------------
# tag_aisvs_check
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "check_id, expected",
    [
        ("AI-4.1", MaestroLayer.KC1_AI_MODELS),
        ("AI-4.2", MaestroLayer.KC1_AI_MODELS),
        ("AI-4.3", MaestroLayer.KC1_AI_MODELS),
        ("AI-5.1", MaestroLayer.KC6_INFRASTRUCTURE),
        ("AI-5.2", MaestroLayer.KC3_AGENTIC_PATTERNS),
        ("AI-6.1", MaestroLayer.KC4_MEMORY_CONTEXT),
        ("AI-6.2", MaestroLayer.KC4_MEMORY_CONTEXT),
        ("AI-7.1", MaestroLayer.KC1_AI_MODELS),
        ("AI-7.2", MaestroLayer.KC1_AI_MODELS),
        ("AI-8.1", MaestroLayer.KC5_TOOLS_CAPABILITIES),
    ],
)
def test_tag_aisvs_check_known(check_id, expected):
    assert tag_aisvs_check(check_id) == expected


def test_tag_aisvs_check_unknown_defaults_kc6():
    assert tag_aisvs_check("AI-99.9") == MaestroLayer.KC6_INFRASTRUCTURE


# ---------------------------------------------------------------------------
# layer_label / layer_labels
# ---------------------------------------------------------------------------


def test_layer_label_includes_id():
    label = layer_label(MaestroLayer.KC1_AI_MODELS)
    assert "KC1" in label
    assert "AI Models" in label


def test_layer_label_includes_description():
    label = layer_label(MaestroLayer.KC4_MEMORY_CONTEXT)
    assert "Vector" in label or "memory" in label.lower()


def test_layer_labels_returns_all():
    all_layers = list(MaestroLayer)
    labels = layer_labels(all_layers)
    assert len(labels) == len(all_layers)
    for label in labels:
        assert isinstance(label, str)
        assert len(label) > 0
