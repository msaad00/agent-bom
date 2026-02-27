"""Tests for HuggingFace model card content parsing."""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.cloud.huggingface import _parse_model_card


def _make_model(**kwargs):
    """Create a mock model info object with the given attributes."""
    return SimpleNamespace(**kwargs)


def test_parse_model_card_empty():
    """Empty model info returns empty dict."""
    model = _make_model()
    meta = _parse_model_card(model)
    assert meta == {}


def test_parse_model_card_pipeline_tag():
    """Pipeline tag is extracted from model info."""
    model = _make_model(pipeline_tag="text-generation")
    meta = _parse_model_card(model)
    assert meta["pipeline_tag"] == "text-generation"


def test_parse_model_card_tags():
    """Tags are extracted from model info."""
    model = _make_model(tags=["pytorch", "transformers", "llama"])
    meta = _parse_model_card(model)
    assert meta["tags"] == ["pytorch", "transformers", "llama"]


def test_parse_model_card_downloads_likes():
    """Downloads and likes are extracted."""
    model = _make_model(downloads=50000, likes=120)
    meta = _parse_model_card(model)
    assert meta["downloads"] == 50000
    assert meta["likes"] == 120


def test_parse_model_card_with_card_data():
    """Card data (YAML frontmatter) is parsed when available."""
    card_data = SimpleNamespace(
        license="apache-2.0",
        datasets=["openwebtext", "c4"],
        language=["en", "fr"],
        model_index=None,
    )
    model = _make_model(card_data=card_data, pipeline_tag="text-generation")
    meta = _parse_model_card(model)
    assert meta["license"] == "apache-2.0"
    assert meta["datasets"] == ["openwebtext", "c4"]
    assert meta["language"] == ["en", "fr"]
    assert meta["pipeline_tag"] == "text-generation"


def test_parse_model_card_with_eval_metrics():
    """Evaluation metrics from model-index are extracted."""
    metric = SimpleNamespace(name="accuracy", type="accuracy", value=0.95)
    result = SimpleNamespace(metrics=[metric])
    model_idx_entry = SimpleNamespace(results=[result])
    card_data = SimpleNamespace(
        license=None,
        datasets=None,
        language=None,
        model_index=[model_idx_entry],
    )
    model = _make_model(card_data=card_data)
    meta = _parse_model_card(model)
    assert "eval_metrics" in meta
    assert len(meta["eval_metrics"]) == 1
    assert meta["eval_metrics"][0]["name"] == "accuracy"
    assert meta["eval_metrics"][0]["value"] == 0.95


def test_parse_model_card_no_card_data():
    """Model without card_data only extracts top-level fields."""
    model = _make_model(card_data=None, pipeline_tag="fill-mask", downloads=100)
    meta = _parse_model_card(model)
    assert meta["pipeline_tag"] == "fill-mask"
    assert meta["downloads"] == 100
    assert "license" not in meta
    assert "datasets" not in meta
