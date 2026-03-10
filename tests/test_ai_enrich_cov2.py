"""Tests for agent_bom.ai_enrich to improve coverage."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

from agent_bom.ai_enrich import (
    _ai_cache_put,
    _cache_key,
    _check_huggingface,
    _check_litellm,
    _detect_ollama,
    _get_ollama_models,
    _has_any_provider,
    _parse_json_response,
    _resolve_model,
)

# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------


def test_check_litellm():
    result = _check_litellm()
    assert isinstance(result, bool)


def test_check_huggingface():
    result = _check_huggingface()
    assert isinstance(result, bool)


def test_detect_ollama_not_running():
    import httpx

    with patch("agent_bom.ai_enrich.httpx.get", side_effect=httpx.ConnectError("refused")):
        assert _detect_ollama() is False


def test_detect_ollama_running():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("agent_bom.ai_enrich.httpx.get", return_value=mock_resp):
        assert _detect_ollama() is True


def test_get_ollama_models_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"models": [{"name": "llama3.2"}]}
    with patch("agent_bom.ai_enrich.httpx.get", return_value=mock_resp):
        models = _get_ollama_models()
        assert "llama3.2" in models


def test_get_ollama_models_failure():
    import httpx

    with patch("agent_bom.ai_enrich.httpx.get", side_effect=httpx.ConnectError("refused")):
        assert _get_ollama_models() == []


def test_resolve_model_ollama():
    """When Ollama is running with a preferred model."""
    with (
        patch("agent_bom.ai_enrich._detect_ollama", return_value=True),
        patch("agent_bom.ai_enrich._get_ollama_models", return_value=["llama3.2"]),
    ):
        model = _resolve_model()
        assert "ollama" in model or "llama" in model


def test_resolve_model_huggingface():
    """When HF_TOKEN is set."""
    with (
        patch("agent_bom.ai_enrich._detect_ollama", return_value=False),
        patch("agent_bom.ai_enrich._check_huggingface", return_value=True),
        patch.dict(os.environ, {"HF_TOKEN": "hf_test"}),
    ):
        model = _resolve_model()
        assert "huggingface" in model


def test_resolve_model_openai():
    """When OPENAI_API_KEY is set."""
    with (
        patch("agent_bom.ai_enrich._detect_ollama", return_value=False),
        patch("agent_bom.ai_enrich._check_huggingface", return_value=False),
        patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False),
    ):
        model = _resolve_model()
        assert "openai" in model


def test_resolve_model_fallback():
    """No providers available — fallback."""
    with (
        patch("agent_bom.ai_enrich._detect_ollama", return_value=False),
        patch("agent_bom.ai_enrich._check_huggingface", return_value=False),
    ):
        env = {k: v for k, v in os.environ.items() if k not in ("OPENAI_API_KEY", "HF_TOKEN")}
        with patch.dict(os.environ, env, clear=True):
            model = _resolve_model()
            assert model is not None


# ---------------------------------------------------------------------------
# _has_any_provider
# ---------------------------------------------------------------------------


def test_has_any_provider_ollama():
    with patch("agent_bom.ai_enrich._detect_ollama", return_value=True):
        assert _has_any_provider("ollama/llama3.2") is True


def test_has_any_provider_none():
    with (
        patch("agent_bom.ai_enrich._detect_ollama", return_value=False),
        patch("agent_bom.ai_enrich._check_litellm", return_value=False),
        patch("agent_bom.ai_enrich._check_huggingface", return_value=False),
    ):
        assert _has_any_provider("openai/gpt-4") is False


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_ai_cache_put():
    _ai_cache_put("test_key", "test_value")
    # Just verify no error


def test_cache_key():
    key = _cache_key("prompt text", "model-name")
    assert isinstance(key, str)
    assert len(key) > 0


# ---------------------------------------------------------------------------
# _parse_json_response
# ---------------------------------------------------------------------------


def test_parse_json_response_clean():
    result = _parse_json_response('{"key": "value"}')
    assert result == {"key": "value"}


def test_parse_json_response_fenced():
    result = _parse_json_response('Here is the result:\n```json\n{"key": "value"}\n```')
    assert result == {"key": "value"}


def test_parse_json_response_embedded():
    result = _parse_json_response('Some text before {"key": "value"} and after')
    assert result == {"key": "value"}


def test_parse_json_response_none():
    assert _parse_json_response("") is None
    assert _parse_json_response(None) is None


def test_parse_json_response_not_dict():
    assert _parse_json_response("[1, 2, 3]") is None


def test_parse_json_response_invalid():
    assert _parse_json_response("not json at all") is None
