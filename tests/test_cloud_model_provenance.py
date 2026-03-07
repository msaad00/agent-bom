"""Tests for cloud/model_provenance.py — HF and Ollama provenance verification."""

from __future__ import annotations

import json
import types
from unittest.mock import MagicMock, patch

from agent_bom.cloud.model_provenance import (
    _LARGE_MODEL_THRESHOLD,
    _SAFE_EXTENSIONS,
    _UNSAFE_EXTENSIONS,
    ProvenanceResult,
    _get_ollama_manifest_file,
    check_hf_model,
    check_hf_models,
    check_ollama_model,
    check_ollama_models,
)

# ---------------------------------------------------------------------------
# Helpers — install fake huggingface_hub into sys.modules
# ---------------------------------------------------------------------------


def _install_mock_hf(model_info_obj, side_effect=None):
    """Install a fake huggingface_hub module and return a context manager."""
    hf_mod = types.ModuleType("huggingface_hub")
    hf_utils = types.ModuleType("huggingface_hub.utils")

    class GatedRepoError(Exception):
        pass

    class RepositoryNotFoundError(Exception):
        pass

    hf_utils.GatedRepoError = GatedRepoError
    hf_utils.RepositoryNotFoundError = RepositoryNotFoundError
    hf_mod.utils = hf_utils

    mock_api_instance = MagicMock()
    if side_effect:
        mock_api_instance.model_info.side_effect = side_effect
    else:
        mock_api_instance.model_info.return_value = model_info_obj

    mock_api_cls = MagicMock(return_value=mock_api_instance)
    hf_mod.HfApi = mock_api_cls

    return patch.dict(
        "sys.modules",
        {
            "huggingface_hub": hf_mod,
            "huggingface_hub.utils": hf_utils,
        },
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_unsafe_extensions_nonempty():
    assert ".pt" in _UNSAFE_EXTENSIONS
    assert ".pkl" in _UNSAFE_EXTENSIONS
    assert ".bin" in _UNSAFE_EXTENSIONS


def test_safe_extensions_nonempty():
    assert ".safetensors" in _SAFE_EXTENSIONS
    assert ".gguf" in _SAFE_EXTENSIONS


def test_large_model_threshold():
    assert _LARGE_MODEL_THRESHOLD == 5 * 1024**3


# ---------------------------------------------------------------------------
# ProvenanceResult model
# ---------------------------------------------------------------------------


def _make_result(**kwargs) -> ProvenanceResult:
    defaults = dict(
        model_id="test/model",
        source="huggingface",
        format="safetensors",
        is_safe_format=True,
        has_digest=True,
        digest="abc123",
        is_gated=False,
        has_model_card=True,
        risk_flags=[],
    )
    defaults.update(kwargs)
    return ProvenanceResult(**defaults)


def test_risk_level_safe():
    assert _make_result().risk_level == "safe"


def test_risk_level_high_unsafe_format_with_digest():
    r = _make_result(is_safe_format=False, has_digest=True, risk_flags=["unsafe_format:.pt"])
    assert r.risk_level == "high"


def test_risk_level_critical_unsafe_no_digest():
    r = _make_result(is_safe_format=False, has_digest=False)
    assert r.risk_level == "critical"


def test_risk_level_medium_no_digest_safe_format():
    r = _make_result(is_safe_format=True, has_digest=False)
    assert r.risk_level == "medium"


def test_risk_level_medium_with_flags():
    r = _make_result(risk_flags=["no_model_card"])
    assert r.risk_level == "medium"


def test_to_dict_has_required_keys():
    d = _make_result().to_dict()
    for key in (
        "model_id",
        "source",
        "format",
        "is_safe_format",
        "has_digest",
        "risk_level",
        "risk_flags",
        "digest",
        "is_gated",
        "has_model_card",
    ):
        assert key in d, f"Missing key: {key}"


def test_to_dict_values_correct():
    r = _make_result(model_id="org/m", source="ollama", is_safe_format=False)
    d = r.to_dict()
    assert d["model_id"] == "org/m"
    assert d["source"] == "ollama"
    assert d["is_safe_format"] is False


# ---------------------------------------------------------------------------
# check_hf_model — no huggingface_hub SDK
# ---------------------------------------------------------------------------


def test_check_hf_model_no_hf_sdk():
    with patch.dict("sys.modules", {"huggingface_hub": None, "huggingface_hub.utils": None}):
        result = check_hf_model("test/model")
    assert result.source == "huggingface"
    assert result.model_id == "test/model"
    assert "no_digest" in result.risk_flags or "error" in result.metadata


# ---------------------------------------------------------------------------
# check_hf_model — mocked HfApi
# ---------------------------------------------------------------------------


def _sibling(filename: str, size: int = 1000, blob_id: str = "") -> MagicMock:
    s = MagicMock()
    s.rfilename = filename
    s.size = size
    s.blob_id = blob_id
    return s


def _model_info(siblings=None, gated=False, private=False, pipeline_tag="", card_data=MagicMock(), downloads=None) -> MagicMock:
    info = MagicMock()
    info.siblings = siblings or []
    info.gated = gated
    info.private = private
    info.pipeline_tag = pipeline_tag
    info.card_data = card_data
    info.downloads = downloads
    return info


def test_safetensors_only_is_safe():
    info = _model_info(siblings=[_sibling("model.safetensors", blob_id="sha256abc")])
    with _install_mock_hf(info):
        result = check_hf_model("org/safe-model")
    assert result.is_safe_format is True
    assert result.has_digest is True
    assert not any("unsafe_format" in f for f in result.risk_flags)


def test_pickle_file_is_unsafe():
    info = _model_info(siblings=[_sibling("model.pt", size=1000)])
    with _install_mock_hf(info):
        result = check_hf_model("org/unsafe-model")
    assert result.is_safe_format is False
    assert any("unsafe_format" in f for f in result.risk_flags)


def test_no_model_card_flagged():
    info = _model_info(siblings=[_sibling("model.safetensors", blob_id="abc")], card_data=None)
    with _install_mock_hf(info):
        result = check_hf_model("org/no-card")
    assert result.has_model_card is False
    assert "no_model_card" in result.risk_flags


def test_no_digest_flagged():
    info = _model_info(siblings=[_sibling("model.safetensors", blob_id="")])
    with _install_mock_hf(info):
        result = check_hf_model("org/no-digest")
    assert result.has_digest is False
    assert "no_digest" in result.risk_flags


def test_public_large_model_flagged():
    big = _sibling("model.safetensors", size=6 * 1024**3, blob_id="abc")
    info = _model_info(siblings=[big], gated=False)
    with _install_mock_hf(info):
        result = check_hf_model("org/huge-model")
    assert "public_large" in result.risk_flags


def test_gated_large_model_not_flagged():
    big = _sibling("model.safetensors", size=6 * 1024**3, blob_id="abc")
    info = _model_info(siblings=[big], gated=True)
    with _install_mock_hf(info):
        result = check_hf_model("org/gated-model")
    assert result.is_gated is True
    assert "public_large" not in result.risk_flags


def test_sensitive_pipeline_ungated_flagged():
    info = _model_info(siblings=[_sibling("model.safetensors", blob_id="abc")], pipeline_tag="text-generation", gated=False)
    with _install_mock_hf(info):
        result = check_hf_model("org/ungated-llm")
    assert "ungated_sensitive" in result.risk_flags


def test_gated_repo_error_returns_gated():
    hf_mod = types.ModuleType("huggingface_hub")
    hf_utils = types.ModuleType("huggingface_hub.utils")

    class GatedRepoError(Exception):
        pass

    class RepositoryNotFoundError(Exception):
        pass

    hf_utils.GatedRepoError = GatedRepoError
    hf_utils.RepositoryNotFoundError = RepositoryNotFoundError
    hf_mod.utils = hf_utils
    mock_api = MagicMock()
    mock_api.model_info.side_effect = GatedRepoError("gated")
    hf_mod.HfApi = MagicMock(return_value=mock_api)

    with patch.dict("sys.modules", {"huggingface_hub": hf_mod, "huggingface_hub.utils": hf_utils}):
        result = check_hf_model("org/secret-model")
    assert result.is_gated is True


def test_model_not_found_returns_error():
    hf_mod = types.ModuleType("huggingface_hub")
    hf_utils = types.ModuleType("huggingface_hub.utils")

    class GatedRepoError(Exception):
        pass

    class RepositoryNotFoundError(Exception):
        pass

    hf_utils.GatedRepoError = GatedRepoError
    hf_utils.RepositoryNotFoundError = RepositoryNotFoundError
    hf_mod.utils = hf_utils
    mock_api = MagicMock()
    mock_api.model_info.side_effect = RepositoryNotFoundError("not found")
    hf_mod.HfApi = MagicMock(return_value=mock_api)

    with patch.dict("sys.modules", {"huggingface_hub": hf_mod, "huggingface_hub.utils": hf_utils}):
        result = check_hf_model("org/nonexistent")
    assert "no_digest" in result.risk_flags


# ---------------------------------------------------------------------------
# _get_ollama_manifest_file
# ---------------------------------------------------------------------------


def test_get_manifest_file_not_found(tmp_path):
    result = _get_ollama_manifest_file("nonexistent-model", "latest")
    assert result is None


def test_get_manifest_file_valid(tmp_path):
    fake_manifest_dir = tmp_path / "registry.ollama.ai"
    manifest_path = fake_manifest_dir / "library" / "llama3" / "8b"
    manifest_path.parent.mkdir(parents=True)
    data = {"schemaVersion": 2, "config": {"digest": "sha256:abc"}, "layers": []}
    manifest_path.write_text(json.dumps(data))

    with patch("agent_bom.cloud.model_provenance._MANIFEST_DIR", fake_manifest_dir):
        result = _get_ollama_manifest_file("llama3", "8b")

    assert result is not None
    assert result["config"]["digest"] == "sha256:abc"


# ---------------------------------------------------------------------------
# check_ollama_model
# ---------------------------------------------------------------------------


def test_check_ollama_no_api_no_manifest(monkeypatch):
    monkeypatch.setattr("agent_bom.cloud.model_provenance._get_ollama_manifest_api", lambda *a, **k: None)
    monkeypatch.setattr("agent_bom.cloud.model_provenance._get_ollama_manifest_file", lambda *a, **k: None)
    result = check_ollama_model("llama3:8b")
    assert result.source == "ollama"
    assert "no_digest" in result.risk_flags


def test_check_ollama_with_digest(monkeypatch):
    manifest = {
        "schemaVersion": 2,
        "config": {"digest": "sha256:deadbeef", "mediaType": ""},
        "layers": [{"mediaType": "gguf", "digest": "sha256:aaaa"}],
    }
    monkeypatch.setattr("agent_bom.cloud.model_provenance._get_ollama_manifest_api", lambda *a, **k: manifest)
    result = check_ollama_model("llama3:8b")
    assert result.has_digest is True
    assert result.digest == "sha256:deadbeef"


def test_check_ollama_gguf_is_safe(monkeypatch):
    manifest = {
        "config": {"digest": "sha256:abc", "mediaType": ""},
        "layers": [{"mediaType": "gguf", "digest": "sha256:xyz"}],
    }
    monkeypatch.setattr("agent_bom.cloud.model_provenance._get_ollama_manifest_api", lambda *a, **k: manifest)
    result = check_ollama_model("mistral:7b")
    assert result.is_safe_format is True
    assert result.format == "gguf"


def test_check_ollama_no_digest_flagged(monkeypatch):
    manifest = {"config": {"digest": "", "mediaType": ""}, "layers": []}
    monkeypatch.setattr("agent_bom.cloud.model_provenance._get_ollama_manifest_api", lambda *a, **k: manifest)
    result = check_ollama_model("llama3:8b")
    assert "no_digest" in result.risk_flags


def test_check_ollama_model_name_parsing(monkeypatch):
    monkeypatch.setattr("agent_bom.cloud.model_provenance._get_ollama_manifest_api", lambda *a, **k: None)
    monkeypatch.setattr("agent_bom.cloud.model_provenance._get_ollama_manifest_file", lambda *a, **k: None)
    result = check_ollama_model("qwen2.5-coder:7b-instruct")
    assert result.model_id == "qwen2.5-coder:7b-instruct"


# ---------------------------------------------------------------------------
# Batch helpers
# ---------------------------------------------------------------------------


def test_check_hf_models_returns_list():
    with patch("agent_bom.cloud.model_provenance.check_hf_model") as mock_fn:
        mock_fn.return_value = _make_result()
        results = check_hf_models(["a/b", "c/d", "e/f"])
    assert len(results) == 3
    assert mock_fn.call_count == 3


def test_check_ollama_models_returns_list():
    with patch("agent_bom.cloud.model_provenance.check_ollama_model") as mock_fn:
        mock_fn.return_value = _make_result(source="ollama")
        results = check_ollama_models(["llama3:8b", "mistral:7b"])
    assert len(results) == 2
    assert mock_fn.call_count == 2


def test_check_hf_models_empty():
    assert check_hf_models([]) == []


def test_check_ollama_models_empty():
    assert check_ollama_models([]) == []
