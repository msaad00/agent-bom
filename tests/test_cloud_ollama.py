"""Tests for agent_bom.cloud.ollama to improve coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# _discover_via_api
# ---------------------------------------------------------------------------


def test_discover_via_api_httpx_success():
    from agent_bom.cloud.ollama import _discover_via_api

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"models": [{"name": "llama3.2"}]}

    with patch("httpx.get", return_value=mock_resp):
        result = _discover_via_api("http://localhost:11434")
        assert result == [{"name": "llama3.2"}]


def test_discover_via_api_both_fail():
    from agent_bom.cloud.ollama import _discover_via_api

    with patch("httpx.get", side_effect=OSError("refused")):
        with patch("agent_bom.http_client.sync_get", return_value=None):
            result = _discover_via_api("http://localhost:11434")
            assert result is None


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


def test_discover_via_api():
    from agent_bom.cloud.ollama import discover

    models = [
        {
            "name": "llama3.2:8b",
            "size": 4_000_000_000,
            "details": {
                "family": "llama",
                "parameter_size": "8B",
                "quantization_level": "Q4_0",
                "format": "gguf",
            },
        }
    ]
    with patch("agent_bom.cloud.ollama._discover_via_api", return_value=models):
        agents, warnings = discover()
        assert len(agents) == 1
        assert "ollama-model-llama3.2" in agents[0].name


def test_discover_no_api_no_manifests():
    from agent_bom.cloud.ollama import discover

    with (
        patch("agent_bom.cloud.ollama._discover_via_api", return_value=None),
        patch("agent_bom.cloud.ollama._MANIFEST_DIR", Path("/nonexistent")),
    ):
        agents, warnings = discover()
        assert len(agents) == 0
        assert any("not detected" in w for w in warnings)


def test_discover_from_manifests(tmp_path):
    from agent_bom.cloud.ollama import discover

    # Create fake manifest structure
    library = tmp_path / "library"
    model_dir = library / "qwen2"
    model_dir.mkdir(parents=True)
    (model_dir / "latest").write_text("{}")

    with patch("agent_bom.cloud.ollama._discover_via_api", return_value=None), patch("agent_bom.cloud.ollama._MANIFEST_DIR", tmp_path):
        agents, warnings = discover()
        assert len(agents) == 1
        assert "qwen2" in agents[0].name


def test_discover_manifests_empty(tmp_path):
    from agent_bom.cloud.ollama import discover

    library = tmp_path / "library"
    library.mkdir(parents=True)

    with patch("agent_bom.cloud.ollama._discover_via_api", return_value=None), patch("agent_bom.cloud.ollama._MANIFEST_DIR", tmp_path):
        agents, warnings = discover()
        assert len(agents) == 0


def test_discover_with_host_env():
    from agent_bom.cloud.ollama import discover

    with (
        patch("agent_bom.cloud.ollama._discover_via_api", return_value=[]),
        patch.dict("os.environ", {"OLLAMA_HOST": "http://custom:11434"}),
    ):
        agents, warnings = discover()
        assert isinstance(agents, list)


def test_discover_api_model_no_details():
    from agent_bom.cloud.ollama import discover

    models = [{"name": "simple-model"}]
    with patch("agent_bom.cloud.ollama._discover_via_api", return_value=models):
        agents, warnings = discover()
        assert len(agents) == 1
