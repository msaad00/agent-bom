"""Tests for dedicated scan-type REST API endpoints (#480).

Covers POST /v1/scan/{dataset-cards,training-pipelines,browser-extensions,
model-provenance,prompt-scan,model-files}.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from unittest.mock import patch

from starlette.testclient import TestClient

from agent_bom.api.server import _jobs, app, set_job_store
from agent_bom.api.store import InMemoryJobStore

_SANITIZE = "agent_bom.api.routes.scan._sanitize_api_path"

# Path under $HOME so the inline commonpath guard in endpoints passes.
_HOME = os.path.realpath(os.path.expanduser("~"))
_FAKE_SAFE = os.path.join(_HOME, "_test_scan_placeholder")


def _fresh_client():
    store = InMemoryJobStore()
    set_job_store(store)
    _jobs.clear()
    return TestClient(app, raise_server_exceptions=False), store


# ---------------------------------------------------------------------------
# 1. Dataset Cards
# ---------------------------------------------------------------------------


def test_scan_dataset_cards_success(tmp_path):
    """POST /v1/scan/dataset-cards returns results from scan_dataset_directory."""
    client, _ = _fresh_client()

    @dataclass
    class _FakeResult:
        datasets: list = field(default_factory=list)
        source_files: list = field(default_factory=list)
        warnings: list = field(default_factory=list)

        def to_dict(self):
            return {"datasets": self.datasets, "source_files": self.source_files, "warnings": self.warnings}

    fake = _FakeResult(datasets=[{"name": "test-ds"}], source_files=["README.md"])

    with (
        patch("agent_bom.parsers.dataset_cards.scan_dataset_directory", return_value=fake),
        patch(_SANITIZE, return_value=_FAKE_SAFE),
    ):
        resp = client.post("/v1/scan/dataset-cards", json={"directories": [str(tmp_path)]})

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_type"] == "dataset-cards"
    assert len(body["results"]) == 1
    assert body["results"][0]["datasets"] == [{"name": "test-ds"}]


def test_scan_dataset_cards_empty_directories():
    """POST /v1/scan/dataset-cards with empty directories returns empty results."""
    client, _ = _fresh_client()
    resp = client.post("/v1/scan/dataset-cards", json={"directories": []})
    assert resp.status_code == 200
    assert resp.json()["results"] == []


def test_scan_dataset_cards_missing_body():
    """POST /v1/scan/dataset-cards without body returns 422."""
    client, _ = _fresh_client()
    resp = client.post("/v1/scan/dataset-cards")
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 2. Training Pipelines
# ---------------------------------------------------------------------------


def test_scan_training_pipelines_success(tmp_path):
    """POST /v1/scan/training-pipelines returns pipeline scan results."""
    client, _ = _fresh_client()

    @dataclass
    class _FakeResult:
        training_runs: list = field(default_factory=list)
        serving_configs: list = field(default_factory=list)
        source_files: list = field(default_factory=list)
        warnings: list = field(default_factory=list)

        def to_dict(self):
            return {
                "training_runs": self.training_runs,
                "serving_configs": self.serving_configs,
                "source_files": self.source_files,
                "warnings": self.warnings,
            }

    fake = _FakeResult(training_runs=[{"run_id": "abc"}])

    with (
        patch("agent_bom.parsers.training_pipeline.scan_training_directory", return_value=fake),
        patch(_SANITIZE, return_value=_FAKE_SAFE),
    ):
        resp = client.post("/v1/scan/training-pipelines", json={"directories": [str(tmp_path)]})

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_type"] == "training-pipelines"
    assert body["results"][0]["training_runs"] == [{"run_id": "abc"}]


def test_scan_training_pipelines_missing_body():
    """POST /v1/scan/training-pipelines without body returns 422."""
    client, _ = _fresh_client()
    resp = client.post("/v1/scan/training-pipelines")
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 3. Browser Extensions
# ---------------------------------------------------------------------------


def test_scan_browser_extensions_success():
    """POST /v1/scan/browser-extensions returns extension scan results."""
    client, _ = _fresh_client()

    @dataclass
    class _FakeExt:
        id: str = "ext-123"
        name: str = "Test Ext"
        risk_level: str = "high"

        def to_dict(self):
            return {"id": self.id, "name": self.name, "risk_level": self.risk_level}

    with patch("agent_bom.parsers.browser_extensions.discover_browser_extensions", return_value=[_FakeExt()]):
        resp = client.post("/v1/scan/browser-extensions", json={})

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_type"] == "browser-extensions"
    assert body["total"] == 1
    assert body["high"] == 1
    assert body["critical"] == 0
    assert body["extensions"][0]["name"] == "Test Ext"


def test_scan_browser_extensions_default_body():
    """POST /v1/scan/browser-extensions works with no body (defaults)."""
    client, _ = _fresh_client()
    with patch("agent_bom.parsers.browser_extensions.discover_browser_extensions", return_value=[]):
        resp = client.post("/v1/scan/browser-extensions", json={})
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


def test_scan_browser_extensions_include_low_risk():
    """POST /v1/scan/browser-extensions passes include_low_risk to scanner."""
    client, _ = _fresh_client()
    with patch("agent_bom.parsers.browser_extensions.discover_browser_extensions", return_value=[]) as mock_fn:
        client.post("/v1/scan/browser-extensions", json={"include_low_risk": True})
    mock_fn.assert_called_once_with(include_low_risk=True)


# ---------------------------------------------------------------------------
# 4. Model Provenance
# ---------------------------------------------------------------------------


def test_scan_model_provenance_hf():
    """POST /v1/scan/model-provenance scans HuggingFace models."""
    client, _ = _fresh_client()

    @dataclass
    class _FakeProvenance:
        model_id: str = "meta-llama/Llama-2-7b"
        source: str = "huggingface"
        is_safe_format: bool = True

        def to_dict(self):
            return {"model_id": self.model_id, "source": self.source, "is_safe_format": self.is_safe_format}

    with patch("agent_bom.cloud.model_provenance.check_hf_models", return_value=[_FakeProvenance()]) as mock_hf:
        resp = client.post("/v1/scan/model-provenance", json={"hf_models": ["meta-llama/Llama-2-7b"]})

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_type"] == "model-provenance"
    assert body["total"] == 1
    assert body["unsafe_format"] == 0
    mock_hf.assert_called_once_with(["meta-llama/Llama-2-7b"])


def test_scan_model_provenance_ollama():
    """POST /v1/scan/model-provenance scans Ollama models."""
    client, _ = _fresh_client()

    @dataclass
    class _FakeProvenance:
        model_id: str = "llama2"
        source: str = "ollama"
        is_safe_format: bool = False

        def to_dict(self):
            return {"model_id": self.model_id, "source": self.source, "is_safe_format": self.is_safe_format}

    with patch("agent_bom.cloud.model_provenance.check_ollama_models", return_value=[_FakeProvenance()]):
        resp = client.post("/v1/scan/model-provenance", json={"ollama_models": ["llama2"]})

    body = resp.json()
    assert body["unsafe_format"] == 1


def test_scan_model_provenance_empty():
    """POST /v1/scan/model-provenance with no models returns empty."""
    client, _ = _fresh_client()
    resp = client.post("/v1/scan/model-provenance", json={})
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


# ---------------------------------------------------------------------------
# 5. Prompt Scan
# ---------------------------------------------------------------------------


def test_scan_prompts_directories(tmp_path):
    """POST /v1/scan/prompt-scan scans directories for prompt files."""
    client, _ = _fresh_client()

    @dataclass
    class _FakeResult:
        files_scanned: int = 3
        findings: list = field(default_factory=list)
        prompt_files: list = field(default_factory=list)
        passed: bool = True

        def to_dict(self):
            return {
                "files_scanned": self.files_scanned,
                "findings": self.findings,
                "prompt_files": self.prompt_files,
                "passed": self.passed,
            }

    with (
        patch("agent_bom.parsers.prompt_scanner.scan_prompt_files", return_value=_FakeResult()),
        patch(_SANITIZE, return_value=_FAKE_SAFE),
    ):
        resp = client.post("/v1/scan/prompt-scan", json={"directories": [str(tmp_path)]})

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_type"] == "prompt-scan"
    assert body["results"][0]["files_scanned"] == 3
    assert body["results"][0]["passed"] is True


def test_scan_prompts_files(tmp_path):
    """POST /v1/scan/prompt-scan scans specific files."""
    client, _ = _fresh_client()
    prompt_file = tmp_path / "test.prompt"
    prompt_file.write_text("Hello {{name}}")

    @dataclass
    class _FakeResult:
        files_scanned: int = 1
        findings: list = field(default_factory=list)
        prompt_files: list = field(default_factory=list)
        passed: bool = True

        def to_dict(self):
            return {
                "files_scanned": self.files_scanned,
                "findings": self.findings,
                "prompt_files": self.prompt_files,
                "passed": self.passed,
            }

    with (
        patch("agent_bom.parsers.prompt_scanner.scan_prompt_files", return_value=_FakeResult()),
        patch(_SANITIZE, return_value=_FAKE_SAFE),
    ):
        resp = client.post("/v1/scan/prompt-scan", json={"files": [str(prompt_file)]})

    assert resp.status_code == 200
    assert len(resp.json()["results"]) == 1


def test_scan_prompts_empty():
    """POST /v1/scan/prompt-scan with no dirs/files returns empty."""
    client, _ = _fresh_client()
    resp = client.post("/v1/scan/prompt-scan", json={})
    assert resp.status_code == 200
    assert resp.json()["results"] == []


# ---------------------------------------------------------------------------
# 6. Model Files
# ---------------------------------------------------------------------------


def test_scan_model_files_success(tmp_path):
    """POST /v1/scan/model-files returns model file scan results."""
    client, _ = _fresh_client()

    fake_files = [
        {"path": str(tmp_path / "model.safetensors"), "format": "safetensors", "security_flags": []},
        {"path": str(tmp_path / "model.pkl"), "format": "pickle", "security_flags": ["unsafe_deserialization"]},
    ]

    with (
        patch("agent_bom.model_files.scan_model_files", return_value=(fake_files, [])),
        patch(_SANITIZE, return_value=_FAKE_SAFE),
    ):
        resp = client.post("/v1/scan/model-files", json={"directories": [str(tmp_path)]})

    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_type"] == "model-files"
    assert body["total"] == 2
    assert body["unsafe"] == 1


def test_scan_model_files_with_hashes(tmp_path):
    """POST /v1/scan/model-files with verify_hashes computes SHA-256."""
    client, _ = _fresh_client()

    fake_files = [{"path": str(tmp_path / "m.pt"), "format": "pytorch", "security_flags": []}]

    with (
        patch("agent_bom.model_files.scan_model_files", return_value=(fake_files, [])),
        patch("agent_bom.model_files.verify_model_hash", return_value={"sha256": "abc123"}) as mock_hash,
        patch(_SANITIZE, return_value=_FAKE_SAFE),
    ):
        resp = client.post("/v1/scan/model-files", json={"directories": [str(tmp_path)], "verify_hashes": True})

    assert resp.status_code == 200
    mock_hash.assert_called_once()
    assert resp.json()["files"][0]["sha256"] == "abc123"


def test_scan_model_files_missing_body():
    """POST /v1/scan/model-files without body returns 422."""
    client, _ = _fresh_client()
    resp = client.post("/v1/scan/model-files")
    assert resp.status_code == 422


def test_scan_model_files_warnings(tmp_path):
    """POST /v1/scan/model-files surfaces warnings from scanner."""
    client, _ = _fresh_client()

    with (
        patch("agent_bom.model_files.scan_model_files", return_value=([], ["Skipped large file"])),
        patch(_SANITIZE, return_value=_FAKE_SAFE),
    ):
        resp = client.post("/v1/scan/model-files", json={"directories": [str(tmp_path)]})

    assert resp.status_code == 200
    assert resp.json()["warnings"] == ["Skipped large file"]


# ---------------------------------------------------------------------------
# 7. Path sanitization
# ---------------------------------------------------------------------------


def test_sanitize_rejects_traversal():
    """_sanitize_api_path rejects path traversal."""
    import pytest

    from agent_bom.api.server import _sanitize_api_path
    from agent_bom.security import SecurityError

    with pytest.raises(SecurityError, match="traversal"):
        _sanitize_api_path("subdir/../../etc/passwd")


def test_sanitize_rejects_absolute_path():
    """_sanitize_api_path rejects absolute paths."""
    import pytest

    from agent_bom.api.server import _sanitize_api_path
    from agent_bom.security import SecurityError

    with pytest.raises(SecurityError, match="Absolute paths"):
        _sanitize_api_path("/etc/passwd")


def test_sanitize_resolves_relative_to_home(tmp_path, monkeypatch):
    """_sanitize_api_path joins relative paths under $HOME."""
    import os

    from agent_bom.api.server import _sanitize_api_path

    # Create a subdir under tmp_path acting as $HOME
    subdir = tmp_path / "projects"
    subdir.mkdir()
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path))

    result = _sanitize_api_path("projects")
    assert result == os.path.realpath(str(subdir))
