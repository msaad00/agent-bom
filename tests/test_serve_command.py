"""Tests for the rewritten `agent-bom serve` command (API-based, no Streamlit)."""

import builtins

from click.testing import CliRunner

from agent_bom.cli import main


def test_serve_requires_uvicorn(monkeypatch):
    """serve exits with error when uvicorn is not installed."""
    runner = CliRunner()
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "uvicorn":
            raise ImportError("No module named 'uvicorn'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    result = runner.invoke(main, ["serve"])
    combined = (result.output or "") + str(result.exception or "")
    assert result.exit_code != 0 or "uvicorn" in combined.lower()


def test_no_streamlit_import():
    """serve_app.py should not exist and streamlit should not be imported."""
    from pathlib import Path

    serve_app = Path(__file__).resolve().parent.parent / "src" / "agent_bom" / "serve_app.py"
    assert not serve_app.exists(), "serve_app.py should be deleted"


def test_pyproject_no_streamlit():
    """pyproject.toml [ui] extras should not contain streamlit."""
    from pathlib import Path

    toml_text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    # Check that ui section no longer has streamlit
    assert "streamlit" not in toml_text.lower()
