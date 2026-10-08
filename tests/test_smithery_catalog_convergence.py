"""Smithery post-publish verification reports why evidence is unavailable."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-registries.yml"


@pytest.fixture
def freshness():
    spec = importlib.util.spec_from_file_location("smithery_convergence_check", ROOT / "scripts/check_surface_freshness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CATALOG = {"qualifiedName": "agentbom/agent-bom", "remote": True, "deploymentUrl": "https://example.invalid", "tools": []}


def test_unavailable_schema_evidence_names_the_underlying_cause(freshness, monkeypatch, tmp_path):
    monkeypatch.setattr(freshness, "_http_json", lambda url, **kw: CATALOG)

    def disagree(*_args, **_kwargs):
        raise ValueError("Smithery public page and catalog schema values disagree")

    monkeypatch.setattr(freshness, "_smithery_public_contract", disagree)

    with pytest.raises(SystemExit) as exc:
        freshness.main(["--smithery-server", "agentbom/agent-bom", "--write-smithery-tool-contract", str(tmp_path / "out.json")])

    message = str(exc.value.code)
    assert message.startswith("complete Smithery schema evidence is unavailable or inconsistent")
    assert "ValueError: Smithery public page and catalog schema values disagree" in message
    assert not (tmp_path / "out.json").exists()


def test_unavailable_reason_is_bounded_to_one_line(freshness, monkeypatch, tmp_path):
    monkeypatch.setattr(freshness, "_http_json", lambda url, **kw: CATALOG)

    def noisy(*_args, **_kwargs):
        raise OSError("line one\nline two " + "x" * 1000)

    monkeypatch.setattr(freshness, "_smithery_public_contract", noisy)

    with pytest.raises(SystemExit) as exc:
        freshness.main(["--smithery-server", "agentbom/agent-bom", "--write-smithery-tool-contract", str(tmp_path / "out.json")])

    message = str(exc.value.code)
    assert "\n" not in message
    assert len(message) < 400


def test_post_publish_verification_allows_smithery_propagation() -> None:
    job = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["smithery"]
    step = next(step for step in job["steps"] if step.get("name") == "Verify Smithery catalog inventory")
    script = step["run"]

    attempts = int(re.search(r"for ATTEMPT in \$\(seq 1 (\d+)\)", script).group(1))
    delay = int(re.search(r"sleep (\d+)", script).group(1))
    # A fresh deployment updates the catalog API before the public page; the
    # two must agree before the schema evidence is trusted.
    assert attempts * delay >= 600
    assert f"attempt ${{ATTEMPT}}/{attempts}" in script
    assert job["timeout-minutes"] >= 45
    assert job["continue-on-error"] is True
