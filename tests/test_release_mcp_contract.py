"""The marketplace oracle must come from the published package, not its host."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_script():
    spec = importlib.util.spec_from_file_location("release_contract", ROOT / "scripts/export_release_mcp_contract.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_install_is_exact_isolated_and_has_no_publishing_credentials(monkeypatch):
    script = load_script()
    calls = []
    expected = [{"name": "exposure_paths", "inputSchema": {"type": "object", "properties": {}}}]

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(expected), stderr="")

    monkeypatch.setenv("GLAMA_API_KEY", "must-not-reach-release-process")
    monkeypatch.setenv("PYTHONPATH", "/mutable-checkout/src")
    monkeypatch.setenv("PIP_INDEX_URL", "https://untrusted.invalid/simple")
    monkeypatch.setattr(script.subprocess, "run", run)
    assert script.export_contract("0.105.0", ["exposure_paths"]) == expected
    install = calls[1][0]
    assert install[-1] == "agent-bom==0.105.0"
    assert "--isolated" in install and "--only-binary=:all:" in install
    assert install[install.index("--index-url") + 1] == "https://pypi.org/simple"
    for command, kwargs in calls:
        assert "-I" in command
        assert not {"GLAMA_API_KEY", "PYTHONPATH", "PIP_INDEX_URL"}.intersection(kwargs["env"])
        assert kwargs["timeout"] <= 300


@pytest.mark.parametrize("version", ["main", "0.106.0 --extra-index-url evil", "0.105.0rc1", "../0.105.0"])
def test_release_install_rejects_non_release_version_before_subprocess(version, monkeypatch):
    script = load_script()
    monkeypatch.setattr(script.subprocess, "run", lambda *_a, **_kw: pytest.fail("must not execute"))
    with pytest.raises(ValueError, match="stable version"):
        script.export_contract(version, ["scan"])


@pytest.mark.parametrize("contract", [[], [{"name": "new_tool", "inputSchema": {}}], [{"name": "scan", "inputSchema": None}]])
def test_release_contract_must_match_immutable_names(contract, monkeypatch):
    script = load_script()
    monkeypatch.setattr(script.subprocess, "run", lambda command, **_kw: subprocess.CompletedProcess(command, 0, json.dumps(contract), ""))
    with pytest.raises(ValueError):
        script.export_contract("0.105.0", ["scan"])


def test_registry_workflows_never_use_hosted_card_as_schema_oracle():
    for name in ("surface-freshness.yml", "deployment-freshness.yml", "publish-registries.yml"):
        text = (ROOT / ".github/workflows" / name).read_text()
        assert "scripts/export_release_mcp_contract.py" in text
        assert "--write-tool-contract" not in text
        assert "server-card.json > /tmp/smithery-expected-tool-contract.json" not in text
    publish = (ROOT / ".github/workflows/publish-registries.yml").read_text()
    assert (
        "--compare-tool-contract-files /tmp/smithery-expected-tool-contract.json /tmp/smithery-actual-server-card-contract.json" in publish
    )


@pytest.mark.parametrize("schema_drift", [False, True])
def test_same_version_deployment_schema_drift_stays_failed(tmp_path, schema_drift):
    workflow = yaml.safe_load((ROOT / ".github/workflows/deployment-freshness.yml").read_text())
    step = next(step for step in workflow["jobs"]["check"]["steps"] if step.get("id") == "railway")
    script = step["run"]
    expected = [{"name": "exposure_paths", "inputSchema": {"type": "object", "properties": {}}}]
    actual = json.loads(json.dumps(expected))
    if schema_drift:
        actual[0]["inputSchema"]["properties"]["cursor"] = {"type": "string"}
    (tmp_path / "deployment-expected-tool-contract.json").write_text(json.dumps(expected))
    card = tmp_path / "card.json"
    card.write_text(json.dumps({"serverInfo": {"version": "0.105.0"}, "tools": actual}))
    script = re.sub(r"if RESPONSE=\$\(PYTHONPATH=src .*?\); then", f'if RESPONSE=$(cat "{card}"); then', script, flags=re.S)
    script = script.replace("/tmp/", str(tmp_path) + "/")
    # Replace the one mock response path after redirecting workflow artifacts.
    script = re.sub(r'if RESPONSE=\$\(cat ".*?"\); then', f'if RESPONSE=$(cat "{card}"); then', script)
    output = tmp_path / "outputs"
    result = subprocess.run(
        ["bash", "-c", script], cwd=ROOT, env={**os.environ, "GITHUB_OUTPUT": str(output)}, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert outputs["probe_failed"] == ("true" if schema_drift else "false")
    assert ("schema drift" in outputs["railway_version"]) == schema_drift
