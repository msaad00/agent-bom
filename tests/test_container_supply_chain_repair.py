from __future__ import annotations

import importlib.util
import json
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]


def test_all_direct_cryptography_constraints_exclude_cve_2026_69247() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    constraints: list[str] = []
    for requirement in project["dependencies"]:
        if Requirement(requirement).name.lower() == "cryptography":
            constraints.append(requirement)
    for requirements in project["optional-dependencies"].values():
        for requirement in requirements:
            if Requirement(requirement).name.lower() == "cryptography":
                constraints.append(requirement)
    assert constraints
    assert all("50.0.0" in Requirement(item).specifier for item in constraints)


def test_floating_latest_uses_reviewed_runtime_security_overlay() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/refresh-latest-container.yml").read_text(encoding="utf-8")
    requirements = (ROOT / "deploy/docker/runtime-security-requirements.txt").read_text(encoding="utf-8")

    assert "runtime-security-requirements.txt" in dockerfile
    assert "--no-config --python /app/.venv/bin/python --no-deps --require-hashes" in dockerfile
    assert "Dockerfile \\" in workflow
    assert "deploy/docker/runtime-security-requirements.txt \\" in workflow
    assert "cryptography==50.0.0" in requirements
    assert requirements.count("--hash=sha256:") == 2


def test_container_sarif_normalization_preserves_image_reference(tmp_path: Path) -> None:
    script_path = ROOT / "scripts/normalize_container_sarif_for_github.py"
    spec = importlib.util.spec_from_file_location("normalize_container_sarif_for_github", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    document = {
        "runs": [
            {
                "automationDetails": {"id": "agent-bom/scan"},
                "results": [
                    {
                        "ruleId": "CVE-2026-69247",
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "docker://agentbom/agent-bom:latest"}}}],
                    }
                ],
            }
        ]
    }
    path = tmp_path / "image.sarif"
    path.write_text(json.dumps(document), encoding="utf-8")

    assert module.main([str(path)]) == 0
    normalized = json.loads(path.read_text(encoding="utf-8"))
    run = normalized["runs"][0]
    result = run["results"][0]
    artifact = result["locations"][0]["physicalLocation"]["artifactLocation"]
    assert "automationDetails" not in run
    assert artifact == {"uri": "Dockerfile", "uriBaseId": "%SRCROOT%"}
    assert result["properties"]["agent-bom:container_uri"] == "docker://agentbom/agent-bom:latest"


def test_container_rescan_normalizes_sarif_without_making_upload_gating() -> None:
    workflow = (ROOT / ".github/workflows/container-rescan.yml").read_text(encoding="utf-8")
    assert "Normalize container SARIF for GitHub" in workflow
    assert "scripts/normalize_container_sarif_for_github.py" in workflow
    upload = workflow.split("- name: Upload SARIF to GitHub Security tab", 1)[1]
    assert "continue-on-error: true" in upload.split("- name:", 1)[0]
