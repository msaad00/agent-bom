from __future__ import annotations

import importlib.util
import json
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]


def test_every_published_python_image_removes_runtime_packaging_tools() -> None:
    """Build tooling and pip's vendored libraries must not ship at runtime.

    Pip 26.2's bundled SBOM includes vulnerable msgpack 1.1.2 and setuptools
    70.3.0 even though agent-bom does not import either package.  Removing pip,
    setuptools, and wheel from the final stage both shrinks the attack surface
    and keeps image scanners aligned with the executable runtime filesystem.
    """
    dockerfiles = [
        ROOT / "Dockerfile",
        ROOT / "deploy/docker/Dockerfile.collector",
        ROOT / "deploy/docker/Dockerfile.mcp",
        ROOT / "deploy/docker/Dockerfile.runtime",
        ROOT / "deploy/docker/Dockerfile.snowpark",
        ROOT / "deploy/docker/Dockerfile.sse",
        ROOT / "integrations/glama/Dockerfile",
    ]
    for dockerfile in dockerfiles:
        text = dockerfile.read_text(encoding="utf-8")
        assert "python -m pip uninstall --yes setuptools wheel pip" in text, dockerfile
        assert "deploy/docker/pip-requirements.txt" not in text, dockerfile

    assert not (ROOT / "deploy/docker/pip-requirements.txt").exists()


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
                        "relatedLocations": [
                            {
                                "id": 0,
                                "logicalLocations": [{"fullyQualifiedName": "package:pip@26.1.2", "kind": "package"}],
                                "message": {"text": "pip@26.1.2"},
                            }
                        ],
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
    related_physical = result["relatedLocations"][0]["physicalLocation"]
    assert related_physical == {"artifactLocation": {"uri": "Dockerfile", "uriBaseId": "%SRCROOT%"}}


def test_container_rescan_normalizes_sarif_without_making_upload_gating() -> None:
    workflow = (ROOT / ".github/workflows/container-rescan.yml").read_text(encoding="utf-8")
    assert "Normalize container SARIF for GitHub" in workflow
    assert "scripts/normalize_container_sarif_for_github.py" in workflow
    upload = workflow.split("- name: Upload SARIF to GitHub Security tab", 1)[1]
    assert "continue-on-error: true" in upload.split("- name:", 1)[0]


def test_container_rescan_runs_after_release_and_records_immutable_image_evidence() -> None:
    workflow = (ROOT / ".github/workflows/container-rescan.yml").read_text(encoding="utf-8")
    assert 'workflows: ["Release"]' in workflow
    assert "github.event.workflow_run.conclusion == 'success'" in workflow
    assert "Resolve pulled image identity" in workflow
    assert "IMAGE_ID:" in workflow
    assert "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" in workflow
    assert 'elif [ "${{ steps.image_scan_table.outcome }}" = "success" ] && [ -n "$EXISTING" ]; then' in workflow
    assert "latest rescan was inconclusive, so this finding remains open" in workflow
