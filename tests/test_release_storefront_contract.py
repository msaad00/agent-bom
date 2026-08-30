"""Release storefront contracts for concise onboarding and sanitized proof."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from scripts import check_release_consistency
from scripts.render_docker_storefront import render_published_readme

ROOT = Path(__file__).resolve().parents[1]


def test_release_storefront_context_distinguishes_candidate_from_published_release() -> None:
    version = check_release_consistency._load_version()
    previous_version = "0.0.0"
    assert not check_release_consistency._requires_published_storefront(version, {})
    assert not check_release_consistency._is_matching_release_tag(
        version, {"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": f"v{previous_version}"}
    )
    assert check_release_consistency._is_matching_release_tag(version, {"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": f"v{version}"})
    assert check_release_consistency._requires_published_storefront(version, {"AGENT_BOM_RELEASE_FINALIZE": "true"})


def test_release_workflow_promotes_candidate_only_in_external_storefront_render(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    version = check_release_consistency._load_version()
    neutral = f"| `{version}` | Version used by the examples below; verify registry availability before pinning |\n"
    rendered = render_published_readme(neutral, version)
    assert neutral not in rendered
    assert f"| `{version}` | Current stable version (pinned) |" in rendered

    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
    monkeypatch.setenv("GITHUB_REF_NAME", f"v{version}")
    check_release_consistency._assert_docker_storefront_state(version)

    monkeypatch.setenv("AGENT_BOM_RELEASE_FINALIZE", "1")
    with pytest.raises(SystemExit):
        check_release_consistency._assert_docker_storefront_state(version)
    published = tmp_path / "DOCKER_HUB_README.published.md"
    published.write_text(rendered)
    monkeypatch.setenv("AGENT_BOM_DOCKER_README_PATH", str(published))
    check_release_consistency._assert_docker_storefront_state(version)

    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    assert "scripts/render_docker_storefront.py" in workflow
    assert 'AGENT_BOM_DOCKER_README_PATH="$PUBLISHED_README"' in workflow
    assert 'DESCRIPTION=$(jq -Rs . < "$PUBLISHED_README")' in workflow


def test_release_manifest_covers_dark_light_and_mobile_product_proof() -> None:
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))
    entries = {entry["path"]: entry for entry in manifest["screenshots"]}

    required = {
        "dashboard-live.png": "dark desktop",
        "dashboard-light-live.png": "light desktop",
        "dashboard-mobile-live.png": "dark mobile",
        "security-graph-live.png": "dark desktop",
        "security-graph-light-live.png": "light desktop",
        "security-graph-mobile-live.png": "dark mobile",
    }
    for path, presentation in required.items():
        assert path in entries
        assert entries[path]["presentation"] == presentation
        assert (ROOT / "docs/images" / path).is_file()

    note = str(manifest["capture_note"])
    assert "deterministic" in note.lower()
    assert "external" in note.lower()


def test_release_manifest_carries_reproducible_sanitized_provenance() -> None:
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))

    assert re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"])
    assert manifest["source_tree"] == "clean"
    assert "private infrastructure" in manifest["capture_note"].lower()

    for entry in manifest["screenshots"]:
        screenshot = ROOT / "docs" / "images" / entry["path"]
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", entry["sha256"])
        actual = hashlib.sha256(screenshot.read_bytes()).hexdigest()
        assert entry["sha256"] == f"sha256:{actual}"

    paths = {entry["path"] for entry in manifest["screenshots"]}
    entries = {entry["path"]: entry for entry in manifest["screenshots"]}
    assert {"agent-lifecycle-live.png", "jobs-pipeline-live.png"} <= paths
    assert {"correlation-receipts-live.png", "correlation-path-live.png"} <= paths
    assert {"remediation-live.png", "remediation-light-live.png", "remediation-mobile-live.png"} <= paths

    lab_digest = (ROOT / "examples/reference-evidence-lab/generated/correlation-proof.sha256").read_text(encoding="utf-8").strip()
    for path in ("correlation-receipts-live.png", "correlation-path-live.png"):
        assert entries[path]["evidence_sha256"] == lab_digest
        assert entries[path]["correlation_manifest_sha256"].startswith("sha256:")


def test_release_manifest_rejects_a_future_visible_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))
    manifest["screenshots"][0]["visible_version"] = "999.0.0"
    candidate = tmp_path / "product-screenshots.json"
    candidate.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(check_release_consistency, "PRODUCT_SCREENSHOTS", candidate)

    with pytest.raises(SystemExit):
        check_release_consistency._assert_product_screenshots_current(check_release_consistency._load_version())
    assert "newer than the release" in capsys.readouterr().err


def test_capture_runbook_matches_the_local_authenticated_release_workflow() -> None:
    """The published runbook must stay executable as auth and capture contracts evolve."""
    runbook = (ROOT / "docs/CAPTURE.md").read_text(encoding="utf-8")
    manifest = json.loads((ROOT / "docs/images/product-screenshots.json").read_text(encoding="utf-8"))
    backend_smoke = runbook.split("Backend-connected release evidence", 1)[1].split("## Per-screenshot scope", 1)[0]

    assert f"Inspect all {len(manifest['screenshots'])} PNGs" in runbook
    assert "`CAPTURE_BASE_URL` is not supported" in runbook
    assert "export CAPTURE_BASE_URL" not in runbook
    assert '--api-key "$CAPTURE_API_KEY"' in backend_smoke
    assert "Authorization: Bearer $CAPTURE_API_KEY" in backend_smoke
    assert "--allow-insecure-no-auth" not in runbook
