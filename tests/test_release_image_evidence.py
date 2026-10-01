"""Published image validation must cover both architectures and retain failures."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_published_image_gate_checks_both_platforms_and_pins_scans():
    job = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]["published-image-scan-gate"]
    assert job["strategy"]["matrix"]["platform"] == ["linux/amd64", "linux/arm64"]
    steps = {step.get("name"): step for step in job["steps"]}
    pull = steps["Pull published API image"]["run"]
    assert "--platform" in pull and "image-identity.json" in pull
    assert "steps.image.outputs.id" in steps["Collect published image vulnerability evidence"]["env"]["IMAGE_ID"]
    assert "steps.image.outputs.id" in steps["Scan published API image with agent-bom (evidence)"]["env"]["IMAGE_ID"]


def test_reports_are_saved_before_policy_gate_and_names_are_platform_specific():
    job = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]["published-image-scan-gate"]
    steps = job["steps"]
    by_name = {step.get("name"): step for step in steps}
    collect = by_name["Collect published image vulnerability evidence"]["run"]
    assert "--format json" in collect and "--exit-code 1" not in collect
    assert "trivy convert" in by_name["Convert published image report to SARIF"]["run"]
    upload = by_name["Upload published image scan artifacts"]
    assert upload["if"] == "always()"
    assert "matrix.arch" in upload["with"]["name"]
    assert "image-identity.json" in upload["with"]["path"]
    gate = by_name["Enforce published image vulnerability policy"]
    assert gate["if"] == "always()"
    assert "--exit-code 1" in gate["run"]
    assert steps.index(upload) < steps.index(gate)


def test_daily_rescan_retains_original_sarif_and_immutable_identity():
    job = yaml.safe_load((ROOT / ".github/workflows/container-rescan.yml").read_text())["jobs"]["rescan"]
    steps = {step.get("name"): step for step in job["steps"]}
    archive = steps["Retain original container scan evidence"]
    assert archive["if"] == "always()"
    assert "image-identity.json" in archive["with"]["path"]
    assert "original-image-scan-" in archive["with"]["path"]
    for name in ("Container image scan table (fixable MEDIUM+)", "Container image scan SARIF"):
        assert "steps.image.outputs.id" in steps[name]["env"]["IMAGE_ID"]
        assert '"$IMAGE_ID"' in steps[name]["run"]
