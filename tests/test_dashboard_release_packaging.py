"""Regression tests: the published API image must carry the bundled dashboard.

``src/agent_bom/ui_dist`` is gitignored and produced only by the release
workflow's ``build`` job. ``docker-publish`` and ``container-gate`` run their
own fresh ``actions/checkout``, so unless the built dashboard is carried into
their build context the published API image cannot serve the dashboard at all —
while the enterprise deployment guide tells operators to pull that one image.

These tests pin the workflow wiring, the ``.dockerignore`` contract, and the
doc language so the defect cannot silently return.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
DASHBOARD_ARTIFACT = "dashboard-ui-dist"
DASHBOARD_PATH = "src/agent_bom/ui_dist"


def _release_jobs() -> dict[str, Any]:
    doc = yaml.safe_load(RELEASE_WORKFLOW.read_text(encoding="utf-8"))
    return doc["jobs"]


def _steps(job_id: str) -> list[dict[str, Any]]:
    return [step for step in _release_jobs()[job_id]["steps"] if isinstance(step, dict)]


def _step_index(steps: list[dict[str, Any]], predicate) -> int:
    for index, step in enumerate(steps):
        if predicate(step):
            return index
    return -1


def _uses_action(step: dict[str, Any], action: str) -> bool:
    return str(step.get("uses", "")).startswith(f"{action}@")


def test_build_job_publishes_the_dashboard_as_an_artifact():
    """The one job that builds the dashboard must hand it to downstream jobs."""
    steps = _steps("build")
    upload = [
        step for step in steps if _uses_action(step, "actions/upload-artifact") and step.get("with", {}).get("name") == DASHBOARD_ARTIFACT
    ]
    assert upload, f"build job does not upload the '{DASHBOARD_ARTIFACT}' artifact"
    assert upload[0]["with"]["path"] == DASHBOARD_PATH
    # An empty upload would pass silently and reintroduce a dashboard-less image.
    assert upload[0]["with"].get("if-no-files-found") == "error"


def test_docker_publish_restores_the_dashboard_before_building_the_image():
    steps = _steps("docker-publish")
    download = _step_index(
        steps,
        lambda step: _uses_action(step, "actions/download-artifact") and step.get("with", {}).get("name") == DASHBOARD_ARTIFACT,
    )
    build = _step_index(steps, lambda step: _uses_action(step, "docker/build-push-action"))
    assert download >= 0, "docker-publish never downloads the built dashboard into its build context"
    assert build >= 0, "docker-publish no longer builds the API image"
    assert download < build, "the dashboard must be restored before the image build reads the context"
    assert steps[download]["with"]["path"] == DASHBOARD_PATH


def test_container_gate_builds_and_proves_the_dashboard_is_in_the_image():
    """The gate must fail the release when the candidate image cannot serve the UI."""
    steps = _steps("container-gate")
    download = _step_index(
        steps,
        lambda step: _uses_action(step, "actions/download-artifact") and step.get("with", {}).get("name") == DASHBOARD_ARTIFACT,
    )
    build = _step_index(steps, lambda step: "docker build" in str(step.get("run", "")))
    assert download >= 0, "container-gate builds an image without the dashboard it is meant to gate"
    assert download < build, "the dashboard must be restored before the candidate image is built"

    gate = [step for step in steps if "dashboard" in str(step.get("name", "")).lower() and step.get("run")]
    assert gate, "container-gate has no dashboard assertion step"
    body = "\n".join(str(step["run"]) for step in gate)
    assert "ui_dist" in body and "index.html" in body, "the gate must assert the packaged dashboard index exists in the image"
    assert "agent-bom:release-test" in body, "the gate must assert against the built release candidate image"
    # A dashboard-less image still answers `/` with 200 (the JSON service card),
    # so a status-code-only gate would pass on the exact defect it exists to catch.
    assert "/_next/static" in body, "the gate must assert on the response body, not only the HTTP status"


def test_release_jobs_that_publish_the_api_image_depend_on_the_dashboard_build():
    jobs = _release_jobs()
    for job_id in ("docker-publish", "container-gate"):
        assert "build" in jobs[job_id]["needs"], f"{job_id} must depend on the job that builds the dashboard"


def _dockerignore_excludes(relative_path: str) -> bool:
    """Evaluate ``.dockerignore`` against ``relative_path`` with Docker semantics.

    Docker patterns are anchored at the build-context root (unlike ``.gitignore``)
    and are matched per path component, so a broad-looking entry such as ``lib/``
    only excludes ``<context>/lib``. Later negations (``!``) win.
    """
    from fnmatch import fnmatch

    excluded = False
    for raw in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        pattern = line.lstrip("!").strip("/")
        if not pattern:
            continue
        # A pattern matches the path itself or any of its parent directories.
        parts = relative_path.split("/")
        candidates = ["/".join(parts[: i + 1]) for i in range(len(parts))]
        if any(fnmatch(candidate, pattern) for candidate in candidates):
            excluded = not negate
    return excluded


def test_dockerignore_keeps_the_bundled_dashboard_in_the_build_context():
    """Guard against a broad pattern (``lib/``, ``*.md``, ``build/``) swallowing ui_dist."""
    for relative_path in (
        "src/agent_bom/ui_dist/index.html",
        "src/agent_bom/ui_dist/csp-hashes.json",
        "src/agent_bom/ui_dist/_next/static/chunks/main.js",
        "src/agent_bom/ui_dist/graph/index.html",
    ):
        assert not _dockerignore_excludes(relative_path), f".dockerignore excludes {relative_path} from the image build context"


def test_dockerfile_copies_the_package_source_that_carries_the_dashboard():
    body = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY src/ ./src/" in body, "the image no longer copies src/, so ui_dist can never reach the wheel it installs"


def test_release_verification_bundles_the_dashboard_before_building_the_wheel():
    """`uv build` alone yields a dashboard-less wheel; the doc must say so in order."""
    body = (ROOT / "docs" / "RELEASE_VERIFICATION.md").read_text(encoding="utf-8")
    assert "make build-ui" in body, "RELEASE_VERIFICATION.md never tells the release engineer to bundle the dashboard"
    assert body.index("make build-ui") < body.index("uv build"), "the dashboard bundle step must precede the package build"
    assert "ui_dist" in body, "the doc must name the artifact the bundle step produces"


def test_enterprise_deployment_states_what_each_artifact_bundles():
    """A blanket 'false' claim shipped while the published image had no dashboard."""
    body = (ROOT / "docs" / "ENTERPRISE_DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "false. Verified above." not in body, "the guide still asserts a blanket claim the reader cannot verify"
    assert "The wheel bundles the dashboard" in body
    assert "agentbom/agent-bom" in body
