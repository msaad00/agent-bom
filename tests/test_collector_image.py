"""Structural surface for the cloud-SDK collector image/sidecar (issue #4239).

The collector ships the boto3/azure/google/snowflake SDK layer independently of
the control-plane release so it can be rebuilt/re-tagged on its own cadence
(daily CI refresh) WITHOUT a control-plane version bump. These tests assert the
shipped STRUCTURE — Dockerfile hardening + single-source-of-truth pins, and the
Helm chart wiring the cloud-scan CronJob to the collector image with a safe
fallback — not merely that `helm template` exits 0.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "deploy" / "docker" / "Dockerfile.collector"
CHART = ROOT / "deploy" / "helm" / "agent-bom"
PYPROJECT = ROOT / "pyproject.toml"

# Anchor SDK distributions the collector image exists to ship. Matches the
# provider extras in pyproject.toml (the single source of truth).
ANCHOR_SDKS = ("boto3", "azure-identity", "google-cloud-resource-manager", "snowflake-connector-python")


# ── Dockerfile structure ─────────────────────────────────────────────────────


def test_collector_dockerfile_exists() -> None:
    assert DOCKERFILE.is_file(), "deploy/docker/Dockerfile.collector must exist"


def test_collector_base_is_digest_pinned() -> None:
    text = DOCKERFILE.read_text()
    from_lines = [ln for ln in text.splitlines() if ln.strip().upper().startswith("FROM ")]
    assert from_lines, "no FROM line in collector Dockerfile"
    for ln in from_lines:
        assert "@sha256:" in ln, f"base image must be digest-pinned: {ln!r}"
        assert ":latest" not in ln, f"base image must not use :latest: {ln!r}"


def test_collector_runs_as_non_root_with_healthcheck() -> None:
    text = DOCKERFILE.read_text()
    assert re.search(r"^\s*USER\s+abom\s*$", text, re.M), "collector must drop to non-root USER abom"
    assert "HEALTHCHECK" in text, "collector must define a HEALTHCHECK"
    assert 'ENTRYPOINT ["agent-bom"]' in text, "collector entrypoint must be agent-bom"


def test_collector_installs_cloud_sdk_extras_not_hardcoded_versions() -> None:
    """The SDK groups come from pyproject and exact versions from uv.lock.

    Guards the single-source-of-truth contract with #3835's drift gate: the
    Dockerfile selects the requested extras from the reviewed ``uv.lock`` and
    must not pin any anchor SDK to a literal version of its own (which would
    silently fork the lockfile contract).
    """
    text = DOCKERFILE.read_text()
    assert "COPY --from=ghcr.io/astral-sh/uv:0.10.9@sha256:" in text
    assert "COPY pyproject.toml uv.lock README.md PYPI_README.md LICENSE ./" in text
    assert "uv sync --locked --no-dev --no-editable" in text
    assert "COPY --from=builder /app/.venv /app/.venv" in text
    assert 'pip install --no-cache-dir --prefix=/install ".[${AGENT_BOM_EXTRAS}]"' not in text
    default = re.search(r"^ARG AGENT_BOM_EXTRAS=(\S+)$", text, re.M)
    assert default, "collector must declare a default AGENT_BOM_EXTRAS build arg"
    extras = set(default.group(1).split(","))
    assert {"aws", "azure", "gcp"} <= extras, f"cloud provider extras missing from default: {extras}"
    # No literal SDK version pin re-declared in the Dockerfile.
    for sdk in ANCHOR_SDKS:
        assert not re.search(rf"{re.escape(sdk)}\s*[><=]=", text), f"{sdk} must not be re-pinned in the collector Dockerfile"


def test_collector_extras_resolve_to_real_pinned_sdks_in_pyproject() -> None:
    """The extras the collector installs actually declare the anchor SDK floors."""
    data = tomllib.loads(PYPROJECT.read_text())
    extras = data["project"]["optional-dependencies"]
    declared = " ".join(spec for group in ("aws", "azure", "gcp", "snowflake") for spec in extras[group])
    for sdk in ANCHOR_SDKS:
        assert f"{sdk}>=" in declared, f"{sdk} floor not declared in the provider extras (single source of truth)"


def test_collector_version_arg_matches_release_version() -> None:
    """The baked provenance VERSION stays in lockstep with the release (bump-version)."""
    version_match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(), re.M)
    assert version_match, "pyproject.toml version not found"
    version = version_match.group(1)
    arg = re.search(r"^ARG VERSION=([0-9]+\.[0-9]+\.[0-9]+)$", DOCKERFILE.read_text(), re.M)
    assert arg, "collector Dockerfile must carry an ARG VERSION"
    assert arg.group(1) == version, f"collector ARG VERSION {arg.group(1)} != pyproject {version}"


def test_collector_registered_in_docker_base_policy() -> None:
    import importlib.util
    import sys

    name = "check_docker_base_policy"
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "check_docker_base_policy.py")
    assert spec and spec.loader, "could not load check_docker_base_policy"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclass decorator resolves __module__ from sys.modules
    spec.loader.exec_module(mod)
    assert "deploy/docker/Dockerfile.collector" in mod.POLICY, "collector Dockerfile not registered in base policy"
    assert mod.main() == 0, "repo Dockerfiles must satisfy the base policy"


# ── Helm chart wiring ────────────────────────────────────────────────────────


def _helm_render(*set_values: str) -> list[dict]:
    if shutil.which("helm") is None:
        pytest.skip("helm not installed")
    args = ["helm", "template", "abom", str(CHART)]
    for value in set_values:
        args += ["--set", value]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return [doc for doc in yaml.safe_load_all(proc.stdout) if doc]


def _scan_cronjob(docs: list[dict]) -> dict:
    cronjobs = [d for d in docs if d.get("kind") == "CronJob"]
    scan = [c for c in cronjobs if c["metadata"]["name"].endswith("-scan")]
    assert scan, "no cloud-scan CronJob rendered"
    return scan[0]


def _scanner_container(cronjob: dict) -> dict:
    spec = cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    containers = [c for c in spec["containers"] if c["name"] == "scanner"]
    assert containers, "no scanner container in the scan CronJob"
    return containers[0]


def _project_version() -> str:
    match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(), re.M)
    assert match, "pyproject.toml version not found"
    return match.group(1)


def test_scan_cronjob_uses_collector_image_by_default() -> None:
    docs = _helm_render()
    container = _scanner_container(_scan_cronjob(docs))
    assert container["image"] == f"agentbom/agent-bom-collector:{_project_version()}", container["image"]


def test_collector_tag_overrides_independently_of_control_plane() -> None:
    """The SDK layer bumps without touching the control-plane image.tag (#4239)."""
    docs = _helm_render("collectorImage.tag=1.2.3-sdk", "image.tag=9.8.7")
    container = _scanner_container(_scan_cronjob(docs))
    assert container["image"] == "agentbom/agent-bom-collector:1.2.3-sdk", container["image"]
    # The control-plane API deployment stays on image.tag — unchanged.
    apis = [d for d in docs if d.get("kind") == "Deployment" and "api" in d["metadata"]["name"]]
    for api in apis:
        for c in api["spec"]["template"]["spec"]["containers"]:
            assert "agent-bom-collector" not in c["image"], "control-plane must not run the collector image"


def test_blank_collector_tag_falls_back_to_control_plane_tag() -> None:
    """A blank collector tag must never render a `repo:` reference with no tag."""
    docs = _helm_render("collectorImage.tag=", "image.tag=9.8.7")
    container = _scanner_container(_scan_cronjob(docs))
    assert container["image"].endswith(":9.8.7"), container["image"]
    assert not container["image"].rstrip().endswith(":"), "empty tag rendered"


def test_unset_collector_block_falls_back_to_control_plane_image() -> None:
    docs = _helm_render("collectorImage=null", "image.repository=agentbom/agent-bom", "image.tag=9.8.7")
    container = _scanner_container(_scan_cronjob(docs))
    assert container["image"] == "agentbom/agent-bom:9.8.7", container["image"]
