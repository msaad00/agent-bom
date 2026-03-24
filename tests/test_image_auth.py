"""Tests for native Docker image scanning: auth helpers, pull behavior, and platform support."""

from __future__ import annotations

import json
import shutil
import subprocess

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.image import (
    ImageScanError,
    _build_scanner_env,
    _docker_inspect,
    _scan_with_docker,
    detect_multi_arch,
    scan_image,
)

# ─── _build_scanner_env ─────────────────────────────────────────────────────


def test_build_scanner_env_with_creds():
    """Auth credentials are set in env dict."""
    env = _build_scanner_env("myuser", "mypass", "GRYPE")
    assert env is not None
    assert env["GRYPE_REGISTRY_AUTH_USERNAME"] == "myuser"
    assert env["GRYPE_REGISTRY_AUTH_PASSWORD"] == "mypass"


def test_build_scanner_env_no_creds():
    """Returns None when no credentials provided."""
    env = _build_scanner_env(None, None, "GRYPE")
    assert env is None


def test_build_scanner_env_fallback_envvar(monkeypatch):
    """Falls back to AGENT_BOM_REGISTRY_USER/PASS env vars."""
    monkeypatch.setenv("AGENT_BOM_REGISTRY_USER", "envuser")
    monkeypatch.setenv("AGENT_BOM_REGISTRY_PASS", "envpass")
    env = _build_scanner_env(None, None, "SYFT")
    assert env is not None
    assert env["SYFT_REGISTRY_AUTH_USERNAME"] == "envuser"
    assert env["SYFT_REGISTRY_AUTH_PASSWORD"] == "envpass"


def test_build_scanner_env_explicit_overrides_envvar(monkeypatch):
    """Explicit credentials override env vars."""
    monkeypatch.setenv("AGENT_BOM_REGISTRY_USER", "envuser")
    monkeypatch.setenv("AGENT_BOM_REGISTRY_PASS", "envpass")
    env = _build_scanner_env("explicit", "secret", "GRYPE")
    assert env["GRYPE_REGISTRY_AUTH_USERNAME"] == "explicit"


# ─── Native image scan behavior ──────────────────────────────────────────────


def test_scan_image_uses_native_docker_scanner(monkeypatch):
    """scan_image delegates to the native Docker-backed scanner."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/docker" if cmd == "docker" else None)
    captured = {}

    def fake_scan(image_ref, platform=None):
        captured["image_ref"] = image_ref
        captured["platform"] = platform
        return []

    monkeypatch.setattr("agent_bom.image._scan_with_docker", fake_scan)
    _packages, strategy = scan_image("myapp:latest", platform="linux/arm64")
    assert captured["image_ref"] == "myapp:latest"
    assert captured["platform"] == "linux/arm64"
    assert strategy == "native"


def test_scan_image_no_docker(monkeypatch):
    """scan_image raises when Docker is unavailable."""
    monkeypatch.setattr(shutil, "which", lambda _: None)
    try:
        scan_image("myapp:latest")
        assert False, "Expected ImageScanError"
    except ImageScanError as e:
        assert "Docker is not available" in str(e)


# ─── Docker platform passthrough ─────────────────────────────────────────────


def test_docker_pull_platform_flag(monkeypatch):
    """Platform flag is passed to docker pull command."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/docker" if cmd == "docker" else None)
    captured_cmds = []

    def fake_run(cmd, **kwargs):
        captured_cmds.append(list(cmd))

        class R:
            pass

        r = R()
        if "inspect" in cmd and len(captured_cmds) == 1:
            r.returncode = 1
            r.stdout = ""
            r.stderr = "No such image"
        elif "pull" in cmd:
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
        elif "inspect" in cmd:
            r.returncode = 0
            r.stdout = json.dumps([{"Config": {}}])
            r.stderr = ""
        elif "save" in cmd:
            r.returncode = 1
            r.stdout = ""
            r.stderr = "save failed"
        else:
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
        return r

    monkeypatch.setattr(subprocess, "run", fake_run)
    try:
        _docker_inspect("myapp:latest", platform="linux/arm64")
    except ImageScanError:
        pass

    pull_cmds = [c for c in captured_cmds if "pull" in c]
    assert len(pull_cmds) > 0
    assert "--platform" in pull_cmds[0]
    assert "linux/arm64" in pull_cmds[0]


def test_native_scan_errors_on_zero_extracted_packages(monkeypatch, tmp_path):
    """Native image scan must fail loudly when both OCI and export paths extract nothing."""
    monkeypatch.setattr("agent_bom.image._docker_inspect", lambda image_ref, platform=None: {"Config": {}})
    monkeypatch.setattr("agent_bom.oci_parser.scan_oci", lambda path: ([], "oci-tarball"))
    monkeypatch.setattr("agent_bom.image._packages_from_tar", lambda path: [])

    save_result = subprocess.CompletedProcess(["docker", "save"], 0, "", "")
    create_result = subprocess.CompletedProcess(["docker", "create"], 0, "container123\n", "")
    export_result = subprocess.CompletedProcess(["docker", "export"], 0, b"", b"")
    rm_result = subprocess.CompletedProcess(["docker", "rm"], 0, "", "")
    results = iter([save_result, create_result, export_result, rm_result])

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: next(results),
    )

    try:
        _scan_with_docker("myapp:latest")
        assert False, "Expected ImageScanError"
    except ImageScanError as e:
        assert "0 packages" in str(e)


# ─── detect_multi_arch ───────────────────────────────────────────────────────


def test_detect_multi_arch_parsing(monkeypatch):
    """detect_multi_arch parses manifest inspect JSON."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/docker")
    manifest_data = {
        "manifests": [
            {"platform": {"os": "linux", "architecture": "amd64"}},
            {"platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
            {"platform": {"os": "linux", "architecture": "arm", "variant": "v7"}},
        ]
    }

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 0
            stdout = json.dumps(manifest_data)
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    platforms = detect_multi_arch("nginx:latest")
    assert "linux/amd64" in platforms
    assert "linux/arm64/v8" in platforms
    assert "linux/arm/v7" in platforms


def test_detect_multi_arch_no_docker(monkeypatch):
    """detect_multi_arch returns empty when docker unavailable."""
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert detect_multi_arch("nginx:latest") == []


def test_detect_multi_arch_not_manifest_list(monkeypatch):
    """detect_multi_arch returns empty for non-manifest images."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/docker")

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 1
            stdout = ""
            stderr = "not a manifest list"

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert detect_multi_arch("custom:dev") == []


# ─── CLI options ─────────────────────────────────────────────────────────────


def test_scan_cli_has_registry_options():
    """scan --help includes registry auth and platform options."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--registry-user" in result.output
    assert "--registry-pass" in result.output
    assert "--platform" in result.output
