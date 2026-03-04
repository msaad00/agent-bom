"""Tests for Docker image scanning: registry auth, multi-arch, and platform support."""

from __future__ import annotations

import json
import shutil
import subprocess

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.image import (
    ImageScanError,
    _build_scanner_env,
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


# ─── Grype auth + platform passthrough ───────────────────────────────────────


def test_grype_auth_env_passed(monkeypatch):
    """Auth env vars are passed to Grype subprocess."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = kwargs.get("env")

        class R:
            returncode = 0
            stdout = json.dumps({"matches": []})
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    scan_image("myapp:latest", registry_user="user1", registry_pass="pass1")
    assert captured["env"]["GRYPE_REGISTRY_AUTH_USERNAME"] == "user1"
    assert captured["env"]["GRYPE_REGISTRY_AUTH_PASSWORD"] == "pass1"


def test_grype_platform_flag(monkeypatch):
    """Platform flag is passed to Grype command."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)

        class R:
            returncode = 0
            stdout = json.dumps({"matches": []})
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    scan_image("myapp:latest", platform="linux/arm64")
    assert "--platform" in captured["cmd"]
    assert "linux/arm64" in captured["cmd"]


def test_grype_no_auth_env_when_none(monkeypatch):
    """No auth env when no credentials provided."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)
    # Clear any env vars that might interfere
    monkeypatch.delenv("AGENT_BOM_REGISTRY_USER", raising=False)
    monkeypatch.delenv("AGENT_BOM_REGISTRY_PASS", raising=False)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["env"] = kwargs.get("env")

        class R:
            returncode = 0
            stdout = json.dumps({"matches": []})
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    scan_image("myapp:latest")
    assert captured["env"] is None  # No custom env = inherit parent


# ─── Syft auth + platform passthrough ────────────────────────────────────────


def test_syft_auth_env_passed(monkeypatch):
    """Auth env vars are passed to Syft subprocess."""
    # Make grype unavailable, syft available
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/syft" if cmd == "syft" else None)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = kwargs.get("env")

        class R:
            returncode = 0
            stdout = json.dumps({"components": []})
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    scan_image("myapp:latest", registry_user="user2", registry_pass="pass2")
    assert captured["env"]["SYFT_REGISTRY_AUTH_USERNAME"] == "user2"
    assert captured["env"]["SYFT_REGISTRY_AUTH_PASSWORD"] == "pass2"


def test_syft_platform_flag(monkeypatch):
    """Platform flag is passed to Syft command."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/syft" if cmd == "syft" else None)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)

        class R:
            returncode = 0
            stdout = json.dumps({"components": []})
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    scan_image("myapp:latest", platform="linux/amd64")
    assert "--platform" in captured["cmd"]
    assert "linux/amd64" in captured["cmd"]


# ─── Docker platform passthrough ─────────────────────────────────────────────


def test_docker_pull_platform_flag(monkeypatch):
    """Platform flag is passed to docker pull command."""
    # Make grype/syft unavailable, docker available
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/docker" if cmd == "docker" else None)
    captured_cmds = []

    def fake_run(cmd, **kwargs):
        captured_cmds.append(list(cmd))

        class R:
            pass

        r = R()
        # docker inspect fails first time (triggers pull)
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
        elif "create" in cmd:
            r.returncode = 0
            r.stdout = "container123"
            r.stderr = ""
        elif "export" in cmd:
            # Create a minimal tar
            r.returncode = 1  # Let it fail — we just want to test the pull command
            r.stdout = ""
            r.stderr = "export failed"
        elif "rm" in cmd:
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
        else:
            r.returncode = 0
            r.stdout = ""
            r.stderr = ""
        return r

    monkeypatch.setattr(subprocess, "run", fake_run)
    try:
        scan_image("myapp:latest", platform="linux/arm64")
    except ImageScanError:
        pass  # Expected — docker export fails

    # Find the pull command
    pull_cmds = [c for c in captured_cmds if "pull" in c]
    assert len(pull_cmds) > 0
    assert "--platform" in pull_cmds[0]
    assert "linux/arm64" in pull_cmds[0]


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
