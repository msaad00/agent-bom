"""Regression tests for optional Grype archive fallback on image tar scans."""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.image import ImageScanError, scan_image_tar


def test_scan_image_tar_grype_fallback_uses_archive_target(monkeypatch, tmp_path: Path) -> None:
    grype_output = {
        "matches": [
            {
                "artifact": {"name": "busybox", "version": "1.35.0-r17", "type": "apk"},
                "vulnerability": {
                    "id": "CVE-2023-42366",
                    "severity": "High",
                    "description": "busybox issue",
                    "fix": {"versions": ["1.35.0-r18"]},
                },
            }
        ]
    }
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))

        class Result:
            returncode = 0
            stdout = json.dumps(grype_output)
            stderr = ""

        return Result()

    monkeypatch.setenv("AGENT_BOM_IMAGE_GRYPE_FALLBACK", "1")
    monkeypatch.setattr("agent_bom.image.subprocess.run", fake_run)
    monkeypatch.setattr("agent_bom.image.shutil.which", lambda name: "/usr/bin/grype" if name == "grype" else None)
    monkeypatch.setattr(
        "agent_bom.oci_parser.scan_oci",
        lambda path: ([], "oci-tarball"),
    )

    tar_path = tmp_path / "alpine.tar"
    tar_path.write_bytes(b"not-a-real-tar")

    packages, strategy = scan_image_tar(str(tar_path))
    assert strategy == "grype-archive"
    assert len(packages) == 1
    assert packages[0].name == "busybox"
    assert packages[0].vulnerabilities[0].id == "CVE-2023-42366"
    assert calls
    assert calls[0][1].startswith("docker-archive:")


def test_scan_image_tar_grype_fallback_disabled_keeps_native(monkeypatch, tmp_path: Path) -> None:
    from agent_bom.models import Package

    native_pkg = Package(name="apk-tools", version="2.12.9-r3", ecosystem="apk")

    monkeypatch.delenv("AGENT_BOM_IMAGE_GRYPE_FALLBACK", raising=False)
    monkeypatch.setattr(
        "agent_bom.oci_parser.scan_oci",
        lambda path: ([native_pkg], "oci-tarball"),
    )

    tar_path = tmp_path / "image.tar"
    tar_path.write_bytes(b"tar")

    packages, strategy = scan_image_tar(str(tar_path))
    assert strategy == "oci-tarball"
    assert packages == [native_pkg]


def test_scan_image_tar_grype_fallback_failure_falls_back_to_native(monkeypatch, tmp_path: Path) -> None:
    from agent_bom.models import Package

    native_pkg = Package(name="musl", version="1.2.3-r3", ecosystem="apk")

    def fake_grype(_target, **kwargs):
        raise ImageScanError("grype not found")

    monkeypatch.setenv("AGENT_BOM_IMAGE_GRYPE_FALLBACK", "1")
    monkeypatch.setattr("agent_bom.image._run_grype_json", fake_grype)
    monkeypatch.setattr("agent_bom.image._grype_available", lambda: True)
    monkeypatch.setattr(
        "agent_bom.oci_parser.scan_oci",
        lambda path: ([native_pkg], "oci-tarball"),
    )

    tar_path = tmp_path / "image.tar"
    tar_path.write_bytes(b"tar")

    packages, strategy = scan_image_tar(str(tar_path))
    assert strategy == "oci-tarball"
    assert packages == [native_pkg]
