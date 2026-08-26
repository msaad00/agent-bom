"""Regression coverage for OCI package artifacts that were previously false-clean."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.oci_parser import scan_oci
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings


def _docker_save_tar(tmp_path: Path, member_path: str, content: bytes) -> Path:
    layer_buffer = io.BytesIO()
    with tarfile.open(fileobj=layer_buffer, mode="w:") as layer:
        member = tarfile.TarInfo(member_path)
        member.size = len(content)
        layer.addfile(member, io.BytesIO(content))

    layer_path = "0" * 40 + "/layer.tar"
    manifest = json.dumps(
        [
            {
                "Config": "config.json",
                "RepoTags": ["coverage:test"],
                "Layers": [layer_path],
            }
        ]
    ).encode()
    image_path = tmp_path / "image.tar"
    with tarfile.open(image_path, mode="w:") as image:
        layer_member = tarfile.TarInfo(layer_path)
        layer_member.size = len(layer_buffer.getvalue())
        image.addfile(layer_member, io.BytesIO(layer_buffer.getvalue()))

        manifest_member = tarfile.TarInfo("manifest.json")
        manifest_member.size = len(manifest)
        image.addfile(manifest_member, io.BytesIO(manifest))

    return image_path


_MALFORMED_PACKAGE_ARTIFACTS: tuple[tuple[str, bytes], ...] = (
    ("usr/lib/python/site-packages/broken.dist-info/METADATA", b"Metadata-Version: 2.1\nName: broken\n"),
    ("usr/lib/python/site-packages/broken.egg-info/PKG-INFO", b"Metadata-Version: 1.2\nVersion: 1.0\n"),
    ("usr/lib/python/site-packages/other.egg-info/METADATA", b"not-rfc822-package-metadata"),
    ("usr/lib/node_modules/broken/package.json", b"{not-json"),
    ("var/lib/dpkg/status", b"Package: broken\nDescription: missing version\n"),
    ("lib/apk/db/installed", b"P:broken\nA:x86_64\n"),
    ("var/log/installed-rpms", b"not-an-rpm-nevra\n"),
    ("var/lib/rpm/rpmdb.sqlite", b"not-a-sqlite-database"),
    ("opt/app/broken.jar", b"not-a-zip-archive"),
    ("usr/local/lib/ruby/gems/3.3.0/specifications/broken.gemspec", b"Gem::Specification.new do |s|\nend\n"),
    ("app/broken.deps.json", b"{not-json"),
    ("app/composer.lock", b"{not-json"),
    ("var/www/composer.lock", b"{not-json"),
    ("var/www/html/composer.lock", b"{not-json"),
    ("srv/composer.lock", b"{not-json"),
    ("home/composer.lock", b"{not-json"),
    ("app/Cargo.lock", b'[[package]]\nname = "broken"\n'),
    ("usr/src/Cargo.lock", b'[[package]]\nversion = "1.0.0"\n'),
    ("home/Cargo.lock", b"[[package]]\nnot valid package metadata\n"),
    ("opt/Cargo.lock", b'[[package]]\nname = "broken"\n'),
    ("srv/Cargo.lock", b'[[package]]\nversion = "1.0.0"\n'),
    ("app/Package.resolved", b"{not-json"),
    ("Package.resolved", b"{not-json"),
    ("Sources/Package.resolved", b"{not-json"),
)


@pytest.fixture(autouse=True)
def _reset_coverage_state() -> None:
    reset_scan_warnings()
    yield
    reset_scan_warnings()


@pytest.mark.parametrize(("member_path", "content"), _MALFORMED_PACKAGE_ARTIFACTS)
def test_malformed_oci_package_artifact_records_partial_coverage(
    tmp_path: Path,
    member_path: str,
    content: bytes,
) -> None:
    image_path = _docker_save_tar(tmp_path, member_path, content)

    packages, strategy = scan_oci(image_path)

    assert packages == []
    assert strategy == "oci-tarball"
    assert consume_coverage_warnings() == [
        {
            "ecosystem": "oci",
            "release": f"oci:{member_path}",
            "reason": "package_metadata_parse_error",
            "detail": "Container package metadata could not be parsed; image inventory is incomplete.",
            "package_count": 0,
            "advisory_rows": 0,
        }
    ]


def test_clean_oci_package_artifact_does_not_record_partial_coverage(tmp_path: Path) -> None:
    image_path = _docker_save_tar(
        tmp_path,
        "usr/lib/node_modules/example/package.json",
        b'{"name":"example","version":"1.2.3"}',
    )

    packages, _strategy = scan_oci(image_path)

    assert [(package.name, package.version) for package in packages] == [("example", "1.2.3")]
    assert consume_coverage_warnings() == []


def test_node_package_subpath_manifest_is_not_a_package_metadata_gap(tmp_path: Path) -> None:
    """Node export-condition manifests beneath a package root are not packages."""
    image_path = _docker_save_tar(
        tmp_path,
        "usr/lib/node_modules/nanoid/non-secure/package.json",
        b'{"type":"module"}',
    )

    packages, _strategy = scan_oci(image_path)

    assert packages == []
    assert consume_coverage_warnings() == []


def test_scoped_node_package_root_manifest_remains_inventory(tmp_path: Path) -> None:
    """Scoped npm package roots remain candidates after subpath filtering."""
    image_path = _docker_save_tar(
        tmp_path,
        "usr/lib/node_modules/@scope/example/package.json",
        b'{"name":"@scope/example","version":"1.2.3"}',
    )

    packages, _strategy = scan_oci(image_path)

    assert [(package.name, package.version, package.ecosystem) for package in packages] == [("@scope/example", "1.2.3", "npm")]
    assert consume_coverage_warnings() == []


def test_oci_coverage_warning_surfaces_in_scan_report(tmp_path: Path) -> None:
    image_path = _docker_save_tar(tmp_path, "app/broken.deps.json", b"{not-json")
    output_path = tmp_path / "report.json"

    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--image-tar",
            str(image_path),
            "--offline",
            "--no-auto-update-db",
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["scan_run"]["outcome"] == "partial"
    oci_warnings = [warning for warning in payload["coverage_warnings"] if warning.get("ecosystem") == "oci"]
    assert oci_warnings == [
        {
            "ecosystem": "oci",
            "release": "oci:app/broken.deps.json",
            "reason": "package_metadata_parse_error",
            "detail": "Container package metadata could not be parsed; image inventory is incomplete.",
            "package_count": 0,
            "advisory_rows": 0,
        }
    ]
