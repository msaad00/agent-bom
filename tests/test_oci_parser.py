"""Tests for agent_bom.oci_parser — native OCI image layer parser."""

from __future__ import annotations

import io
import json
import tarfile
import tempfile
from pathlib import Path

import pytest

from agent_bom.oci_parser import (
    OCIParseError,
    parse_oci_layout_dir,
    parse_oci_tarball,
    scan_oci,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_layer_tar(files: dict[str, bytes]) -> bytes:
    """Build an in-memory layer tarball from {path: content} dict."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for path, content in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _make_docker_save_tar(layers: list[dict[str, bytes]], repo_tags: list[str] | None = None) -> Path:
    """Build a Docker save-style tarball with given filesystem layers."""
    tmp = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
    layer_paths: list[str] = []

    with tarfile.open(fileobj=tmp, mode="w:") as outer:
        for i, layer_files in enumerate(layers):
            layer_data = _make_layer_tar(layer_files)
            layer_path = f"{i:040x}/layer.tar"
            layer_paths.append(layer_path)
            info = tarfile.TarInfo(name=layer_path)
            info.size = len(layer_data)
            outer.addfile(info, io.BytesIO(layer_data))

        # Write manifest.json
        manifest = [
            {
                "Config": "sha256:abc.json",
                "RepoTags": repo_tags or ["myapp:latest"],
                "Layers": layer_paths,
            }
        ]
        manifest_bytes = json.dumps(manifest).encode()
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest_bytes)
        outer.addfile(info, io.BytesIO(manifest_bytes))

    tmp.close()
    return Path(tmp.name)


def _make_oci_layout_tar(layers: list[dict[str, bytes]]) -> Path:
    """Build an OCI image layout tarball (index.json + blobs/sha256/)."""
    import hashlib

    tmp = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
    layer_descriptors = []

    with tarfile.open(fileobj=tmp, mode="w:") as outer:
        # Write layer blobs
        for layer_files in layers:
            layer_data = _make_layer_tar(layer_files)
            layer_hash = hashlib.sha256(layer_data).hexdigest()
            blob_path = f"blobs/sha256/{layer_hash}"
            info = tarfile.TarInfo(name=blob_path)
            info.size = len(layer_data)
            outer.addfile(info, io.BytesIO(layer_data))
            layer_descriptors.append(
                {"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": f"sha256:{layer_hash}", "size": len(layer_data)}
            )

        # Write manifest blob
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:config", "size": 0},
            "layers": layer_descriptors,
        }
        manifest_bytes = json.dumps(manifest).encode()
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        manifest_blob_path = f"blobs/sha256/{manifest_hash}"
        info = tarfile.TarInfo(name=manifest_blob_path)
        info.size = len(manifest_bytes)
        outer.addfile(info, io.BytesIO(manifest_bytes))

        # Write index.json
        index = {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": f"sha256:{manifest_hash}",
                    "size": len(manifest_bytes),
                }
            ],
        }
        index_bytes = json.dumps(index).encode()
        info = tarfile.TarInfo(name="index.json")
        info.size = len(index_bytes)
        outer.addfile(info, io.BytesIO(index_bytes))

    tmp.close()
    return Path(tmp.name)


def _make_oci_layout_dir(layers: list[dict[str, bytes]]) -> Path:
    """Build an OCI image layout directory on disk."""
    import hashlib

    tmpdir = Path(tempfile.mkdtemp())
    blobs_dir = tmpdir / "blobs" / "sha256"
    blobs_dir.mkdir(parents=True)

    layer_descriptors = []
    for layer_files in layers:
        layer_data = _make_layer_tar(layer_files)
        layer_hash = hashlib.sha256(layer_data).hexdigest()
        (blobs_dir / layer_hash).write_bytes(layer_data)
        layer_descriptors.append(
            {"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": f"sha256:{layer_hash}", "size": len(layer_data)}
        )

    manifest = {
        "schemaVersion": 2,
        "config": {"mediaType": "...", "digest": "sha256:config", "size": 0},
        "layers": layer_descriptors,
    }
    manifest_bytes = json.dumps(manifest).encode()
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    (blobs_dir / manifest_hash).write_bytes(manifest_bytes)

    index = {
        "schemaVersion": 2,
        "manifests": [{"mediaType": "...", "digest": f"sha256:{manifest_hash}", "size": len(manifest_bytes)}],
    }
    (tmpdir / "index.json").write_text(json.dumps(index))
    (tmpdir / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}))
    return tmpdir


# ── Sample layer file contents ────────────────────────────────────────────────

_DPKG_STATUS = b"""Package: bash
Version: 5.2.26-1
Status: install ok installed
Architecture: amd64

Package: curl
Version: 8.1.2-1
Status: install ok installed
Architecture: amd64

"""

_APK_INSTALLED = b"""P:busybox
V:1.36.1-r0
T:Size optimized toolbox of many common UNIX utilities

P:musl
V:1.2.4-r2
T:the musl c library (libc) implementation

"""

_METADATA_REQUESTS = b"""Metadata-Version: 2.1
Name: requests
Version: 2.31.0
"""

_METADATA_FLASK = b"""Metadata-Version: 2.1
Name: Flask
Version: 3.0.0
"""

_PACKAGE_JSON_EXPRESS = json.dumps({"name": "express", "version": "4.18.2"}).encode()
_PACKAGE_JSON_LODASH = json.dumps({"name": "lodash", "version": "4.17.21"}).encode()


# ── parse_oci_tarball — Docker save format ────────────────────────────────────


def test_docker_save_python_packages():
    tar = _make_docker_save_tar([{"requests-2.31.0.dist-info/METADATA": _METADATA_REQUESTS}])
    result = parse_oci_tarball(tar)
    assert result.strategy == "oci-tarball"
    assert result.layer_count == 1
    names = {p.name for p in result.packages}
    assert "requests" in names


def test_docker_save_node_packages():
    tar = _make_docker_save_tar([{"usr/lib/node_modules/express/package.json": _PACKAGE_JSON_EXPRESS}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "express" in names


def test_docker_save_debian_packages():
    tar = _make_docker_save_tar([{"var/lib/dpkg/status": _DPKG_STATUS}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "bash" in names
    assert "curl" in names


def test_docker_save_alpine_packages():
    tar = _make_docker_save_tar([{"lib/apk/db/installed": _APK_INSTALLED}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "busybox" in names
    assert "musl" in names


def test_docker_save_multi_layer_dedup():
    """Same package in two layers is only reported once."""
    tar = _make_docker_save_tar(
        [
            {"requests-2.31.0.dist-info/METADATA": _METADATA_REQUESTS},
            {"requests-2.31.0.dist-info/METADATA": _METADATA_REQUESTS},
        ]
    )
    result = parse_oci_tarball(tar)
    names = [p.name for p in result.packages]
    assert names.count("requests") == 1


def test_docker_save_multi_layer_multi_ecosystem():
    """Packages from different layers and ecosystems all collected."""
    tar = _make_docker_save_tar(
        [
            {"var/lib/dpkg/status": _DPKG_STATUS},
            {"requests-2.31.0.dist-info/METADATA": _METADATA_REQUESTS},
            {"usr/lib/node_modules/express/package.json": _PACKAGE_JSON_EXPRESS},
        ]
    )
    result = parse_oci_tarball(tar)
    assert result.layer_count == 3
    names = {p.name for p in result.packages}
    assert "bash" in names
    assert "requests" in names
    assert "express" in names


def test_docker_save_repo_tags():
    tar = _make_docker_save_tar([{}], repo_tags=["myapp:v1.0"])
    result = parse_oci_tarball(tar)
    assert result.image_tags == ["myapp:v1.0"]


def test_docker_save_empty_layers():
    tar = _make_docker_save_tar([{}, {}])
    result = parse_oci_tarball(tar)
    assert result.packages == []
    assert result.layer_count == 2


def test_docker_save_package_purl():
    tar = _make_docker_save_tar([{"var/lib/dpkg/status": _DPKG_STATUS}])
    result = parse_oci_tarball(tar)
    purls = {p.purl for p in result.packages}
    assert any("pkg:deb" in pu for pu in purls)


# ── parse_oci_tarball — OCI layout format ─────────────────────────────────────


def test_oci_layout_tar_python():
    tar = _make_oci_layout_tar([{"Flask-3.0.0.dist-info/METADATA": _METADATA_FLASK}])
    result = parse_oci_tarball(tar)
    assert result.strategy == "oci-tarball"
    names = {p.name for p in result.packages}
    assert "Flask" in names


def test_oci_layout_tar_node():
    tar = _make_oci_layout_tar([{"usr/lib/node_modules/lodash/package.json": _PACKAGE_JSON_LODASH}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "lodash" in names


def test_oci_layout_tar_multi_layer():
    tar = _make_oci_layout_tar(
        [
            {"var/lib/dpkg/status": _DPKG_STATUS},
            {"Flask-3.0.0.dist-info/METADATA": _METADATA_FLASK},
        ]
    )
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "bash" in names
    assert "Flask" in names


# ── parse_oci_layout_dir ──────────────────────────────────────────────────────


def test_oci_layout_dir_python():
    layout_dir = _make_oci_layout_dir([{"requests-2.31.0.dist-info/METADATA": _METADATA_REQUESTS}])
    result = parse_oci_layout_dir(layout_dir)
    assert result.strategy == "oci-layout-dir"
    names = {p.name for p in result.packages}
    assert "requests" in names


def test_oci_layout_dir_alpine():
    layout_dir = _make_oci_layout_dir([{"lib/apk/db/installed": _APK_INSTALLED}])
    result = parse_oci_layout_dir(layout_dir)
    names = {p.name for p in result.packages}
    assert "busybox" in names


def test_oci_layout_dir_multi_layer():
    layout_dir = _make_oci_layout_dir(
        [
            {"lib/apk/db/installed": _APK_INSTALLED},
            {"requests-2.31.0.dist-info/METADATA": _METADATA_REQUESTS},
        ]
    )
    result = parse_oci_layout_dir(layout_dir)
    names = {p.name for p in result.packages}
    assert "busybox" in names
    assert "requests" in names


# ── Error cases ───────────────────────────────────────────────────────────────


def test_parse_oci_tarball_not_found():
    with pytest.raises(OCIParseError, match="not found"):
        parse_oci_tarball(Path("/nonexistent/image.tar"))


def test_parse_oci_tarball_invalid_format():
    """A tarball without manifest.json or index.json raises OCIParseError."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        data = b"hello"
        info = tarfile.TarInfo("some_other_file.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    tmp = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
    tmp.write(buf.getvalue())
    tmp.close()
    with pytest.raises(OCIParseError, match="Unrecognized"):
        parse_oci_tarball(Path(tmp.name))


def test_parse_oci_layout_dir_not_directory():
    with pytest.raises(OCIParseError, match="Not a directory"):
        parse_oci_layout_dir(Path("/nonexistent/dir"))


def test_parse_oci_layout_dir_missing_index():
    tmpdir = Path(tempfile.mkdtemp())
    with pytest.raises(OCIParseError, match="index.json"):
        parse_oci_layout_dir(tmpdir)


# ── scan_oci auto-detection ───────────────────────────────────────────────────


def test_scan_oci_tarball_auto():
    tar = _make_docker_save_tar([{"var/lib/dpkg/status": _DPKG_STATUS}])
    packages, strategy = scan_oci(tar)
    assert strategy == "oci-tarball"
    assert any(p.name == "bash" for p in packages)


def test_scan_oci_layout_dir_auto():
    layout_dir = _make_oci_layout_dir([{"lib/apk/db/installed": _APK_INSTALLED}])
    packages, strategy = scan_oci(layout_dir)
    assert strategy == "oci-layout-dir"
    assert any(p.name == "busybox" for p in packages)


# ── Whiteout handling ─────────────────────────────────────────────────────────


def test_whiteout_path_collected():
    """Whiteout files are collected per layer (basic smoke test)."""
    # A layer with a whiteout for a file
    layer_files = {".wh.var/lib/dpkg/status": b""}
    tar = _make_docker_save_tar([layer_files])
    result = parse_oci_tarball(tar)
    # No packages from whiteout-only layer
    assert result.packages == []
