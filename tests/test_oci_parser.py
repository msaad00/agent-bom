"""Tests for agent_bom.oci_parser — native OCI image layer parser."""

from __future__ import annotations

import io
import json
import sqlite3
import struct
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

from agent_bom.oci_parser import (
    _RPM_HDR_MAGIC,
    _RPM_TYPE_STRING,
    _RPMTAG_NAME,
    _RPMTAG_RELEASE,
    _RPMTAG_VERSION,
    OCIParseError,
    _decompression_ratio_exceeded,
    _zip_compressed_size,
    _zip_uncompressed_size,
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


def _make_docker_save_tar(
    layers: list[dict[str, bytes]],
    repo_tags: list[str] | None = None,
    history: list[dict] | None = None,
) -> Path:
    """Build a Docker save-style tarball with given filesystem layers."""
    tmp = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
    layer_paths: list[str] = []
    config_path = "sha256:abc.json"

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
                "Config": config_path,
                "RepoTags": repo_tags or ["myapp:latest"],
                "Layers": layer_paths,
            }
        ]
        manifest_bytes = json.dumps(manifest).encode()
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest_bytes)
        outer.addfile(info, io.BytesIO(manifest_bytes))

        if history is not None:
            config_bytes = json.dumps({"history": history}).encode()
            info = tarfile.TarInfo(name=config_path)
            info.size = len(config_bytes)
            outer.addfile(info, io.BytesIO(config_bytes))

    tmp.close()
    return Path(tmp.name)


def _make_oci_layout_tar(layers: list[dict[str, bytes]], history: list[dict] | None = None) -> Path:
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

        config_bytes = json.dumps({"history": history or []}).encode()
        config_hash = hashlib.sha256(config_bytes).hexdigest()
        config_blob_path = f"blobs/sha256/{config_hash}"
        info = tarfile.TarInfo(name=config_blob_path)
        info.size = len(config_bytes)
        outer.addfile(info, io.BytesIO(config_bytes))

        # Write manifest blob
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": f"sha256:{config_hash}",
                "size": len(config_bytes),
            },
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


def _make_oci_layout_dir(layers: list[dict[str, bytes]], history: list[dict] | None = None) -> Path:
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

    config_bytes = json.dumps({"history": history or []}).encode()
    config_hash = hashlib.sha256(config_bytes).hexdigest()
    (blobs_dir / config_hash).write_bytes(config_bytes)

    manifest = {
        "schemaVersion": 2,
        "config": {"mediaType": "...", "digest": f"sha256:{config_hash}", "size": len(config_bytes)},
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


def test_docker_save_tracks_layer_occurrences_and_instruction():
    tar = _make_docker_save_tar(
        [{"requests-2.31.0.dist-info/METADATA": _METADATA_REQUESTS}],
        history=[{"created_by": "/bin/sh -c pip install requests==2.31.0"}],
    )
    result = parse_oci_tarball(tar)
    pkg = next(p for p in result.packages if p.name == "requests")
    assert len(pkg.occurrences) == 1
    occ = pkg.occurrences[0]
    assert occ.layer_index == 1
    assert occ.package_path == "requests-2.31.0.dist-info/METADATA"
    assert occ.created_by == "/bin/sh -c pip install requests==2.31.0"
    assert occ.dockerfile_instruction == "RUN pip install requests==2.31.0"


def test_docker_save_latest_layer_version_wins():
    tar = _make_docker_save_tar(
        [
            {"requests-2.31.0.dist-info/METADATA": _METADATA_REQUESTS},
            {"requests-2.32.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: requests\nVersion: 2.32.0\n"},
        ],
        history=[
            {"created_by": "/bin/sh -c pip install requests==2.31.0"},
            {"created_by": "/bin/sh -c pip install --upgrade requests==2.32.0"},
        ],
    )
    result = parse_oci_tarball(tar)
    pkg = next(p for p in result.packages if p.name == "requests")
    assert pkg.version == "2.32.0"
    assert len(pkg.occurrences) == 1
    assert pkg.occurrences[0].layer_index == 2
    assert pkg.occurrences[0].dockerfile_instruction == "RUN pip install --upgrade requests==2.32.0"


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


def test_docker_save_skips_layer_over_uncompressed_limit(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_LAYER_UNCOMPRESSED_BYTES", "10")
    tar = _make_docker_save_tar([{"huge.txt": b"x" * 11}])

    result = parse_oci_tarball(tar)

    assert result.packages == []
    assert any("uncompressed extraction limit" in warning for warning in result.warnings)


def test_decompression_ratio_guard_is_configurable(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_OCI_MAX_DECOMPRESSION_RATIO", "10")

    assert _decompression_ratio_exceeded(101, 10) is True
    assert _decompression_ratio_exceeded(100, 10) is False


def test_zip_size_helpers_measure_compressed_and_uncompressed_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.txt", b"x" * 4096)
    with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
        assert _zip_uncompressed_size(zf) == 4096
        assert _zip_compressed_size(zf) < 4096


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


def test_oci_layout_dir_tracks_layer_instruction():
    layout_dir = _make_oci_layout_dir(
        [{"usr/lib/node_modules/express/package.json": _PACKAGE_JSON_EXPRESS}],
        history=[{"created_by": "/bin/sh -c #(nop)  RUN npm install express"}],
    )
    result = parse_oci_layout_dir(layout_dir)
    pkg = next(p for p in result.packages if p.name == "express")
    assert pkg.occurrences[0].layer_index == 1
    assert pkg.occurrences[0].dockerfile_instruction == "RUN npm install express"


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


# ── Java JAR parsing ──────────────────────────────────────────────────────────


def _make_jar(pom_props: dict[str, str] | None = None, manifest_mf: dict[str, str] | None = None) -> bytes:
    """Build an in-memory JAR with optional pom.properties and MANIFEST.MF."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        if pom_props is not None:
            group_id = pom_props.get("groupId", "com.example")
            artifact_id = pom_props.get("artifactId", "mylib")
            lines = "\n".join(f"{k}={v}" for k, v in pom_props.items())
            zf.writestr(f"META-INF/maven/{group_id}/{artifact_id}/pom.properties", lines)
        if manifest_mf is not None:
            lines = "\n".join(f"{k}: {v}" for k, v in manifest_mf.items()) + "\n"
            zf.writestr("META-INF/MANIFEST.MF", lines)
    return buf.getvalue()


def test_jar_pom_properties():
    """JAR with pom.properties extracted correctly."""
    jar = _make_jar(pom_props={"groupId": "org.apache", "artifactId": "commons-lang3", "version": "3.12.0"})
    tar = _make_docker_save_tar([{"usr/share/java/commons-lang3.jar": jar}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "commons-lang3" in names
    pkg = next(p for p in result.packages if p.name == "commons-lang3")
    assert pkg.version == "3.12.0"
    assert pkg.ecosystem == "maven"
    assert "pkg:maven/org.apache/commons-lang3@3.12.0" == pkg.purl


def test_jar_manifest_mf_fallback():
    """JAR with MANIFEST.MF used when no pom.properties."""
    jar = _make_jar(manifest_mf={"Implementation-Title": "MyLib", "Implementation-Version": "2.0.1"})
    tar = _make_docker_save_tar([{"opt/app/mylib.jar": jar}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "MyLib" in names


def test_jar_bundle_manifest_fallback():
    """OSGI Bundle-Name/Bundle-Version in MANIFEST.MF."""
    jar = _make_jar(manifest_mf={"Bundle-Name": "guava", "Bundle-Version": "32.1.3"})
    tar = _make_docker_save_tar([{"usr/local/lib/guava.jar": jar}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "guava" in names


def test_jar_outside_known_dirs_skipped():
    """JARs outside known directories are not scanned (performance guard)."""
    jar = _make_jar(pom_props={"groupId": "x", "artifactId": "hidden", "version": "1.0"})
    tar = _make_docker_save_tar([{"proc/1234/hidden.jar": jar}])
    result = parse_oci_tarball(tar)
    assert not any(p.name == "hidden" for p in result.packages)


def test_jar_pom_and_manifest_dedup():
    """Same artifact from two JARs in same layer only counted once."""
    jar = _make_jar(pom_props={"groupId": "org.apache", "artifactId": "log4j", "version": "2.20.0"})
    tar = _make_docker_save_tar(
        [
            {
                "usr/share/java/log4j-core.jar": jar,
                "usr/share/java/log4j-api.jar": jar,
            }
        ]
    )
    result = parse_oci_tarball(tar)
    assert sum(1 for p in result.packages if p.name == "log4j") == 1


# ── Go binary parsing ─────────────────────────────────────────────────────────


def _make_go_binary(deps: list[tuple[str, str]]) -> bytes:
    """Build a fake Go binary blob containing embedded build info text."""
    # Go buildinfo magic (14 bytes) + 4 bytes padding, then dep lines
    header = b"\xff Go buildinf:\x00\x00\x00\x00"
    dep_block = b""
    for mod_path, mod_ver in deps:
        dep_block += f"\ndep\t{mod_path}\t{mod_ver}\th1:abc=\n".encode()
    # Pad to realistic minimum size (real Go binaries are always >> 1 KB)
    content = header + dep_block
    return content + b"\x00" * max(0, 256 - len(content))


def test_go_binary_deps_extracted():
    """Go binary deps extracted from embedded buildinfo."""
    binary = _make_go_binary(
        [
            ("github.com/gin-gonic/gin", "v1.9.1"),
            ("golang.org/x/net", "v0.21.0"),
        ]
    )
    tar = _make_docker_save_tar([{"usr/bin/myapp": binary}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "github.com/gin-gonic/gin" in names
    assert "golang.org/x/net" in names


def test_go_binary_version_correct():
    """Go binary dep version extracted correctly."""
    binary = _make_go_binary([("github.com/spf13/cobra", "v1.8.0")])
    tar = _make_docker_save_tar([{"usr/local/bin/kubectl": binary}])
    result = parse_oci_tarball(tar)
    pkg = next((p for p in result.packages if p.name == "github.com/spf13/cobra"), None)
    assert pkg is not None
    assert pkg.version == "v1.8.0"
    assert pkg.ecosystem == "golang"
    assert "pkg:golang/github.com/spf13/cobra@v1.8.0" == pkg.purl


def test_go_binary_outside_bin_dirs_skipped():
    """Go binary outside known bin dirs not scanned."""
    binary = _make_go_binary([("github.com/some/pkg", "v1.0.0")])
    tar = _make_docker_save_tar([{"var/tmp/binary": binary}])
    result = parse_oci_tarball(tar)
    assert not any(p.ecosystem == "golang" for p in result.packages)


def test_go_binary_no_magic_skipped():
    """File without Go buildinfo magic is skipped."""
    tar = _make_docker_save_tar([{"usr/bin/notgo": b"\x7fELF\x00" * 100}])
    result = parse_oci_tarball(tar)
    assert not any(p.ecosystem == "golang" for p in result.packages)


# ── Ruby gem parsing ──────────────────────────────────────────────────────────


_GEMSPEC_RAILS = b"""
Gem::Specification.new do |s|
  s.name = "rails"
  s.version = "7.1.2"
  s.summary = "Full-stack web framework"
end
"""

_GEMSPEC_NOKOGIRI = b"""
Gem::Specification.new do |s|
  s.name = "nokogiri"
  s.version = Gem::Version.new("1.15.4")
end
"""


def test_ruby_gemspec_basic():
    tar = _make_docker_save_tar([{"usr/lib/ruby/gems/3.1.0/specifications/rails-7.1.2.gemspec": _GEMSPEC_RAILS}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "rails" in names
    pkg = next(p for p in result.packages if p.name == "rails")
    assert pkg.version == "7.1.2"
    assert pkg.ecosystem == "gem"
    assert pkg.purl == "pkg:gem/rails@7.1.2"


def test_ruby_gemspec_version_new_syntax():
    """Gem::Version.new('...') version syntax parsed correctly."""
    tar = _make_docker_save_tar([{"var/lib/gems/3.0.0/specifications/nokogiri-1.15.4.gemspec": _GEMSPEC_NOKOGIRI}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "nokogiri" in names


def test_ruby_non_gemspec_skipped():
    """Non-gemspec files in specifications/ dir are not parsed as gems."""
    tar = _make_docker_save_tar([{"usr/lib/ruby/gems/3.1.0/specifications/README": b"not a gemspec"}])
    result = parse_oci_tarball(tar)
    assert result.packages == []


# ── .NET deps.json parsing ────────────────────────────────────────────────────


_DEPS_JSON = json.dumps(
    {
        "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0"},
        "targets": {
            ".NETCoreApp,Version=v8.0": {
                "Newtonsoft.Json/13.0.3": {},
                "Microsoft.Extensions.Logging/8.0.0": {},
            }
        },
        "libraries": {
            "Newtonsoft.Json/13.0.3": {"type": "package", "sha512": "abc"},
            "Microsoft.Extensions.Logging/8.0.0": {"type": "package", "sha512": "def"},
            "MyApp/1.0.0": {"type": "project"},  # should be skipped
        },
    }
).encode()


def test_dotnet_deps_json_packages():
    tar = _make_docker_save_tar([{"app/MyApp.deps.json": _DEPS_JSON}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "Newtonsoft.Json" in names
    assert "Microsoft.Extensions.Logging" in names


def test_dotnet_deps_json_versions():
    tar = _make_docker_save_tar([{"app/MyApp.deps.json": _DEPS_JSON}])
    result = parse_oci_tarball(tar)
    nj = next(p for p in result.packages if p.name == "Newtonsoft.Json")
    assert nj.version == "13.0.3"
    assert nj.ecosystem == "nuget"
    assert nj.purl == "pkg:nuget/Newtonsoft.Json@13.0.3"


def test_dotnet_project_type_skipped():
    """Libraries with type=project are not included."""
    tar = _make_docker_save_tar([{"app/MyApp.deps.json": _DEPS_JSON}])
    result = parse_oci_tarball(tar)
    assert not any(p.name == "MyApp" for p in result.packages)


# ── RPM sqlite parsing ────────────────────────────────────────────────────────


def _make_rpm_header_blob(name: str, version: str, release: str = "1.el9") -> bytes:
    """Build a minimal valid RPM header blob for testing."""
    # Encode strings
    strings = {
        _RPMTAG_NAME: name.encode() + b"\x00",
        _RPMTAG_VERSION: version.encode() + b"\x00",
        _RPMTAG_RELEASE: release.encode() + b"\x00",
    }

    # Build data section and compute offsets
    data = b""
    offsets: dict[int, int] = {}
    for tag_id, s in strings.items():
        offsets[tag_id] = len(data)
        data += s

    nindex = len(strings)
    hsize = len(data)

    header = _RPM_HDR_MAGIC
    header += struct.pack(">II", nindex, hsize)
    for tag_id, s in strings.items():
        header += struct.pack(">IIII", tag_id, _RPM_TYPE_STRING, offsets[tag_id], 1)
    header += data
    return header


def _make_rpm_sqlite(packages: list[tuple[str, str, str]]) -> bytes:
    """Build an in-memory RPM sqlite database with the given packages."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)")
    for i, (name, version, release) in enumerate(packages):
        blob = _make_rpm_header_blob(name, version, release)
        conn.execute("INSERT INTO Packages VALUES (?, ?)", (i, blob))
    conn.commit()
    # Write to a file and read back as bytes
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        tmp_path = tmp.name
    conn2 = sqlite3.connect(tmp_path)
    conn.backup(conn2)
    conn2.close()
    conn.close()
    import os

    with open(tmp_path, "rb") as f:
        data = f.read()
    os.unlink(tmp_path)
    return data


def test_rpm_sqlite_packages():
    """rpmdb.sqlite packages extracted correctly."""
    db = _make_rpm_sqlite([("bash", "5.2.26", "1.el9"), ("curl", "8.1.2", "3.el9")])
    tar = _make_docker_save_tar([{"var/lib/rpm/rpmdb.sqlite": db}])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "bash" in names
    assert "curl" in names


def test_rpm_sqlite_version_includes_release():
    """RPM version includes release (version-release format)."""
    db = _make_rpm_sqlite([("openssl", "3.1.0", "2.el9")])
    tar = _make_docker_save_tar([{"var/lib/rpm/rpmdb.sqlite": db}])
    result = parse_oci_tarball(tar)
    pkg = next(p for p in result.packages if p.name == "openssl")
    assert pkg.version == "3.1.0-2.el9"
    assert pkg.ecosystem == "rpm"


def test_rpm_sqlite_gpg_pubkey_skipped():
    """gpg-pubkey entries are filtered out."""
    db = _make_rpm_sqlite([("gpg-pubkey", "12345678", "abc"), ("bash", "5.2", "1")])
    tar = _make_docker_save_tar([{"var/lib/rpm/rpmdb.sqlite": db}])
    result = parse_oci_tarball(tar)
    assert not any(p.name == "gpg-pubkey" for p in result.packages)
    assert any(p.name == "bash" for p in result.packages)


def test_rpm_sqlite_and_log_manifest_dedup():
    """Same package from sqlite and log manifest only counted once."""
    db = _make_rpm_sqlite([("nginx", "1.25.0", "1.el9")])
    log = b"nginx-1.25.0-1.el9.x86_64\n"
    tar = _make_docker_save_tar(
        [
            {
                "var/lib/rpm/rpmdb.sqlite": db,
                "var/log/installed-rpms": log,
            }
        ]
    )
    result = parse_oci_tarball(tar)
    assert sum(1 for p in result.packages if p.name == "nginx") == 1


# ── Full mixed ecosystem layer ────────────────────────────────────────────────


# ── Security hardening: tar-member safety ───────────────────────────────────


def _make_layer_tar_with_members(members: list[tarfile.TarInfo], payloads: list[bytes | None]) -> bytes:
    """Build an in-memory layer tar with explicit TarInfo objects (for symlink / traversal tests)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for info, payload in zip(members, payloads):
            if payload is None:
                tf.addfile(info)  # link/symlink/dir — no payload
            else:
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _wrap_layer_bytes_in_docker_save(layer_bytes: bytes) -> Path:
    """Wrap a single raw layer tar into a Docker-save outer tar (manifest.json + layer.tar)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
    layer_path = "0" * 40 + "/layer.tar"
    with tarfile.open(fileobj=tmp, mode="w:") as outer:
        info = tarfile.TarInfo(name=layer_path)
        info.size = len(layer_bytes)
        outer.addfile(info, io.BytesIO(layer_bytes))
        manifest = [{"Config": "sha256:abc.json", "RepoTags": ["myapp:latest"], "Layers": [layer_path]}]
        mb = json.dumps(manifest).encode()
        mi = tarfile.TarInfo(name="manifest.json")
        mi.size = len(mb)
        outer.addfile(mi, io.BytesIO(mb))
    tmp.close()
    return Path(tmp.name)


def test_is_safe_tar_member_name_accepts_normal_paths():
    from agent_bom.oci_parser import _is_safe_tar_member_name

    assert _is_safe_tar_member_name("var/lib/dpkg/status") is True
    assert _is_safe_tar_member_name("./usr/lib/node_modules/foo/package.json") is True
    assert _is_safe_tar_member_name("a/b/c") is True


def test_is_safe_tar_member_name_rejects_traversal():
    from agent_bom.oci_parser import _is_safe_tar_member_name

    assert _is_safe_tar_member_name("../etc/passwd") is False
    assert _is_safe_tar_member_name("../../etc/passwd") is False
    assert _is_safe_tar_member_name("foo/../../etc/passwd") is False, "normalize must detect escapes that span segments"
    assert _is_safe_tar_member_name("a/b/../../c/../../d") is False


def test_is_safe_tar_member_name_rejects_absolute_and_nul():
    from agent_bom.oci_parser import _is_safe_tar_member_name

    assert _is_safe_tar_member_name("/etc/passwd") is False
    assert _is_safe_tar_member_name("") is False
    assert _is_safe_tar_member_name("a\x00b") is False


def test_path_traversal_member_never_produces_a_package():
    """A crafted tar whose member name escapes the root must not be parsed as a real file."""
    traversal_info = tarfile.TarInfo(name="foo/../../../etc/passwd")
    traversal_info.type = tarfile.REGTYPE
    # Give it "METADATA-looking" content so a naive parser would treat it as a Python dist-info
    payload = b"Name: evil\nVersion: 9.9.9\n"

    benign_info = tarfile.TarInfo(name="requests-2.31.0.dist-info/METADATA")
    benign_info.type = tarfile.REGTYPE

    layer = _make_layer_tar_with_members(
        [traversal_info, benign_info],
        [payload, _METADATA_REQUESTS],
    )
    tar = _wrap_layer_bytes_in_docker_save(layer)
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "evil" not in names, "path-traversal member must not contribute a package"
    assert "requests" in names, "legitimate sibling members must still parse"


def test_symlink_metadata_member_is_refused_not_followed():
    """A symlinked METADATA member must not be opened (would leak host FS if followed)."""
    symlink = tarfile.TarInfo(name="requests-2.31.0.dist-info/METADATA")
    symlink.type = tarfile.SYMTYPE
    symlink.linkname = "/etc/passwd"

    # Include a legitimate sibling package so we know the parser still runs.
    other = tarfile.TarInfo(name="urllib3-2.0.0.dist-info/METADATA")
    other.type = tarfile.REGTYPE
    other_payload = b"Name: urllib3\nVersion: 2.0.0\n"

    layer = _make_layer_tar_with_members([symlink, other], [None, other_payload])
    tar = _wrap_layer_bytes_in_docker_save(layer)
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}
    assert "requests" not in names, "symlinked METADATA must be skipped, not followed"
    assert "urllib3" in names, "non-symlink siblings must still parse"


def test_symlinked_dpkg_status_is_refused():
    """A symlinked var/lib/dpkg/status must not be followed to leak host state."""
    symlink = tarfile.TarInfo(name="var/lib/dpkg/status")
    symlink.type = tarfile.SYMTYPE
    symlink.linkname = "/etc/passwd"

    layer = _make_layer_tar_with_members([symlink], [None])
    tar = _wrap_layer_bytes_in_docker_save(layer)
    result = parse_oci_tarball(tar)
    assert all("passwd" not in (p.name or "") for p in result.packages)
    # Zero dpkg packages because the symlink was refused.
    assert len(result.packages) == 0


def test_absolute_path_member_rejected():
    """A member whose name starts with `/` must not be readable."""
    info = tarfile.TarInfo(name="/etc/evil/METADATA")
    info.type = tarfile.REGTYPE
    payload = b"Name: escaped\nVersion: 0.0.1\n"

    layer = _make_layer_tar_with_members([info], [payload])
    tar = _wrap_layer_bytes_in_docker_save(layer)
    result = parse_oci_tarball(tar)
    assert not any(p.name == "escaped" for p in result.packages)


def test_full_mixed_ecosystem_layer():
    """All ecosystems detected from a single mixed layer."""
    jar = _make_jar(pom_props={"groupId": "org.springframework", "artifactId": "spring-core", "version": "6.1.0"})
    go_bin = _make_go_binary([("github.com/prometheus/client_golang", "v1.18.0")])
    db = _make_rpm_sqlite([("glibc", "2.34", "1.el9")])
    deps_json = json.dumps({"libraries": {"System.Text.Json/8.0.0": {"type": "package"}}}).encode()

    layer = {
        "var/lib/dpkg/status": _DPKG_STATUS,
        "lib/apk/db/installed": _APK_INSTALLED,
        "requests-2.31.0.dist-info/METADATA": _METADATA_REQUESTS,
        "usr/lib/node_modules/express/package.json": _PACKAGE_JSON_EXPRESS,
        "usr/share/java/spring-core.jar": jar,
        "usr/bin/prometheus": go_bin,
        "usr/lib/ruby/gems/3.1.0/specifications/rails-7.1.2.gemspec": _GEMSPEC_RAILS,
        "app/MyApp.deps.json": deps_json,
        "var/lib/rpm/rpmdb.sqlite": db,
    }
    tar = _make_docker_save_tar([layer])
    result = parse_oci_tarball(tar)
    names = {p.name for p in result.packages}

    assert "bash" in names  # deb
    assert "busybox" in names  # apk
    assert "requests" in names  # python
    assert "express" in names  # node
    assert "spring-core" in names  # java/maven
    assert "github.com/prometheus/client_golang" in names  # go
    assert "rails" in names  # ruby
    assert "System.Text.Json" in names  # .net
    assert "glibc" in names  # rpm sqlite
