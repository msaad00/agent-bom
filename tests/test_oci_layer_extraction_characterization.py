"""Characterization golden for per-layer package extraction.

Synthetic layers cover every package-database branch of
``_extract_packages_from_layer``; the golden pins packages, provenance,
whiteouts and diagnostics in emission order.
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
import struct
import tarfile
import tempfile
import zipfile
from dataclasses import asdict
from pathlib import Path

import pytest

import agent_bom.oci_parser as oci_parser
from agent_bom.models import Package
from agent_bom.oci_parser import (
    _RPM_HDR_MAGIC,
    _RPM_TYPE_STRING,
    _RPMTAG_NAME,
    _RPMTAG_RELEASE,
    _RPMTAG_VERSION,
    LayerMetadata,
    OCIInputWarning,
    OCIParseError,
    _extract_packages_from_layer,
)

GOLDEN = Path(__file__).parent / "fixtures" / "oci_layer_extraction_golden.json"


def _rpm_header(name: str, version: str, release: str, *, magic: bool) -> bytes:
    strings = {_RPMTAG_NAME: name, _RPMTAG_VERSION: version, _RPMTAG_RELEASE: release}
    data = b""
    entries = b""
    for tag, value in strings.items():
        entries += struct.pack(">IIII", tag, _RPM_TYPE_STRING, len(data), 1)
        data += value.encode() + b"\x00"
    body = struct.pack(">II", len(strings), len(data)) + entries + data
    return (_RPM_HDR_MAGIC + body) if magic else body


def _rpm_sqlite(blobs: list[bytes]) -> bytes:
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    try:
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)")
        conn.executemany("INSERT INTO Packages (blob) VALUES (?)", [(blob,) for blob in blobs])
        conn.commit()
        conn.close()
        return Path(path).read_bytes()
    finally:
        os.unlink(path)


def _jar(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _layer(files: dict[str, bytes], symlinks: dict[str, str] | None = None) -> tarfile.TarFile:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for path, content in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
        for path, target in (symlinks or {}).items():
            info = tarfile.TarInfo(name=path)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r:")


GO_BINARY = (
    b"\x7fELF" + b"\x00" * 60 + b"\xff Go buildinf:" + b"\x00" * 16 + b"path\texample.com/app\n"
    b"dep\tgithub.com/gorilla/mux\tv1.8.0\th1:abc=\n"
    b"dep\tgolang.org/x/net\tv0.17.0\th1:def=\n"
)

EVERY_ECOSYSTEM = {
    "usr/lib/python3/site-packages/requests-2.31.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n",
    "usr/lib/python3/dist-packages/pip-18.1.egg-info/PKG-INFO": b"Name: pip\nVersion: 18.1\n",
    "usr/lib/python3/dist-packages/wheel-0.32.egg-info/METADATA": b"Name: wheel\nVersion: 0.32.3\n",
    "usr/lib/python3/site-packages/broken-1.0.dist-info/METADATA": b"Name: broken\n",
    "app/node_modules/express/package.json": json.dumps({"name": "express", "version": "4.18.2"}).encode(),
    "app/node_modules/@types/node/package.json": json.dumps({"name": "@types/node"}).encode(),
    "app/node_modules/nameless/package.json": json.dumps({"version": "1.0.0"}).encode(),
    "app/node_modules/garbage/package.json": b"{not json",
    "app/node_modules/nanoid/non-secure/package.json": json.dumps({"main": "x"}).encode(),
    "var/lib/dpkg/status": (
        b"Package: libc6\nVersion: 2.36-9\nSource: glibc (2.36-9)\n\n"
        b"Package: bash\nVersion: 5.2.15-2\n\n"
        b"Package: zlib1g\nVersion: 1:1.2.13\nSource: zlib"
    ),
    "lib/apk/db/installed": b"P:musl\nV:1.2.4-r2\no:musl\n\nP:busybox\nV:1.36.1-r5\n",
    "var/log/installed-rpms": b"bash-5.1.8-6.el9.x86_64 Mon\ngpg-pubkey-fd431d51-4ae0493b\nnot-an-nvr\n\nopenssl-3.0.7-24.el9.x86_64\n",
    "var/lib/rpm/rpmdb.sqlite": _rpm_sqlite(
        [
            _rpm_header("glibc", "2.34", "60.el9", magic=False),
            _rpm_header("gpg-pubkey", "fd431d51", "4ae0493b", magic=False),
            b"short",
        ]
    ),
    "usr/share/java/lib-pom.jar": _jar(
        {
            "META-INF/maven/org.example/lib-pom/pom.properties": "#c\ngroupId=org.example\nartifactId=lib-pom\nversion=1.2.3\n",
            "META-INF/maven/nogroup/solo/pom.properties": "artifactId=solo\nversion=0.1\n",
            "META-INF/MANIFEST.MF": "Implementation-Title: ignored\nImplementation-Version: 9\n",
        }
    ),
    "opt/app/lib/manifest-only.jar": _jar({"META-INF/MANIFEST.MF": "Bundle-Name: bundle-lib\nBundle-Version: 4.5.6\n"}),
    "opt/app/lib/placeholder.jar": _jar({"META-INF/MANIFEST.MF": "Implementation-Title: ${name}\nImplementation-Version: 1\n"}),
    "opt/app/lib/empty.jar": b"",
    "opt/app/lib/corrupt.jar": b"not a zip",
    "tmp/not-hinted.jar": _jar({"META-INF/MANIFEST.MF": "Implementation-Title: t\nImplementation-Version: 1\n"}),
    "usr/local/bin/server": GO_BINARY,
    "usr/local/bin/script": b"#!/bin/sh\n" + b"echo hi\n" * 10,
    "usr/local/bin/tiny": b"\xff Go buildinf:",
    "usr/lib/ruby/gems/3.2.0/specifications/rack-2.2.8.gemspec": (
        b'Gem::Specification.new do |s|\n  s.name = "rack"\n  s.version = "2.2.8"\nend\n'
    ),
    "usr/lib/ruby/gems/3.2.0/specifications/json-2.7.gemspec": b"s.name = 'json'\ns.version = Gem::Version.new('2.7.1')\n",
    "usr/lib/ruby/gems/3.2.0/specifications/odd.gemspec": b"s.summary = 'none'\n",
    "app/web.deps.json": json.dumps(
        {
            "libraries": {
                "Newtonsoft.Json/13.0.1": {"type": "package"},
                "web/1.0.0": {"type": "project"},
                "noslash": {"type": "package"},
            }
        }
    ).encode(),
    "app/bad.deps.json": b"[",
    "app/composer.lock": json.dumps(
        {"packages": [{"name": "monolog/monolog", "version": "v3.5.0"}, {"version": "1"}], "packages-dev": [{"name": "phpunit/phpunit"}]}
    ).encode(),
    "./var/www/composer.lock": b"{bad",
    "app/Cargo.lock": b'[[package]]\nname = "serde"\nversion = "1.0.193"\n\n[[package]]\nname = "tokio"\nversion = "1.35.0"\n',
    "./opt/Cargo.lock": b"[[package]]\nbroken = true\n",
    "app/Package.resolved": json.dumps(
        {
            "pins": [
                {"identity": "swift-nio", "location": "https://github.com/apple/swift-nio.git", "state": {"version": "2.62.0"}},
                {"location": "https://github.com/vapor/vapor.git/", "state": {"branch": "main"}},
            ]
        }
    ).encode(),
    "./Package.resolved": json.dumps(
        {"object": {"pins": [{"repositoryURL": "https://github.com/pointfreeco/swift-case-paths", "state": {"version": "1.1.0"}}]}}
    ).encode(),
    "etc/.wh.passwd": b"",
    "var/cache/.wh..wh..opq": b"",
    ".wh.rootfile": b"",
}


def _serialize_package(package: Package) -> dict:
    return {
        "name": package.name,
        "version": package.version,
        "ecosystem": package.ecosystem,
        "purl": package.purl,
        "source_package": package.source_package,
        "distro_name": package.distro_name,
        "distro_version": package.distro_version,
        "is_direct": package.is_direct,
        "resolved_from_registry": package.resolved_from_registry,
        "occurrences": [asdict(occurrence) for occurrence in package.occurrences],
    }


def _scenarios() -> list[tuple[str, dict[str, bytes], dict[str, str], set[str], bool]]:
    return [
        ("every_ecosystem", EVERY_ECOSYSTEM, {"usr/local/bin/link": "server"}, set(), True),
        (
            "deleted_by_later_layers",
            {
                **EVERY_ECOSYSTEM,
                "app/node_modules/express/package.json": json.dumps({"name": "express", "version": "4.19.0"}).encode(),
            },
            {},
            {"var/lib/dpkg/status", "usr/lib/python3/dist-packages/", "app/Cargo.lock", "usr/local/bin/server"},
            True,
        ),
        ("no_diagnostic_sinks", EVERY_ECOSYSTEM, {}, set(), False),
        (
            "legacy_bdb",
            {
                "var/lib/rpm/Packages": b"\x00" * 32
                + _rpm_header("coreutils", "8.32", "34.el9", magic=True)
                + b"\x00" * 8
                + _rpm_header("gpg-pubkey", "1", "2", magic=True)
                + _rpm_header("coreutils", "8.32", "34.el9", magic=True),
                "var/lib/dpkg/status": b"garbage without fields\n",
                "lib/apk/db/installed": b"",
            },
            {},
            set(),
            True,
        ),
        (
            "legacy_ndb_shadowed_by_manifest",
            {
                "var/lib/rpm/Packages.db": _rpm_header("ignored", "1", "1", magic=True),
                "./var/log/installed-rpms": b"only-junk\n",
            },
            {},
            set(),
            True,
        ),
        ("legacy_ndb_invalid", {"./var/lib/rpm/Packages.db": b"no headers here"}, {}, set(), True),
        (
            "prefixed_duplicates",
            {
                "./var/lib/dpkg/status": b"Package: curl\nVersion: 8.0\n",
                "var/lib/dpkg/status": b"Package: wget\nVersion: 1.21\n",
                "./lib/apk/db/installed": b"P:zlib\nV:1.3\nO:zlib-src\n",
                "./var/lib/rpm/rpmdb.sqlite": b"not a database",
                "usr/lib/python3/site-packages/requests-2.32.0.dist-info/METADATA": b"Name: requests\nVersion: 2.32.0\n",
            },
            {},
            set(),
            True,
        ),
    ]


def _characterize() -> dict:
    packages_by_key: dict[tuple[str, str], Package] = {}
    packages: list[Package] = []
    runs = []
    for index, (label, files, symlinks, deleted, sinks) in enumerate(_scenarios()):
        warnings: list[str] | None = [] if sinks else None
        coverage: list[OCIInputWarning] | None = [] if sinks else None
        layer = LayerMetadata(
            layer_index=index, layer_id=f"sha256:{index:064x}", layer_path=f"blobs/{index}", created_by=f"RUN step {index}"
        )
        with _layer(files, symlinks) as layer_tf:
            try:
                found = _extract_packages_from_layer(layer_tf, packages_by_key, packages, set(deleted), layer, warnings, coverage)
                whiteouts = sorted(found)
                error = None
            except OCIParseError as exc:
                whiteouts = []
                error = str(exc)
        runs.append(
            {
                "label": label,
                "whiteouts": whiteouts,
                "error": error,
                "warnings": warnings,
                "coverage_warnings": [asdict(item) for item in coverage] if coverage is not None else None,
                "package_count": len(packages),
            }
        )
    return {"runs": runs, "packages": [_serialize_package(package) for package in packages]}


def _ordered_tar_names(layer_tf: tarfile.TarFile) -> dict[str, None]:
    # Member names are a set in production, so iteration order follows the hash
    # seed; an insertion-ordered view pins emission order for the golden.
    return dict.fromkeys(sorted(_SAFE_TAR_NAMES(layer_tf)))


_SAFE_TAR_NAMES = oci_parser._safe_tar_names


def test_layer_extraction_matches_golden(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oci_parser, "_safe_tar_names", _ordered_tar_names)
    actual = _characterize()
    if os.environ.get("AGENT_BOM_UPDATE_GOLDENS") == "1":
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
    assert actual == json.loads(GOLDEN.read_text())


def test_golden_covers_every_ecosystem_branch() -> None:
    golden = json.loads(GOLDEN.read_text())
    ecosystems = {package["ecosystem"] for package in golden["packages"]}
    assert ecosystems == {"pypi", "npm", "deb", "apk", "rpm", "maven", "golang", "gem", "nuget", "composer", "cargo", "swift"}
    assert {run["label"] for run in golden["runs"] if run["error"]} == {"legacy_ndb_invalid"}
    assert any(run["whiteouts"] for run in golden["runs"])
    assert any(package["occurrences"] and package["source_package"] for package in golden["packages"])
