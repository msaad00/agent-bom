"""CPython inventory uses exact static version evidence, never executes images."""

import io
import tarfile

from agent_bom.oci_parser import LayerMetadata, _extract_packages_from_layer


def scan(files, deleted=None, coverage_warnings=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, body in files.items():
            data = body.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    stream.seek(0)
    packages = []
    with tarfile.open(fileobj=stream) as archive:
        _extract_packages_from_layer(
            archive,
            {},
            packages,
            deleted or set(),
            LayerMetadata(layer_index=0, layer_id="sha256:test", layer_path="layer"),
            [],
            coverage_warnings if coverage_warnings is not None else [],
        )
    return packages


def test_cpython_header_records_exact_runtime_version():
    packages = scan({"usr/local/include/python3.13/patchlevel.h": '#define PY_VERSION "3.13.2"\n'})
    assert [(p.name, p.version, p.ecosystem) for p in packages] == [("cpython", "3.13.2", "generic")]
    assert packages[0].is_direct is None
    assert packages[0].version_source == "installed_package"
    assert packages[0].occurrences[0].package_path.endswith("patchlevel.h")


def test_runtime_path_alone_or_deleted_header_does_not_invent_version():
    assert scan({"usr/local/bin/python3.13": "ELF"}) == []
    path = "usr/local/include/python3.13/patchlevel.h"
    assert scan({path: '#define PY_VERSION "3.13.2"\n'}, {path}) == []


def test_collapsed_multiple_runtime_identities_keep_image_coverage_partial():
    warnings = []
    scan(
        {
            "usr/local/include/python3.13/patchlevel.h": '#define PY_VERSION "3.13.2"\n',
            "usr/local/include/python3.14/patchlevel.h": '#define PY_VERSION "3.14.8"\n',
        },
        coverage_warnings=warnings,
    )
    assert warnings and warnings[0].reason == "package_metadata_parse_error"
