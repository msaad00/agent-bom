"""An unreadable or non-UTF8 npm manifest degrades; it never aborts the scan.

``OSError``/``PermissionError`` (bounded reads in ``parsers/file_limits.py``)
and ``UnicodeDecodeError`` (``errors="strict"``) escaped the npm parsers, so a
single ``chmod 000`` manifest or one binary ``package.json`` killed the whole
scan with no artifact written. The correct behaviour already existed one branch
over for a corrupt lockfile: a named coverage warning plus a written report.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agent_bom.parsers.node_parsers import parse_npm_packages
from agent_bom.scanners import state as scanner_state


@pytest.fixture(autouse=True)
def _reset_coverage_warnings():
    scanner_state.consume_coverage_warnings()
    yield
    scanner_state.consume_coverage_warnings()


def _warning_paths() -> list[str]:
    return [str(warning.get("release", "")) for warning in scanner_state.consume_coverage_warnings()]


def _skip_if_root() -> None:
    if os.geteuid() == 0:
        pytest.skip("chmod 000 does not deny reads for root")


def test_unreadable_package_lock_degrades_with_a_named_warning(tmp_path: Path) -> None:
    _skip_if_root()
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(json.dumps({"packages": {"node_modules/left-pad": {"version": "1.3.0"}}}))
    lock_file.chmod(0o000)
    try:
        packages = parse_npm_packages(tmp_path)
    finally:
        lock_file.chmod(0o644)

    assert packages == []
    assert any("package-lock.json" in path for path in _warning_paths()), _warning_paths()


def test_unreadable_package_json_degrades_with_a_named_warning(tmp_path: Path) -> None:
    _skip_if_root()
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"dependencies": {"left-pad": "1.3.0"}}))
    manifest.chmod(0o000)
    try:
        packages = parse_npm_packages(tmp_path)
    finally:
        manifest.chmod(0o644)

    assert packages == []
    assert any("package.json" in path for path in _warning_paths()), _warning_paths()


def test_non_utf8_package_json_degrades_with_a_named_warning(tmp_path: Path) -> None:
    manifest = tmp_path / "package.json"
    manifest.write_bytes(b'{"dependencies": {"left-pad": "\xa4\xa4"}}')

    packages = parse_npm_packages(tmp_path)

    assert packages == []
    assert any("package.json" in path for path in _warning_paths()), _warning_paths()


def test_non_utf8_package_lock_degrades_with_a_named_warning(tmp_path: Path) -> None:
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_bytes(b'{"packages": {"node_modules/\xa4": {"version": "1.0.0"}}}')

    packages = parse_npm_packages(tmp_path)

    assert packages == []
    assert any("package-lock.json" in path for path in _warning_paths()), _warning_paths()


def test_oversize_package_json_degrades_with_a_named_warning(tmp_path: Path, monkeypatch) -> None:
    """``ManifestTooLargeError`` subclasses ``OSError`` — same graceful path."""
    monkeypatch.setenv("AGENT_BOM_MAX_MANIFEST_BYTES", "8")
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"dependencies": {"left-pad": "1.3.0"}}))

    packages = parse_npm_packages(tmp_path)

    assert packages == []
    assert any("package.json" in path for path in _warning_paths()), _warning_paths()


def test_readable_manifest_still_parses(tmp_path: Path) -> None:
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"dependencies": {"left-pad": "1.3.0"}}))

    packages = parse_npm_packages(tmp_path)

    assert [(pkg.name, pkg.version) for pkg in packages] == [("left-pad", "1.3.0")]
    assert _warning_paths() == []
