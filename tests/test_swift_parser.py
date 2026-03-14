"""Tests for Swift Package Manager parser."""

import json
from pathlib import Path

import pytest

from agent_bom.parsers.swift_parsers import parse_package_resolved, parse_swift_packages


@pytest.fixture
def tmp_project(tmp_path: Path):
    return tmp_path


def test_parse_package_resolved_v2(tmp_project: Path):
    """Parse v2 format Package.resolved."""
    data = {
        "pins": [
            {
                "identity": "swift-argument-parser",
                "kind": "remoteSourceControl",
                "location": "https://github.com/apple/swift-argument-parser.git",
                "state": {"revision": "abc123", "version": "1.3.0"},
            },
            {
                "identity": "vapor",
                "kind": "remoteSourceControl",
                "location": "https://github.com/vapor/vapor.git",
                "state": {"revision": "def456", "version": "4.89.0"},
            },
        ],
        "version": 2,
    }
    (tmp_project / "Package.resolved").write_text(json.dumps(data), encoding="utf-8")

    packages = parse_package_resolved(tmp_project)
    assert len(packages) == 2

    names = {p.name for p in packages}
    assert "swift-argument-parser" in names
    assert "vapor" in names

    sap = next(p for p in packages if p.name == "swift-argument-parser")
    assert sap.version == "1.3.0"
    assert sap.ecosystem == "swift"
    assert sap.purl == "pkg:swift/swift-argument-parser@1.3.0"
    assert sap.repository_url == "https://github.com/apple/swift-argument-parser.git"


def test_parse_package_resolved_no_version(tmp_project: Path):
    """Handle pins with branch/revision but no version."""
    data = {
        "pins": [
            {
                "identity": "swift-testing",
                "location": "https://github.com/apple/swift-testing.git",
                "state": {"branch": "main", "revision": "abc123"},
            },
        ],
        "version": 3,
    }
    (tmp_project / "Package.resolved").write_text(json.dumps(data), encoding="utf-8")

    packages = parse_package_resolved(tmp_project)
    assert len(packages) == 1
    assert packages[0].version == "unknown"


def test_parse_no_swift_files(tmp_project: Path):
    """No packages when no Swift files exist."""
    assert parse_swift_packages(tmp_project) == []


def test_parse_deduplication(tmp_project: Path):
    """No duplicate packages."""
    data = {
        "pins": [
            {
                "identity": "vapor",
                "location": "https://github.com/vapor/vapor.git",
                "state": {"version": "4.89.0"},
            },
            {
                "identity": "vapor",
                "location": "https://github.com/vapor/vapor.git",
                "state": {"version": "4.89.0"},
            },
        ],
        "version": 2,
    }
    (tmp_project / "Package.resolved").write_text(json.dumps(data), encoding="utf-8")

    packages = parse_package_resolved(tmp_project)
    assert len(packages) == 1
