"""Tests for scanner core gap fixes — conda resolution, npm semver, OSV logging."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from agent_bom.models import Package

# ── Conda resolver coverage ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_conda_resolve_package_version():
    """Conda packages should attempt PyPI resolution for unversioned deps."""
    from agent_bom.resolver import resolve_package_version

    pkg = Package(name="numpy", version="latest", ecosystem="conda")

    async def mock_pypi_metadata(name, client):
        return ("1.26.0", "BSD-3-Clause")

    with patch("agent_bom.resolver.resolve_pypi_metadata", side_effect=mock_pypi_metadata):
        mock_client = AsyncMock()
        resolved = await resolve_package_version(pkg, mock_client)

    assert resolved is True
    assert pkg.version == "1.26.0"


@pytest.mark.asyncio
async def test_conda_unresolvable_stays_unresolved():
    """Conda packages that don't exist on PyPI stay unresolved."""
    from agent_bom.resolver import resolve_package_version

    pkg = Package(name="cudatoolkit", version="unknown", ecosystem="conda")

    async def mock_pypi_not_found(name, client):
        return (None, None)

    with patch("agent_bom.resolver.resolve_pypi_metadata", side_effect=mock_pypi_not_found):
        mock_client = AsyncMock()
        resolved = await resolve_package_version(pkg, mock_client)

    assert resolved is False
    assert pkg.version == "unknown"


# ── npm semver validation ────────────────────────────────────────────────────


def test_npm_package_json_valid_semver(tmp_path):
    """Valid semver versions are preserved after range stripping."""
    from agent_bom.parsers.node_parsers import parse_npm_packages

    pkg_json = {"dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))

    packages = parse_npm_packages(tmp_path)
    versions = {p.name: p.version for p in packages}
    assert versions["express"] == "4.18.2"
    assert versions["lodash"] == "4.17.21"


def test_npm_package_json_incomplete_semver_becomes_latest(tmp_path):
    """Incomplete semver (e.g. ^1.2) becomes 'latest' for resolver to handle."""
    from agent_bom.parsers.node_parsers import parse_npm_packages

    pkg_json = {"dependencies": {"foo": "^1.2", "bar": "~1"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))

    packages = parse_npm_packages(tmp_path)
    versions = {p.name: p.version for p in packages}
    assert versions["foo"] == "latest"
    assert versions["bar"] == "latest"


def test_npm_package_json_star_becomes_latest(tmp_path):
    """Wildcard version '*' becomes 'latest'."""
    from agent_bom.parsers.node_parsers import parse_npm_packages

    pkg_json = {"dependencies": {"wildcard-pkg": "*"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))

    packages = parse_npm_packages(tmp_path)
    assert packages[0].version == "latest"


# ── Conda in auto-resolve filter ─────────────────────────────────────────────


def test_conda_in_auto_resolve_filter():
    """Conda ecosystem should be included in the auto-resolve filter."""
    # Verify the filter string is present in scanners code
    import inspect

    from agent_bom.scanners import scan_packages

    source = inspect.getsource(scan_packages)
    assert "conda" in source, "conda must be in the auto-resolve ecosystem filter"
