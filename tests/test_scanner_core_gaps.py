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


def test_npm_package_json_range_is_unresolved_not_floored(tmp_path):
    """A range keeps its spec and no version; flooring ^4.18.2 to 4.18.2 matched
    advisories a fresh install never has."""
    from agent_bom.parsers.node_parsers import parse_npm_packages

    pkg_json = {"dependencies": {"express": "^4.18.2", "lodash": "~4.17.21", "exact": "4.17.21"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))

    packages = {p.name: p for p in parse_npm_packages(tmp_path)}
    assert (packages["express"].version, packages["express"].declared_version) == ("unknown", "^4.18.2")
    assert (packages["lodash"].version, packages["lodash"].declared_version) == ("unknown", "~4.17.21")
    assert packages["express"].purl is None
    assert packages["exact"].version == "4.17.21"


def test_npm_package_json_incomplete_and_wildcard_ranges_are_unresolved(tmp_path):
    """``^1.2``, ``~1`` and ``*`` are ranges too: unresolved, spec preserved."""
    from agent_bom.parsers.node_parsers import parse_npm_packages

    pkg_json = {"dependencies": {"foo": "^1.2", "bar": "~1", "wildcard-pkg": "*", "tagged": "latest"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))

    packages = {p.name: p for p in parse_npm_packages(tmp_path)}
    for name, declared in (("foo", "^1.2"), ("bar", "~1"), ("wildcard-pkg", "*")):
        assert packages[name].version == "unknown"
        assert packages[name].declared_version == declared
        assert packages[name].floating_reference is True
    assert packages["tagged"].version == "latest"


# ── Conda in auto-resolve filter ─────────────────────────────────────────────


def test_conda_in_auto_resolve_filter():
    """Conda ecosystem should be included in the auto-resolve filter."""
    # Verify the filter string is present in scanners code
    import inspect

    from agent_bom.scanners.package_scan import _resolve_registry_versions

    source = inspect.getsource(_resolve_registry_versions)
    assert "conda" in source, "conda must be in the auto-resolve ecosystem filter"
