"""Tests for resolver module — coverage expansion."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import agent_bom.resolver as resolver
from agent_bom.models import Package
from agent_bom.resolver import (
    _NPM_LATEST_CACHE,
    _PYPI_INFO_CACHE,
    _get_npm_latest_doc,
    enrich_licenses,
    enrich_supply_chain_metadata,
    resolve_all_versions,
    resolve_npm_metadata,
    resolve_npm_supply_chain,
    resolve_package_version,
    resolve_pypi_metadata,
    resolve_pypi_supply_chain,
)


@pytest.fixture(autouse=True)
def clear_registry_metadata_caches():
    _NPM_LATEST_CACHE.clear()
    _PYPI_INFO_CACHE.clear()

    resolver._NPM_RATE_LIMIT_UNTIL = 0.0
    resolver._NPM_RATE_LIMIT_HITS = 0
    yield
    _NPM_LATEST_CACHE.clear()
    _PYPI_INFO_CACHE.clear()
    resolver._NPM_RATE_LIMIT_UNTIL = 0.0
    resolver._NPM_RATE_LIMIT_HITS = 0


class TestResolveNpmMetadata:
    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"version": "4.18.2", "license": "MIT"}
        with patch("agent_bom.resolver.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            version, lic = await resolve_npm_metadata("express", client)
            assert version == "4.18.2"
            assert lic == "MIT"

    @pytest.mark.asyncio
    async def test_license_as_dict(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"version": "1.0.0", "license": {"type": "ISC"}}
        with patch("agent_bom.resolver.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            version, lic = await resolve_npm_metadata("test", client)
            assert lic == "ISC"

    @pytest.mark.asyncio
    async def test_failed_response(self):
        mock_response = MagicMock()
        mock_response.status_code = 404
        with patch("agent_bom.resolver.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            version, lic = await resolve_npm_metadata("nonexistent", client)
            assert version is None
            assert lic is None

    @pytest.mark.asyncio
    async def test_rate_limit_opens_cooldown_and_skips_followup_lookups(self):
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "7"}

        with (
            patch("agent_bom.resolver.request_with_retry", return_value=mock_response) as mock_request,
            patch("agent_bom.resolver.time.monotonic", return_value=100.0),
        ):
            client = AsyncMock()
            assert await _get_npm_latest_doc("first", client) is None
            assert await _get_npm_latest_doc("second", client) is None

        assert mock_request.call_count == 1
        assert resolver._NPM_RATE_LIMIT_HITS == 1
        assert resolver._NPM_RATE_LIMIT_UNTIL == 107.0

    @pytest.mark.asyncio
    async def test_caches_latest_doc_across_version_and_supply_chain(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "version": "1.2.3",
            "license": "MIT",
            "description": "Cached package",
        }
        pkg = Package(name="cached", version="1.2.3", ecosystem="npm")
        with patch("agent_bom.resolver.request_with_retry", return_value=mock_response) as mock_request:
            client = AsyncMock()
            version, lic = await resolve_npm_metadata("cached", client)
            await resolve_npm_supply_chain(pkg, client)
        assert version == "1.2.3"
        assert lic == "MIT"
        assert pkg.description == "Cached package"
        assert mock_request.call_count == 1


class TestResolvePypiMetadata:
    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"version": "2.31.0", "license": "Apache-2.0"}}
        with patch("agent_bom.resolver.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            version, lic = await resolve_pypi_metadata("requests", client)
            assert version == "2.31.0"
            assert lic == "Apache-2.0"

    @pytest.mark.asyncio
    async def test_unknown_license(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"info": {"version": "1.0.0", "license": "UNKNOWN"}}
        with patch("agent_bom.resolver.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            version, lic = await resolve_pypi_metadata("test", client)
            assert version == "1.0.0"
            assert lic is None


class TestResolveNpmSupplyChain:
    @pytest.mark.asyncio
    async def test_enriches_package(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "description": "Fast web framework",
            "homepage": "https://expressjs.com",
            "repository": {"url": "https://github.com/expressjs/express"},
            "author": {"name": "TJ Holowaychuk"},
        }
        pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        with patch("agent_bom.resolver.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            await resolve_npm_supply_chain(pkg, client)
            assert pkg.description == "Fast web framework"
            assert pkg.homepage == "https://expressjs.com"
            assert pkg.author == "TJ Holowaychuk"

    @pytest.mark.asyncio
    async def test_string_repository(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "repository": "https://github.com/owner/repo",
        }
        pkg = Package(name="test", version="1.0.0", ecosystem="npm")
        with patch("agent_bom.resolver.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            await resolve_npm_supply_chain(pkg, client)
            assert pkg.repository_url == "https://github.com/owner/repo"

    @pytest.mark.asyncio
    async def test_string_author(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"author": "John Doe"}
        pkg = Package(name="test", version="1.0.0", ecosystem="npm")
        with patch("agent_bom.resolver.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            await resolve_npm_supply_chain(pkg, client)
            assert pkg.author == "John Doe"


class TestResolvePypiSupplyChain:
    @pytest.mark.asyncio
    async def test_enriches_package(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "info": {
                "summary": "Python HTTP library",
                "home_page": "https://requests.readthedocs.io",
                "project_urls": {"Repository": "https://github.com/psf/requests", "Homepage": "https://requests.readthedocs.io"},
                "author": "Kenneth Reitz",
                "maintainer": "PSF",
            }
        }
        pkg = Package(name="requests", version="2.31.0", ecosystem="pypi")
        with patch("agent_bom.resolver.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            await resolve_pypi_supply_chain(pkg, client)
            assert pkg.description == "Python HTTP library"
            assert pkg.author == "Kenneth Reitz"
            assert pkg.supplier == "PSF"


class TestResolvePackageVersion:
    @pytest.mark.asyncio
    async def test_already_resolved(self):
        pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        client = AsyncMock()
        result = await resolve_package_version(pkg, client)
        assert result is False

    @pytest.mark.asyncio
    async def test_npm_resolution(self):
        pkg = Package(name="express", version="latest", ecosystem="npm")
        with patch("agent_bom.resolver.resolve_npm_metadata", return_value=("4.18.2", "MIT")):
            client = AsyncMock()
            result = await resolve_package_version(pkg, client)
            assert result is True
            assert pkg.version == "4.18.2"
            assert pkg.license == "MIT"

    @pytest.mark.asyncio
    async def test_pypi_resolution(self):
        pkg = Package(name="requests", version="unknown", ecosystem="pypi")
        with patch("agent_bom.resolver.resolve_pypi_metadata", return_value=("2.31.0", "Apache-2.0")):
            client = AsyncMock()
            result = await resolve_package_version(pkg, client)
            assert result is True
            assert pkg.version == "2.31.0"

    @pytest.mark.asyncio
    async def test_go_resolution(self):
        pkg = Package(name="github.com/gin-gonic/gin", version="unknown", ecosystem="go")
        with patch("agent_bom.version_utils.resolve_go_metadata", return_value=("1.9.0", "MIT")):
            client = AsyncMock()
            result = await resolve_package_version(pkg, client)
            assert result is True

    @pytest.mark.asyncio
    async def test_cargo_resolution(self):
        pkg = Package(name="serde", version="unknown", ecosystem="cargo")
        with patch("agent_bom.version_utils.resolve_cargo_metadata", return_value=("1.0.0", "MIT")):
            client = AsyncMock()
            result = await resolve_package_version(pkg, client)
            assert result is True

    @pytest.mark.asyncio
    async def test_maven_resolution(self):
        pkg = Package(name="org.apache:commons-lang3", version="unknown", ecosystem="maven")
        with patch("agent_bom.version_utils.resolve_maven_metadata", return_value=("3.14.0", "Apache-2.0")):
            client = AsyncMock()
            result = await resolve_package_version(pkg, client)
            assert result is True

    @pytest.mark.asyncio
    async def test_no_version_found(self):
        pkg = Package(name="nonexistent", version="unknown", ecosystem="npm")
        with patch("agent_bom.resolver.resolve_npm_metadata", return_value=(None, None)):
            client = AsyncMock()
            result = await resolve_package_version(pkg, client)
            assert result is False

    @pytest.mark.asyncio
    async def test_uses_registry_fallback_when_live_lookup_fails(self):
        pkg = Package(
            name="example-mcp",
            version="unknown",
            ecosystem="npm",
            registry_version="1.2.3",
        )
        with patch("agent_bom.resolver.resolve_npm_metadata", return_value=(None, None)):
            client = AsyncMock()
            result = await resolve_package_version(pkg, client)
            assert result is True
            assert pkg.version == "1.2.3"
            assert pkg.version_source == "registry_fallback"
            assert pkg.purl == "pkg:npm/example-mcp@1.2.3"


class TestResolveAllVersions:
    @pytest.mark.asyncio
    async def test_duplicate_package_resolution_is_deduped_and_propagated(self):
        packages = [
            Package(name="dup", version="unknown", ecosystem="npm"),
            Package(name="dup", version="unknown", ecosystem="npm"),
        ]

        async def fake_resolve(pkg, client):
            pkg.version = "9.9.9"
            pkg.purl = "pkg:npm/dup@9.9.9"
            return True

        client_cm = AsyncMock()
        client_cm.__aenter__.return_value = AsyncMock()
        client_cm.__aexit__.return_value = None

        with (
            patch("agent_bom.resolver.create_client", return_value=client_cm),
            patch("agent_bom.resolver.resolve_package_version", side_effect=fake_resolve) as mock_resolve,
            patch("agent_bom.resolver.enrich_licenses", return_value=0),
        ):
            resolved = await resolve_all_versions(packages, quiet=True, global_timeout=0.5)

        assert resolved == 2
        assert packages[0].version == "9.9.9"
        assert packages[1].version == "9.9.9"
        assert mock_resolve.call_count == 1

    @pytest.mark.asyncio
    async def test_timeout_preserves_completed_and_fallback_versions(self):
        packages = [
            Package(name="fast", version="unknown", ecosystem="npm", registry_version="1.0.0"),
            Package(name="slow", version="unknown", ecosystem="npm", registry_version="2.0.0"),
        ]

        async def fake_resolve(pkg, client):
            if pkg.name == "fast":
                pkg.version = "1.0.1"
                pkg.version_source = "registry_fallback"
                pkg.purl = "pkg:npm/fast@1.0.1"
                return True
            await asyncio.sleep(0.2)
            return False

        client_cm = AsyncMock()
        client_cm.__aenter__.return_value = AsyncMock()
        client_cm.__aexit__.return_value = None

        with (
            patch("agent_bom.resolver.create_client", return_value=client_cm),
            patch("agent_bom.resolver.resolve_package_version", side_effect=fake_resolve),
            patch("agent_bom.resolver.enrich_licenses", return_value=0),
        ):
            resolved = await resolve_all_versions(packages, quiet=True, global_timeout=0.05)

        assert resolved == 2
        assert packages[0].version == "1.0.1"
        assert packages[1].version == "2.0.0"
        assert packages[1].version_source == "registry_fallback"

    @pytest.mark.asyncio
    async def test_rate_limited_npm_uses_fallback_without_repeated_live_calls(self):
        packages = [
            Package(name="first", version="unknown", ecosystem="npm", registry_version="1.0.0"),
            Package(name="second", version="unknown", ecosystem="npm", registry_version="2.0.0"),
        ]

        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "5"}

        client_cm = AsyncMock()
        client_cm.__aenter__.return_value = AsyncMock()
        client_cm.__aexit__.return_value = None

        with (
            patch("agent_bom.resolver.create_client", return_value=client_cm),
            patch("agent_bom.resolver.request_with_retry", return_value=mock_response) as mock_request,
            patch("agent_bom.resolver.time.monotonic", return_value=100.0),
            patch("agent_bom.resolver.enrich_licenses", return_value=0),
        ):
            resolved = await resolve_all_versions(packages, quiet=True, global_timeout=0.5)

        assert resolved == 2
        assert packages[0].version == "1.0.0"
        assert packages[1].version == "2.0.0"
        assert packages[0].version_source == "registry_fallback"
        assert packages[1].version_source == "registry_fallback"
        assert mock_request.call_count == 1


class TestEnrichLicenses:
    @pytest.mark.asyncio
    async def test_enriches_npm_license(self):
        pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        with patch("agent_bom.resolver.resolve_npm_metadata", return_value=(None, "MIT")):
            client = AsyncMock()
            count = await enrich_licenses([pkg], client)
            assert count == 1
            assert pkg.license == "MIT"

    @pytest.mark.asyncio
    async def test_skips_already_licensed(self):
        pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        pkg.license = "MIT"
        client = AsyncMock()
        count = await enrich_licenses([pkg], client)
        assert count == 0

    @pytest.mark.asyncio
    async def test_skips_unknown_version(self):
        pkg = Package(name="express", version="unknown", ecosystem="npm")
        client = AsyncMock()
        count = await enrich_licenses([pkg], client)
        assert count == 0


class TestEnrichSupplyChainMetadata:
    @pytest.mark.asyncio
    async def test_enriches_npm_metadata(self):
        pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"description": "Web framework"}
        with patch("agent_bom.resolver.request_with_retry", return_value=mock_response):
            client = AsyncMock()
            count = await enrich_supply_chain_metadata([pkg], client)
            assert count == 1

    @pytest.mark.asyncio
    async def test_skips_packages_with_description(self):
        pkg = Package(name="express", version="4.18.2", ecosystem="npm")
        pkg.description = "Already described"
        client = AsyncMock()
        count = await enrich_supply_chain_metadata([pkg], client)
        assert count == 0
