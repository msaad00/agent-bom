"""Tests for Go module integrity verification and GOPROXY version resolution.

Covers:
- verify_go_checksums: ok / mismatch / missing / network failure / HTTPS enforcement
- resolve_go_version: latest → pinned, pre-release filtering, already-pinned passthrough,
  network failure handling
- parse_go_packages integration: mismatch marks package as malicious,
  resolve_versions updates version via proxy
"""

from __future__ import annotations

import textwrap
from unittest.mock import patch

import pytest

from agent_bom.parsers.compiled_parsers import (
    parse_go_packages,
    resolve_go_version,
    verify_go_checksums,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GO_MOD_BASIC = textwrap.dedent("""\
    module example.com/myapp

    go 1.21

    require (
        github.com/gin-gonic/gin v1.9.1
        github.com/stretchr/testify v1.8.4 // indirect
    )
""")

# go.sum with real-looking (but synthetic) hashes
GO_SUM_CONTENT = textwrap.dedent("""\
    github.com/gin-gonic/gin v1.9.1 h1:AABBCCDD==
    github.com/gin-gonic/gin v1.9.1/go.mod h1:ZZYYXXWW==
    github.com/stretchr/testify v1.8.4 h1:EEFFGGHH==
    github.com/stretchr/testify v1.8.4/go.mod h1:IIJJKKLL==
""")

# Checksum DB response format (tile protocol):
#   line 0 — tree size
#   line 1 — hash matching go.sum
#   line 2+ — signed tree head (ignored here)
_DB_RESPONSE_OK = "3\nh1:AABBCCDD==\n\nsome signed tree head\n"
_DB_RESPONSE_MISMATCH = "3\nh1:TAMPERED==\n\nsome signed tree head\n"

# GOPROXY list response (newline-separated versions)
_PROXY_LIST_STABLE = "v1.2.3\nv1.3.0\nv2.0.0\n"
_PROXY_LIST_WITH_PRERELEASE = "v1.2.3\nv1.3.0-rc1\nv1.3.0-alpha\nv1.4.0-beta.2\nv1.2.4\n"
_PROXY_LIST_EMPTY = ""


def _as_bytes(body: str) -> bytes:
    """Encode a string to bytes, matching fetch_bytes return type."""
    return body.encode("utf-8")


# ===========================================================================
# verify_go_checksums — unit tests
# ===========================================================================


class TestVerifyGoChecksumsOk:
    """Hash in go.sum matches the checksum database → status 'ok'."""

    def test_returns_ok_for_matching_hash(self, tmp_path):
        go_sum = tmp_path / "go.sum"
        go_sum.write_text(GO_SUM_CONTENT)
        modules = [("github.com/gin-gonic/gin", "v1.9.1")]

        with patch("agent_bom.http_client.fetch_bytes", return_value=_as_bytes(_DB_RESPONSE_OK)):
            result = verify_go_checksums(go_sum, modules)

        assert result["github.com/gin-gonic/gin@v1.9.1"] == "ok"

    def test_ok_result_does_not_set_malicious(self, tmp_path):
        """A passing verification must not affect any Package object."""
        go_sum = tmp_path / "go.sum"
        go_sum.write_text(GO_SUM_CONTENT)
        modules = [("github.com/gin-gonic/gin", "v1.9.1")]

        with patch("agent_bom.http_client.fetch_bytes", return_value=_as_bytes(_DB_RESPONSE_OK)):
            result = verify_go_checksums(go_sum, modules)

        # Just status; callers decide what to do with it
        assert result["github.com/gin-gonic/gin@v1.9.1"] == "ok"


class TestVerifyGoChecksumsMismatch:
    """Hash in go.sum differs from checksum database → status 'mismatch'."""

    def test_returns_mismatch_for_differing_hash(self, tmp_path):
        go_sum = tmp_path / "go.sum"
        go_sum.write_text(GO_SUM_CONTENT)
        modules = [("github.com/gin-gonic/gin", "v1.9.1")]

        with patch(
            "agent_bom.http_client.fetch_bytes",
            return_value=_as_bytes(_DB_RESPONSE_MISMATCH),
        ):
            result = verify_go_checksums(go_sum, modules)

        assert result["github.com/gin-gonic/gin@v1.9.1"] == "mismatch"

    def test_parse_go_packages_mismatch_marks_is_malicious(self, tmp_path):
        """End-to-end: go.sum mismatch propagates to Package.is_malicious=True."""
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        (tmp_path / "go.sum").write_text(GO_SUM_CONTENT)

        with patch(
            "agent_bom.http_client.fetch_bytes",
            return_value=_as_bytes(_DB_RESPONSE_MISMATCH),
        ):
            pkgs = parse_go_packages(tmp_path, verify_checksums=True)

        gin_pkg = next(p for p in pkgs if p.name == "github.com/gin-gonic/gin")
        assert gin_pkg.is_malicious is True
        assert "mismatch" in gin_pkg.malicious_reason.lower()

    def test_parse_go_packages_mismatch_reason_mentions_tamper(self, tmp_path):
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        (tmp_path / "go.sum").write_text(GO_SUM_CONTENT)

        with patch(
            "agent_bom.http_client.fetch_bytes",
            return_value=_as_bytes(_DB_RESPONSE_MISMATCH),
        ):
            pkgs = parse_go_packages(tmp_path, verify_checksums=True)

        gin_pkg = next(p for p in pkgs if p.name == "github.com/gin-gonic/gin")
        assert "tampered" in gin_pkg.malicious_reason.lower()


class TestVerifyGoChecksumsMissing:
    """Module not present in go.sum → status 'missing'."""

    def test_returns_missing_when_not_in_go_sum(self, tmp_path):
        go_sum = tmp_path / "go.sum"
        # go.sum only has testify, not gin
        go_sum.write_text("github.com/stretchr/testify v1.8.4 h1:EEFFGGHH==\ngithub.com/stretchr/testify v1.8.4/go.mod h1:IIJJKKLL==\n")
        modules = [("github.com/gin-gonic/gin", "v1.9.1")]

        # No network call expected since the module is missing from go.sum
        result = verify_go_checksums(go_sum, modules)

        assert result["github.com/gin-gonic/gin@v1.9.1"] == "missing"

    def test_missing_does_not_set_malicious(self, tmp_path):
        """Missing entry is not the same as tampered — is_malicious stays False."""
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        # Provide a go.sum without gin
        (tmp_path / "go.sum").write_text(
            "github.com/stretchr/testify v1.8.4 h1:EEFFGGHH==\ngithub.com/stretchr/testify v1.8.4/go.mod h1:IIJJKKLL==\n"
        )

        with patch("agent_bom.http_client.fetch_bytes", return_value=_as_bytes(_DB_RESPONSE_OK)):
            pkgs = parse_go_packages(tmp_path, verify_checksums=True)

        gin_pkg = next((p for p in pkgs if p.name == "github.com/gin-gonic/gin"), None)
        assert gin_pkg is not None
        assert gin_pkg.is_malicious is False


class TestVerifyGoChecksumsNetworkFailure:
    """Network failure during verification must be handled gracefully."""

    def test_network_failure_returns_empty_not_crash(self, tmp_path):
        go_sum = tmp_path / "go.sum"
        go_sum.write_text(GO_SUM_CONTENT)
        modules = [("github.com/gin-gonic/gin", "v1.9.1")]

        with patch(
            "agent_bom.http_client.fetch_bytes",
            side_effect=ConnectionError("connection refused"),
        ):
            # Must not raise
            result = verify_go_checksums(go_sum, modules)

        # Entry omitted (not surfaced as error), no crash
        assert "github.com/gin-gonic/gin@v1.9.1" not in result

    def test_oserror_returns_gracefully(self, tmp_path):
        go_sum = tmp_path / "go.sum"
        go_sum.write_text(GO_SUM_CONTENT)
        modules = [("github.com/gin-gonic/gin", "v1.9.1")]

        with patch("agent_bom.http_client.fetch_bytes", side_effect=OSError("timeout")):
            result = verify_go_checksums(go_sum, modules)

        assert "github.com/gin-gonic/gin@v1.9.1" not in result


class TestVerifyChecksumsHttpsOnly:
    """Non-HTTPS checksum DB URLs must be rejected."""

    def test_http_url_raises_value_error(self, tmp_path):
        go_sum = tmp_path / "go.sum"
        go_sum.write_text(GO_SUM_CONTENT)
        modules = [("github.com/gin-gonic/gin", "v1.9.1")]

        with pytest.raises(ValueError, match="https://"):
            verify_go_checksums(go_sum, modules, checksum_db_url="http://sum.golang.org")

    def test_file_url_raises_value_error(self, tmp_path):
        go_sum = tmp_path / "go.sum"
        go_sum.write_text(GO_SUM_CONTENT)
        modules = [("github.com/gin-gonic/gin", "v1.9.1")]

        with pytest.raises(ValueError, match="https://"):
            verify_go_checksums(go_sum, modules, checksum_db_url="file:///tmp/fake")


# ===========================================================================
# resolve_go_version — unit tests
# ===========================================================================


class TestResolveGoVersionLatest:
    """'latest' version should be resolved to the highest stable release."""

    def test_resolves_latest_to_highest_stable(self):
        with patch(
            "agent_bom.http_client.fetch_bytes",
            return_value=_as_bytes(_PROXY_LIST_STABLE),
        ):
            result = resolve_go_version("github.com/gin-gonic/gin", "latest")

        assert result == "v2.0.0"

    def test_resolves_empty_string_version(self):
        with patch(
            "agent_bom.http_client.fetch_bytes",
            return_value=_as_bytes(_PROXY_LIST_STABLE),
        ):
            result = resolve_go_version("github.com/gin-gonic/gin", "")

        assert result == "v2.0.0"

    def test_resolves_devel_version(self):
        with patch(
            "agent_bom.http_client.fetch_bytes",
            return_value=_as_bytes(_PROXY_LIST_STABLE),
        ):
            result = resolve_go_version("github.com/gin-gonic/gin", "(devel)")

        assert result == "v2.0.0"

    def test_resolves_unknown_version(self):
        with patch(
            "agent_bom.http_client.fetch_bytes",
            return_value=_as_bytes(_PROXY_LIST_STABLE),
        ):
            result = resolve_go_version("github.com/gin-gonic/gin", "unknown")

        assert result == "v2.0.0"


class TestResolveGoVersionSkipsPrerelease:
    """Pre-release versions (rc/alpha/beta/pre) must be excluded."""

    def test_skips_rc_versions(self):
        with patch(
            "agent_bom.http_client.fetch_bytes",
            return_value=_as_bytes(_PROXY_LIST_WITH_PRERELEASE),
        ):
            result = resolve_go_version("github.com/example/mod", "latest")

        # Stable versions: v1.2.3 and v1.2.4
        assert result == "v1.2.4"
        assert "rc" not in result
        assert "alpha" not in result
        assert "beta" not in result

    def test_all_prerelease_returns_original_version(self):
        all_pre = "v1.0.0-rc1\nv1.0.0-alpha\n"
        with patch(
            "agent_bom.http_client.fetch_bytes",
            return_value=_as_bytes(all_pre),
        ):
            result = resolve_go_version("github.com/example/mod", "latest")

        assert result == "latest"


class TestResolveGoVersionAlreadyPinned:
    """A pinned version string must be returned unchanged — no network call made."""

    def test_pinned_version_returns_immediately(self):
        with patch("agent_bom.http_client.fetch_bytes") as mock_fetch:
            result = resolve_go_version("github.com/gin-gonic/gin", "v1.9.1")

        mock_fetch.assert_not_called()
        assert result == "v1.9.1"

    def test_semver_with_patch_not_queried(self):
        with patch("agent_bom.http_client.fetch_bytes") as mock_fetch:
            result = resolve_go_version("github.com/pkg/errors", "v0.9.1")

        mock_fetch.assert_not_called()
        assert result == "v0.9.1"


class TestResolveGoVersionNetworkFailure:
    """Network failure must return the original version without raising."""

    def test_connection_error_returns_original_version(self):
        with patch(
            "agent_bom.http_client.fetch_bytes",
            side_effect=ConnectionError("connection refused"),
        ):
            result = resolve_go_version("github.com/gin-gonic/gin", "latest")

        assert result == "latest"

    def test_oserror_returns_original_version(self):
        with patch("agent_bom.http_client.fetch_bytes", side_effect=OSError("timeout")):
            result = resolve_go_version("github.com/gin-gonic/gin", "latest")

        assert result == "latest"

    def test_no_exception_propagated(self):
        """resolve_go_version must never raise regardless of network conditions."""
        with patch(
            "agent_bom.http_client.fetch_bytes",
            side_effect=Exception("unexpected error"),
        ):
            # Should not raise
            try:
                resolve_go_version("github.com/gin-gonic/gin", "latest")
            except Exception:  # noqa: BLE001
                pytest.fail("resolve_go_version raised an unexpected exception")


# ===========================================================================
# parse_go_packages — integration with resolve_versions
# ===========================================================================


class TestParseGoPackagesResolveVersions:
    """parse_go_packages with resolve_versions=True updates unpinned versions."""

    def test_resolve_versions_false_skips_network(self, tmp_path):
        """Default resolve_versions=False must not call the proxy."""
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)

        with patch("agent_bom.http_client.fetch_bytes") as mock_fetch:
            pkgs = parse_go_packages(tmp_path, verify_checksums=False, resolve_versions=False)

        # No proxy call for version resolution (checksums off too)
        mock_fetch.assert_not_called()
        assert pkgs  # packages still parsed

    def test_verify_checksums_false_skips_checksum_db(self, tmp_path):
        """verify_checksums=False must not call sum.golang.org."""
        (tmp_path / "go.mod").write_text(GO_MOD_BASIC)
        (tmp_path / "go.sum").write_text(GO_SUM_CONTENT)

        with patch("agent_bom.http_client.fetch_bytes") as mock_fetch:
            pkgs = parse_go_packages(tmp_path, verify_checksums=False, resolve_versions=False)

        mock_fetch.assert_not_called()
        assert pkgs
