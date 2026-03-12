"""Tests for Maven Central and crates.io version resolution."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.parsers.compiled_parsers import (
    resolve_cargo_version,
    resolve_maven_version,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_urlopen_response(body: dict) -> MagicMock:
    """Return a mock context-manager suitable for patching urllib.request.urlopen."""
    raw = json.dumps(body).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = raw
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ── Maven Central tests ───────────────────────────────────────────────────────


class TestResolveMavenVersion:
    """Maven Central version resolution via resolve_maven_version()."""

    def test_resolve_maven_version_release(self):
        """'RELEASE' triggers a Maven Central fetch and returns the stable version."""
        body = {
            "response": {
                "docs": [
                    {"g": "org.springframework", "a": "spring-core", "v": "6.1.4"},
                ]
            }
        }
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(body)):
            result = resolve_maven_version("org.springframework", "spring-core", "RELEASE")
        assert result == "6.1.4"

    def test_resolve_maven_version_latest(self):
        """'LATEST' triggers a Maven Central fetch and returns the stable version."""
        body = {
            "response": {
                "docs": [
                    {"g": "com.google.guava", "a": "guava", "v": "33.0.0-jre"},
                    {"g": "com.google.guava", "a": "guava", "v": "32.1.3-jre"},
                ]
            }
        }
        # "33.0.0-jre" does not match the SNAPSHOT/RC/M prerelease pattern so it
        # is the first stable doc returned — resolver should return it.
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(body)):
            result = resolve_maven_version("com.google.guava", "guava", "LATEST")
        assert result == "33.0.0-jre"

    def test_resolve_maven_version_pinned(self):
        """A pinned version is returned immediately without any network call."""
        with patch("urllib.request.urlopen") as mock_open:
            result = resolve_maven_version("org.springframework", "spring-core", "5.3.30")
        mock_open.assert_not_called()
        assert result == "5.3.30"

    def test_resolve_maven_version_skips_snapshot(self):
        """Docs with SNAPSHOT suffix are skipped; the next stable doc is returned."""
        body = {
            "response": {
                "docs": [
                    {"g": "com.example", "a": "lib", "v": "2.0.0-SNAPSHOT"},
                    {"g": "com.example", "a": "lib", "v": "1.9.0-RC1"},
                    {"g": "com.example", "a": "lib", "v": "1.8.5"},
                ]
            }
        }
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(body)):
            result = resolve_maven_version("com.example", "lib", "RELEASE")
        assert result == "1.8.5"

    def test_resolve_maven_version_network_failure(self):
        """A network error returns the original version string without raising."""
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
            result = resolve_maven_version("org.apache", "commons-lang3", "RELEASE")
        assert result == "RELEASE"

    def test_resolve_maven_version_https_only(self):
        """An http:// maven_central_url raises ValueError before any network call."""
        with pytest.raises(ValueError, match="https://"):
            resolve_maven_version(
                "org.springframework",
                "spring-core",
                "RELEASE",
                maven_central_url="http://search.maven.org",
            )


# ── crates.io tests ───────────────────────────────────────────────────────────


class TestResolveCargoVersion:
    """crates.io version resolution via resolve_cargo_version()."""

    def test_resolve_cargo_version_wildcard(self):
        """'*' triggers a crates.io fetch and returns max_stable_version."""
        body = {
            "crate": {
                "max_stable_version": "1.0.196",
                "newest_version": "1.0.197-beta.1",
            }
        }
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(body)), patch("time.sleep"):
            result = resolve_cargo_version("serde", "*")
        assert result == "1.0.196"

    def test_resolve_cargo_version_pinned(self):
        """A pinned version is returned immediately without any network call."""
        with patch("urllib.request.urlopen") as mock_open, patch("time.sleep"):
            result = resolve_cargo_version("serde", "1.76.0")
        mock_open.assert_not_called()
        assert result == "1.76.0"

    def test_resolve_cargo_version_uses_max_stable(self):
        """max_stable_version is preferred over newest_version (which may be pre-release)."""
        body = {
            "crate": {
                "max_stable_version": "0.11.0",
                "newest_version": "0.12.0-alpha.3",
            }
        }
        with patch("urllib.request.urlopen", return_value=_make_urlopen_response(body)), patch("time.sleep"):
            result = resolve_cargo_version("tokio", "*")
        assert result == "0.11.0"
        assert result != "0.12.0-alpha.3"

    def test_resolve_cargo_version_network_failure(self):
        """A network error returns the original version string without raising."""
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")), patch("time.sleep"):
            result = resolve_cargo_version("serde", "*")
        assert result == "*"

    def test_resolve_cargo_user_agent(self):
        """The User-Agent header required by crates.io policy is sent with the request."""
        body = {
            "crate": {
                "max_stable_version": "2.0.0",
                "newest_version": "2.0.0",
            }
        }
        captured_requests: list = []

        def _capture_urlopen(req, timeout=5):
            captured_requests.append(req)
            return _make_urlopen_response(body)

        with patch("urllib.request.urlopen", side_effect=_capture_urlopen), patch("time.sleep"):
            resolve_cargo_version("rand", "")

        assert len(captured_requests) == 1
        ua = captured_requests[0].get_header("User-agent")
        assert ua is not None
        assert "agent-bom" in ua
        assert "github.com/msaad00/agent-bom" in ua
