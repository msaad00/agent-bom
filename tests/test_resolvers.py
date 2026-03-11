"""Tests for version resolvers and drift detection."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from agent_bom.models import Package
from agent_bom.resolvers.drift_detector import (
    DriftReport,
    VersionDrift,
    _assess_drift_severity,
    _normalize_name,
    _parse_version_parts,
    _versions_match,
    detect_drift,
)
from agent_bom.resolvers.runtime_resolver import (
    _walk_npm_tree,
    resolve_go_versions,
    resolve_npm_versions,
    resolve_pip_versions,
)

# ── Runtime Resolver Tests ────────────────────────────────────────────────────


class TestResolvePipVersions:
    """Tests for pip version resolution."""

    def test_pip_not_found(self):
        with patch("shutil.which", return_value=None):
            assert resolve_pip_versions() == {}

    def test_pip_success(self):
        mock_output = json.dumps(
            [
                {"name": "requests", "version": "2.31.0"},
                {"name": "Flask", "version": "3.0.0"},
            ]
        )
        mock_result = MagicMock(returncode=0, stdout=mock_output, stderr="")
        with patch("shutil.which", return_value="/usr/bin/pip"), patch("subprocess.run", return_value=mock_result):
            versions = resolve_pip_versions()
            assert versions == {"requests": "2.31.0", "flask": "3.0.0"}

    def test_pip_with_python_path(self):
        mock_output = json.dumps([{"name": "numpy", "version": "1.26.0"}])
        mock_result = MagicMock(returncode=0, stdout=mock_output, stderr="")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            versions = resolve_pip_versions(python_path="/path/to/python")
            assert versions == {"numpy": "1.26.0"}
            mock_run.assert_called_once()
            assert mock_run.call_args[0][0][0] == "/path/to/python"

    def test_pip_failure(self):
        mock_result = MagicMock(returncode=1, stdout="", stderr="error")
        with patch("shutil.which", return_value="/usr/bin/pip"), patch("subprocess.run", return_value=mock_result):
            assert resolve_pip_versions() == {}

    def test_pip_timeout(self):
        with patch("shutil.which", return_value="/usr/bin/pip"), patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pip", 30)):
            assert resolve_pip_versions() == {}

    def test_pip_invalid_json(self):
        mock_result = MagicMock(returncode=0, stdout="not json", stderr="")
        with patch("shutil.which", return_value="/usr/bin/pip"), patch("subprocess.run", return_value=mock_result):
            assert resolve_pip_versions() == {}


class TestResolveNpmVersions:
    """Tests for npm version resolution."""

    def test_npm_not_found(self, tmp_path):
        with patch("shutil.which", return_value=None):
            assert resolve_npm_versions(tmp_path) == {}

    def test_no_package_json(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/npm"):
            assert resolve_npm_versions(tmp_path) == {}

    def test_npm_success(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        mock_output = json.dumps(
            {
                "dependencies": {
                    "express": {"version": "4.18.2", "dependencies": {"accepts": {"version": "1.3.8"}}},
                    "lodash": {"version": "4.17.21"},
                }
            }
        )
        mock_result = MagicMock(returncode=0, stdout=mock_output, stderr="")
        with patch("shutil.which", return_value="/usr/bin/npm"), patch("subprocess.run", return_value=mock_result):
            versions = resolve_npm_versions(tmp_path)
            assert versions == {"express": "4.18.2", "accepts": "1.3.8", "lodash": "4.17.21"}

    def test_npm_nonzero_exit_still_parses(self, tmp_path):
        """npm ls returns non-zero for missing deps but still outputs JSON."""
        (tmp_path / "package.json").write_text("{}")
        mock_output = json.dumps({"dependencies": {"pkg": {"version": "1.0.0"}}})
        mock_result = MagicMock(returncode=1, stdout=mock_output, stderr="missing deps")
        with patch("shutil.which", return_value="/usr/bin/npm"), patch("subprocess.run", return_value=mock_result):
            versions = resolve_npm_versions(tmp_path)
            assert versions == {"pkg": "1.0.0"}

    def test_npm_empty_output(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        mock_result = MagicMock(returncode=0, stdout="", stderr="")
        with patch("shutil.which", return_value="/usr/bin/npm"), patch("subprocess.run", return_value=mock_result):
            assert resolve_npm_versions(tmp_path) == {}

    def test_npm_timeout(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        with patch("shutil.which", return_value="/usr/bin/npm"), patch("subprocess.run", side_effect=subprocess.TimeoutExpired("npm", 30)):
            assert resolve_npm_versions(tmp_path) == {}


class TestResolveGoVersions:
    """Tests for Go module version resolution."""

    def test_go_not_found(self, tmp_path):
        with patch("shutil.which", return_value=None):
            assert resolve_go_versions(tmp_path) == {}

    def test_no_go_mod(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/go"):
            assert resolve_go_versions(tmp_path) == {}

    def test_go_success(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/foo")
        # go list -m -json outputs concatenated JSON objects
        mock_output = '{"Path": "github.com/foo/bar", "Version": "v1.2.3"}\n{"Path": "github.com/baz/qux", "Version": "v0.5.0"}\n'
        mock_result = MagicMock(returncode=0, stdout=mock_output, stderr="")
        with patch("shutil.which", return_value="/usr/bin/go"), patch("subprocess.run", return_value=mock_result):
            versions = resolve_go_versions(tmp_path)
            assert versions == {"github.com/foo/bar": "1.2.3", "github.com/baz/qux": "0.5.0"}

    def test_go_failure(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/foo")
        mock_result = MagicMock(returncode=1, stdout="", stderr="error")
        with patch("shutil.which", return_value="/usr/bin/go"), patch("subprocess.run", return_value=mock_result):
            assert resolve_go_versions(tmp_path) == {}

    def test_go_timeout(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/foo")
        with patch("shutil.which", return_value="/usr/bin/go"), patch("subprocess.run", side_effect=subprocess.TimeoutExpired("go", 30)):
            assert resolve_go_versions(tmp_path) == {}


class TestWalkNpmTree:
    """Tests for npm dependency tree walker."""

    def test_flat_deps(self):
        deps = {"a": {"version": "1.0"}, "b": {"version": "2.0"}}
        versions: dict[str, str] = {}
        _walk_npm_tree(deps, versions)
        assert versions == {"a": "1.0", "b": "2.0"}

    def test_nested_deps(self):
        deps = {"a": {"version": "1.0", "dependencies": {"c": {"version": "3.0"}}}}
        versions: dict[str, str] = {}
        _walk_npm_tree(deps, versions)
        assert versions == {"a": "1.0", "c": "3.0"}

    def test_empty(self):
        versions: dict[str, str] = {}
        _walk_npm_tree({}, versions)
        assert versions == {}

    def test_missing_version_key(self):
        deps = {"a": {"resolved": "https://..."}}
        versions: dict[str, str] = {}
        _walk_npm_tree(deps, versions)
        assert versions == {}


# ── Drift Detector Tests ─────────────────────────────────────────────────────


class TestNormalizeName:
    def test_pypi_normalize(self):
        assert _normalize_name("Flask-Login", "pypi") == "flask_login"
        assert _normalize_name("my.package", "pypi") == "my_package"
        assert _normalize_name("requests", "pypi") == "requests"

    def test_npm_case_sensitive(self):
        assert _normalize_name("Express", "npm") == "Express"
        assert _normalize_name("@scope/pkg", "npm") == "@scope/pkg"

    def test_go_case_sensitive(self):
        assert _normalize_name("github.com/Foo/Bar", "go") == "github.com/Foo/Bar"


class TestVersionsMatch:
    def test_exact_match(self):
        assert _versions_match("1.2.3", "1.2.3")

    def test_prefix_strip(self):
        assert _versions_match("v1.2.3", "1.2.3")
        assert _versions_match("^1.2.3", "1.2.3")
        assert _versions_match("==1.2.3", "1.2.3")

    def test_mismatch(self):
        assert not _versions_match("1.2.3", "1.2.4")


class TestAssessDriftSeverity:
    def test_major_drift(self):
        assert _assess_drift_severity("1.2.3", "2.0.0") == "critical"

    def test_minor_drift(self):
        assert _assess_drift_severity("1.2.3", "1.3.0") == "high"

    def test_patch_drift(self):
        assert _assess_drift_severity("1.2.3", "1.2.4") == "medium"

    def test_same_version(self):
        assert _assess_drift_severity("1.2.3", "1.2.3") == "low"

    def test_unparseable(self):
        assert _assess_drift_severity("abc", "xyz") == "medium"


class TestParseVersionParts:
    def test_full_semver(self):
        assert _parse_version_parts("1.2.3") == (1, 2, 3)

    def test_with_v_prefix(self):
        assert _parse_version_parts("v1.2.3") == (1, 2, 3)

    def test_major_only(self):
        assert _parse_version_parts("3") == (3, 0, 0)

    def test_major_minor(self):
        assert _parse_version_parts("3.1") == (3, 1, 0)

    def test_unparseable(self):
        assert _parse_version_parts("latest") is None


class TestDetectDrift:
    def _make_pkg(self, name: str, version: str, ecosystem: str = "pypi") -> Package:
        return Package(
            name=name,
            version=version,
            ecosystem=ecosystem,
            purl=f"pkg:{ecosystem}/{name}@{version}",
            is_direct=True,
        )

    def test_no_drift(self):
        declared = [self._make_pkg("requests", "2.31.0")]
        installed = {"requests": "2.31.0"}
        report = detect_drift(declared, installed, "pypi")
        assert report.drift_count == 0
        assert report.match_count == 1

    def test_version_mismatch(self):
        declared = [self._make_pkg("requests", "2.28.0")]
        installed = {"requests": "2.31.0"}
        report = detect_drift(declared, installed, "pypi")
        assert report.drift_count == 1
        assert report.drifts[0].drift_type == "version_mismatch"
        assert report.drifts[0].severity == "high"  # minor version diff

    def test_missing_package(self):
        declared = [self._make_pkg("requests", "2.31.0")]
        installed = {}
        report = detect_drift(declared, installed, "pypi")
        assert report.drift_count == 1
        assert report.drifts[0].drift_type == "missing"
        assert report.drifts[0].severity == "high"

    def test_undeclared_package(self):
        declared = []
        installed = {"rogue-pkg": "1.0.0"}
        report = detect_drift(declared, installed, "pypi")
        assert report.drift_count == 1
        assert report.drifts[0].drift_type == "undeclared"
        assert report.drifts[0].severity == "medium"

    def test_pypi_name_normalization(self):
        """Flask-Login in manifest should match flask-login from pip."""
        declared = [self._make_pkg("Flask-Login", "0.6.3")]
        installed = {"flask_login": "0.6.3"}
        report = detect_drift(declared, installed, "pypi")
        assert report.drift_count == 0
        assert report.match_count == 1

    def test_mixed_ecosystems_filtered(self):
        """Only compare packages of the target ecosystem."""
        declared = [
            self._make_pkg("requests", "2.31.0", "pypi"),
            self._make_pkg("express", "4.18.2", "npm"),
        ]
        installed = {"requests": "2.31.0"}
        report = detect_drift(declared, installed, "pypi")
        assert report.declared_count == 1  # Only pypi packages counted
        assert report.match_count == 1

    def test_critical_major_drift(self):
        declared = [self._make_pkg("lodash", "3.10.1", "npm")]
        installed = {"lodash": "4.17.21"}
        report = detect_drift(declared, installed, "npm")
        assert report.drifts[0].severity == "critical"

    def test_to_dict(self):
        declared = [self._make_pkg("pkg", "1.0.0")]
        installed = {"pkg": "2.0.0"}
        report = detect_drift(declared, installed, "pypi")
        d = report.to_dict()
        assert d["drift_count"] == 1
        assert d["has_critical"] is True
        assert d["drifts"][0]["package"] == "pkg"

    def test_empty_inputs(self):
        report = detect_drift([], {}, "pypi")
        assert report.drift_count == 0
        assert report.declared_count == 0
        assert report.installed_count == 0


class TestVersionDrift:
    def test_to_dict(self):
        drift = VersionDrift(
            package_name="pkg",
            ecosystem="npm",
            declared_version="1.0.0",
            installed_version="2.0.0",
            drift_type="version_mismatch",
            severity="critical",
            detail="test",
        )
        d = drift.to_dict()
        assert d["package"] == "pkg"
        assert d["severity"] == "critical"


class TestDriftReport:
    def test_has_critical(self):
        report = DriftReport()
        assert not report.has_critical
        report.drifts.append(VersionDrift("p", "npm", "1.0", "2.0", "version_mismatch", "critical", "test"))
        assert report.has_critical

    def test_drift_count(self):
        report = DriftReport()
        assert report.drift_count == 0
        report.drifts.append(VersionDrift("p", "npm", "1.0", "1.1", "version_mismatch", "medium", "test"))
        assert report.drift_count == 1
