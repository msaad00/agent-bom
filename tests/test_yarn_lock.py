"""Tests for yarn.lock (Classic v1 and Berry v2) parser."""

from __future__ import annotations

import textwrap

from agent_bom.parsers import parse_yarn_lock

YARN_V1 = textwrap.dedent("""\
    # yarn lockfile v1

    "lodash@^4.17.0":
      version "4.17.21"
      resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
      integrity sha512-xxx

    "express@^4.18.0":
      version "4.18.2"
      resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
      integrity sha512-yyy

    "@types/node@^20.0.0":
      version "20.0.0"
      resolved "https://registry.yarnpkg.com/@types/node/-/node-20.0.0.tgz"
      integrity sha512-zzz
""")

YARN_V1_MULTI_RANGE = textwrap.dedent("""\
    # yarn lockfile v1

    "accepts@~1.3.5, accepts@~1.3.7, accepts@^1.3.8":
      version "1.3.8"
      resolved "https://registry.yarnpkg.com/accepts"
      integrity sha512-aaa
""")

YARN_BERRY = textwrap.dedent("""\
    __metadata:
      version: 6
      cacheKey: 8

    "express@npm:^4.18.0":
      version: "4.18.2"
      resolution: "express@npm:4.18.2"
      checksum: abc123

    "lodash@npm:^4.17.0":
      version: "4.17.21"
      resolution: "lodash@npm:4.17.21"
      checksum: def456

    "@babel/core@npm:^7.0.0":
      version: "7.23.0"
      resolution: "@babel/core@npm:7.23.0"
      checksum: ghi789
""")


class TestYarnV1:
    def test_parses_packages(self, tmp_path):
        (tmp_path / "yarn.lock").write_text(YARN_V1)
        pkgs = parse_yarn_lock(tmp_path)
        names = {p.name for p in pkgs}
        assert "lodash" in names
        assert "express" in names

    def test_scoped_package(self, tmp_path):
        (tmp_path / "yarn.lock").write_text(YARN_V1)
        pkgs = parse_yarn_lock(tmp_path)
        names = {p.name for p in pkgs}
        assert "@types/node" in names

    def test_versions_correct(self, tmp_path):
        (tmp_path / "yarn.lock").write_text(YARN_V1)
        pkgs = parse_yarn_lock(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["lodash"].version == "4.17.21"
        assert by_name["express"].version == "4.18.2"

    def test_ecosystem_is_npm(self, tmp_path):
        (tmp_path / "yarn.lock").write_text(YARN_V1)
        pkgs = parse_yarn_lock(tmp_path)
        assert all(p.ecosystem == "npm" for p in pkgs)

    def test_purl_format(self, tmp_path):
        (tmp_path / "yarn.lock").write_text(YARN_V1)
        pkgs = parse_yarn_lock(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["lodash"].purl == "pkg:npm/lodash@4.17.21"

    def test_multi_range_deduplicates(self, tmp_path):
        """Multiple version ranges resolving to same version → one entry."""
        (tmp_path / "yarn.lock").write_text(YARN_V1_MULTI_RANGE)
        pkgs = parse_yarn_lock(tmp_path)
        accepts = [p for p in pkgs if p.name == "accepts"]
        assert len(accepts) == 1
        assert accepts[0].version == "1.3.8"

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_yarn_lock(tmp_path) == []


class TestYarnBerry:
    def test_parses_packages(self, tmp_path):
        (tmp_path / "yarn.lock").write_text(YARN_BERRY)
        pkgs = parse_yarn_lock(tmp_path)
        names = {p.name for p in pkgs}
        assert "express" in names
        assert "lodash" in names

    def test_scoped_package(self, tmp_path):
        (tmp_path / "yarn.lock").write_text(YARN_BERRY)
        pkgs = parse_yarn_lock(tmp_path)
        names = {p.name for p in pkgs}
        assert "@babel/core" in names

    def test_versions_correct(self, tmp_path):
        (tmp_path / "yarn.lock").write_text(YARN_BERRY)
        pkgs = parse_yarn_lock(tmp_path)
        by_name = {p.name: p for p in pkgs}
        assert by_name["express"].version == "4.18.2"
        assert by_name["lodash"].version == "4.17.21"

    def test_ecosystem_is_npm(self, tmp_path):
        (tmp_path / "yarn.lock").write_text(YARN_BERRY)
        pkgs = parse_yarn_lock(tmp_path)
        assert all(p.ecosystem == "npm" for p in pkgs)
