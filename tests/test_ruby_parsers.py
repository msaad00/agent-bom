"""Tests for Ruby/Gemfile parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.parsers.ruby_parsers import parse_gemfile_lock, parse_ruby_packages


@pytest.fixture()
def tmp_ruby(tmp_path: Path):
    """Helper to create temporary Ruby project files."""

    def _write(content: str, name: str = "Gemfile.lock") -> Path:
        p = tmp_path / name
        p.write_text(content)
        return tmp_path

    return _write


SAMPLE_GEMFILE_LOCK = """\
GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.1.3)
      actionpack (= 7.1.3)
      nio4r (~> 2.0)
    actionpack (7.1.3)
      rack (>= 2.2.4)
    nio4r (2.7.0)
    rack (3.0.8)
    rails (7.1.3)
      actioncable (= 7.1.3)
      actionpack (= 7.1.3)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.1)

BUNDLED WITH
   2.5.4
"""


class TestGemfileLockParser:
    """Parse Gemfile.lock correctly."""

    def test_basic_parsing(self, tmp_ruby):
        d = tmp_ruby(SAMPLE_GEMFILE_LOCK)
        pkgs = parse_gemfile_lock(d)
        names = {p.name for p in pkgs}
        assert "rails" in names
        assert "actioncable" in names
        assert "rack" in names
        assert "nio4r" in names
        assert len(pkgs) == 5

    def test_versions_exact(self, tmp_ruby):
        d = tmp_ruby(SAMPLE_GEMFILE_LOCK)
        pkgs = parse_gemfile_lock(d)
        by_name = {p.name: p for p in pkgs}
        assert by_name["rails"].version == "7.1.3"
        assert by_name["rack"].version == "3.0.8"
        assert by_name["nio4r"].version == "2.7.0"

    def test_ecosystem_rubygems(self, tmp_ruby):
        d = tmp_ruby(SAMPLE_GEMFILE_LOCK)
        pkgs = parse_gemfile_lock(d)
        for p in pkgs:
            assert p.ecosystem == "rubygems"

    def test_purl_format(self, tmp_ruby):
        d = tmp_ruby(SAMPLE_GEMFILE_LOCK)
        pkgs = parse_gemfile_lock(d)
        by_name = {p.name: p for p in pkgs}
        assert by_name["rails"].purl == "pkg:gem/rails@7.1.3"

    def test_source_gemfile_lock(self, tmp_ruby):
        d = tmp_ruby(SAMPLE_GEMFILE_LOCK)
        pkgs = parse_gemfile_lock(d)
        for p in pkgs:
            assert p.version_source == "detected"

    def test_no_duplicates(self, tmp_ruby):
        d = tmp_ruby(SAMPLE_GEMFILE_LOCK)
        pkgs = parse_gemfile_lock(d)
        keys = [(p.name.lower(), p.version) for p in pkgs]
        assert len(keys) == len(set(keys))

    def test_direct_marking_with_gemfile(self, tmp_ruby):
        """When Gemfile exists, mark matching gems as direct."""
        d = tmp_ruby(SAMPLE_GEMFILE_LOCK)
        (d / "Gemfile").write_text('gem "rails", "~> 7.1"\ngem "rack"\n')
        pkgs = parse_gemfile_lock(d)
        by_name = {p.name: p for p in pkgs}
        assert by_name["rails"].is_direct is True
        assert by_name["rack"].is_direct is True
        assert by_name["nio4r"].is_direct is False

    def test_empty_lock(self, tmp_ruby):
        d = tmp_ruby("")
        pkgs = parse_gemfile_lock(d)
        assert pkgs == []

    def test_no_lockfile(self, tmp_path):
        pkgs = parse_gemfile_lock(tmp_path)
        assert pkgs == []


class TestGemfileFallback:
    """Fall back to Gemfile when no lock file exists."""

    def test_gemfile_only(self, tmp_ruby):
        d = tmp_ruby('gem "rails", "~> 7.1.3"\ngem "pg", ">= 1.5"\n', "Gemfile")
        pkgs = parse_ruby_packages(d)
        assert len(pkgs) == 2
        by_name = {p.name: p for p in pkgs}
        assert by_name["rails"].version == "7.1.3"
        assert by_name["pg"].version == "1.5"
        assert all(p.version_source == "manifest" for p in pkgs)
        assert all(p.is_direct is True for p in pkgs)

    def test_gemfile_no_version(self, tmp_ruby):
        d = tmp_ruby("gem 'nokogiri'\n", "Gemfile")
        pkgs = parse_ruby_packages(d)
        assert len(pkgs) == 1
        assert pkgs[0].name == "nokogiri"
        assert pkgs[0].version == "unknown"

    def test_lock_takes_precedence(self, tmp_ruby):
        d = tmp_ruby(SAMPLE_GEMFILE_LOCK)
        (d / "Gemfile").write_text('gem "rails"\n')
        pkgs = parse_ruby_packages(d)
        # Should use lock file (5 gems), not Gemfile (1 gem)
        assert len(pkgs) == 5

    def test_no_ruby_files(self, tmp_path):
        pkgs = parse_ruby_packages(tmp_path)
        assert pkgs == []


class TestMultipleGEMSections:
    """Handle Gemfile.lock with multiple sections."""

    def test_path_section_ignored(self, tmp_ruby):
        content = """\
PATH
  remote: .
  specs:
    my-gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    rake (13.1.0)
    rspec (3.12.0)

PLATFORMS
  ruby

DEPENDENCIES
  my-gem!
  rake
  rspec
"""
        d = tmp_ruby(content)
        pkgs = parse_gemfile_lock(d)
        names = {p.name for p in pkgs}
        # Should only parse GEM section, not PATH
        assert "rake" in names
        assert "rspec" in names
        assert "my-gem" not in names
        assert len(pkgs) == 2
