"""Tests for PHP Composer parser."""

from pathlib import Path

import pytest

from agent_bom.parsers.php_parsers import parse_composer_lock, parse_php_packages


@pytest.fixture
def tmp_project(tmp_path: Path):
    """Create a temporary project with PHP files."""
    return tmp_path


def test_parse_composer_lock(tmp_project: Path):
    """Parse packages from a composer.lock file."""
    lock_data = {
        "packages": [
            {"name": "monolog/monolog", "version": "3.5.0"},
            {"name": "symfony/console", "version": "v7.0.4"},
        ],
        "packages-dev": [
            {"name": "phpunit/phpunit", "version": "11.0.3"},
        ],
    }
    (tmp_project / "composer.lock").write_text(__import__("json").dumps(lock_data), encoding="utf-8")

    packages = parse_composer_lock(tmp_project)
    assert len(packages) == 3

    names = {p.name for p in packages}
    assert "monolog/monolog" in names
    assert "symfony/console" in names
    assert "phpunit/phpunit" in names

    # Version "v" prefix stripped
    symfony = next(p for p in packages if p.name == "symfony/console")
    assert symfony.version == "7.0.4"

    # Ecosystem and purl
    assert all(p.ecosystem == "composer" for p in packages)
    assert symfony.purl == "pkg:composer/symfony/console@7.0.4"


def test_parse_composer_lock_with_direct_deps(tmp_project: Path):
    """Direct dependencies marked from composer.json."""
    (tmp_project / "composer.json").write_text(
        __import__("json").dumps(
            {
                "require": {"monolog/monolog": "^3.0"},
                "require-dev": {"phpunit/phpunit": "^11.0"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_project / "composer.lock").write_text(
        __import__("json").dumps(
            {
                "packages": [
                    {"name": "monolog/monolog", "version": "3.5.0"},
                    {"name": "psr/log", "version": "3.0.0"},
                ],
                "packages-dev": [
                    {"name": "phpunit/phpunit", "version": "11.0.3"},
                ],
            }
        ),
        encoding="utf-8",
    )

    packages = parse_composer_lock(tmp_project)
    monolog = next(p for p in packages if p.name == "monolog/monolog")
    psr_log = next(p for p in packages if p.name == "psr/log")
    phpunit = next(p for p in packages if p.name == "phpunit/phpunit")

    assert monolog.is_direct is True
    assert psr_log.is_direct is False  # Not in composer.json require
    assert phpunit.is_direct is True


def test_parse_composer_json_fallback(tmp_project: Path):
    """Fall back to composer.json when no lock file."""
    (tmp_project / "composer.json").write_text(
        __import__("json").dumps(
            {
                "require": {
                    "php": ">=8.1",
                    "ext-json": "*",
                    "laravel/framework": "^11.0",
                },
            }
        ),
        encoding="utf-8",
    )

    packages = parse_php_packages(tmp_project)
    assert len(packages) == 1  # php and ext-json skipped
    assert packages[0].name == "laravel/framework"
    assert packages[0].version == "11.0"
    assert packages[0].is_direct is True


def test_parse_no_php_files(tmp_project: Path):
    """No packages when no PHP files exist."""
    assert parse_php_packages(tmp_project) == []


def test_parse_deduplication(tmp_project: Path):
    """No duplicate packages from lock file."""
    (tmp_project / "composer.lock").write_text(
        __import__("json").dumps(
            {
                "packages": [
                    {"name": "monolog/monolog", "version": "3.5.0"},
                    {"name": "monolog/monolog", "version": "3.5.0"},
                ],
                "packages-dev": [],
            }
        ),
        encoding="utf-8",
    )

    packages = parse_composer_lock(tmp_project)
    assert len(packages) == 1
