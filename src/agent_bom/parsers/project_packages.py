"""Collect and deduplicate package evidence from one project directory."""

from pathlib import Path

from agent_bom.models import Package


def parse_project_packages(directory: Path) -> list[Package]:
    # Resolve the compatibility facade at call time to avoid import cycles.
    from agent_bom import parsers

    packages: list[Package] = []
    for parser in (
        parsers.parse_npm_packages,
        parsers.parse_yarn_lock,
        parsers.parse_pnpm_lock,
        parsers.parse_bun_packages,
        parsers.parse_pip_packages,
        parsers.parse_pip_compile_inputs,
        parsers.parse_conda_environment,
        parsers.parse_conda_packages,
        parsers.parse_go_packages,
        parsers.parse_cargo_packages,
        parsers.parse_maven_packages,
        parsers.parse_gradle_packages,
        parsers.parse_nuget_packages,
        parsers.parse_ruby_packages,
        parsers.parse_php_packages,
        parsers.parse_swift_packages,
        parsers.parse_hex_packages,
        parsers.parse_pub_packages,
    ):
        packages.extend(parser(directory))
    unique: dict[tuple[str, str, str], Package] = {}
    for package in packages:
        unique.setdefault((package.name, package.version, package.ecosystem), package)
    return list(unique.values())
