"""Shared remediation command builders for console, JSON, and automation."""

from __future__ import annotations

import re

_SHELL_METACHAR_RE = re.compile(r"[;&|`$\n\r<>\"'\\]")

_ECOSYSTEM_COMMANDS: dict[str, str] = {
    "npm": "npm install {package}@{version}",
    "pypi": "pip install '{package}>={version}'",
    "PyPI": "pip install '{package}>={version}'",
    "cargo": "cargo update -p {package} --precise {version}",
    "go": "go get {package}@v{version}",
    "maven": "# Update {package} to {version} in pom.xml",
    "nuget": "dotnet add package {package} --version {version}",
    "rubygems": "gem install {package} -v '{version}'",
}


def has_shell_metachar(value: str) -> bool:
    """Check if a string contains shell metacharacters that could enable injection."""
    return bool(_SHELL_METACHAR_RE.search(value))


def build_fix_command(ecosystem: str, package: str, version: str) -> str | None:
    """Build the primary remediation command for a package/ecosystem/version."""
    if not ecosystem or not package or not version:
        return None
    if has_shell_metachar(package) or has_shell_metachar(version):
        return None
    template = _ECOSYSTEM_COMMANDS.get(ecosystem)
    if not template:
        return None
    return template.format(package=package, version=version)


def build_verify_command(ecosystem: str, package: str, version: str) -> str | None:
    """Build a follow-up verification command using agent-bom's pre-install checker."""
    if not ecosystem or not package or not version:
        return None
    if has_shell_metachar(package) or has_shell_metachar(version):
        return None
    normalized = ecosystem.lower()
    return f"agent-bom check {package}@{version} --ecosystem {normalized}"
