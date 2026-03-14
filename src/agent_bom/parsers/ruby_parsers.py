"""Ruby/Gemfile parser — extracts gems from Gemfile.lock.

Parses Gemfile.lock (Bundler lock file) to extract gem names, versions,
and source metadata.  Falls back to Gemfile for direct dependencies when
no lock file is present.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from agent_bom.models import Package

logger = logging.getLogger(__name__)


def parse_gemfile_lock(directory: str | Path) -> list[Package]:
    """Parse gems from Gemfile.lock in *directory*.

    Gemfile.lock format (Bundler)::

        GEM
          remote: https://rubygems.org/
          specs:
            actioncable (7.1.3)
              actionpack (= 7.1.3)
              nio4r (~> 2.0)
            actionpack (7.1.3)
              ...

    Only the ``GEM`` → ``specs:`` section is parsed.  Each top-level entry
    under ``specs:`` (4-space indent) is a direct gem; nested entries
    (6+ space indent) are transitive dependencies.

    Returns
    -------
    list[Package]
        Parsed gems with ecosystem ``rubygems``.
    """
    lockfile = Path(directory) / "Gemfile.lock"
    if not lockfile.is_file():
        return []

    try:
        content = lockfile.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Cannot read %s: %s", lockfile, exc)
        return []

    packages: list[Package] = []
    seen: set[tuple[str, str]] = set()

    # Read direct dependency names from Gemfile for is_direct marking
    direct_names: set[str] = set()
    gemfile = Path(directory) / "Gemfile"
    if gemfile.is_file():
        try:
            gf_content = gemfile.read_text(encoding="utf-8", errors="replace")
            # Match: gem "name" or gem 'name'
            for m in re.finditer(r"""gem\s+["']([^"']+)["']""", gf_content):
                direct_names.add(m.group(1).strip())
        except OSError:
            pass

    # Parse the GEM specs section
    in_gem_section = False
    in_specs = False
    # Pattern: 4 spaces + gem_name (version)
    gem_pattern = re.compile(r"^    (\S+)\s+\(([^)]+)\)$")

    for line in content.splitlines():
        stripped = line.rstrip()

        # Detect section boundaries
        if stripped == "GEM":
            in_gem_section = True
            in_specs = False
            continue
        if in_gem_section and stripped.strip() == "specs:":
            in_specs = True
            continue
        # End of GEM section (new section starts at column 0)
        if in_gem_section and stripped and not stripped.startswith(" "):
            in_gem_section = False
            in_specs = False
            continue

        if not in_specs:
            continue

        # Match top-level gems (4-space indent)
        m = gem_pattern.match(line)
        if not m:
            continue

        name = m.group(1)
        version = m.group(2)
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)

        is_direct = name in direct_names or not direct_names
        packages.append(
            Package(
                name=name,
                version=version,
                ecosystem="rubygems",
                version_source="detected",
                purl=f"pkg:gem/{name}@{version}",
                is_direct=is_direct,
            ),
        )

    if packages:
        logger.info("Parsed %d gems from %s", len(packages), lockfile)

    return packages


def parse_ruby_packages(directory: str | Path) -> list[Package]:
    """Parse Ruby packages from a project directory.

    Prefers Gemfile.lock (exact versions) over Gemfile (version specs).

    Parameters
    ----------
    directory:
        Project root containing Gemfile and/or Gemfile.lock.

    Returns
    -------
    list[Package]
        All discovered Ruby gems.
    """
    packages = parse_gemfile_lock(directory)
    if packages:
        return packages

    # Fallback: parse Gemfile for declared (not resolved) dependencies
    gemfile = Path(directory) / "Gemfile"
    if not gemfile.is_file():
        return []

    try:
        content = gemfile.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Cannot read %s: %s", gemfile, exc)
        return []

    packages = []
    seen: set[str] = set()
    # Match: gem "name", "~> 1.2.3" or gem 'name', '>= 2.0'
    gem_re = re.compile(
        r"""gem\s+["']([^"']+)["']"""
        r"""(?:\s*,\s*["']([^"']+)["'])?"""
    )

    for m in gem_re.finditer(content):
        name = m.group(1).strip()
        version_spec = m.group(2) or ""
        # Extract version number from spec (e.g., "~> 1.2.3" -> "1.2.3")
        version = re.sub(r"^[~><=!]+\s*", "", version_spec).strip() or "unknown"
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        packages.append(
            Package(
                name=name,
                version=version,
                ecosystem="rubygems",
                version_source="manifest",
                purl=f"pkg:gem/{name}@{version}",
                is_direct=True,
            ),
        )

    if packages:
        logger.info("Parsed %d gems from %s (no lock file)", len(packages), gemfile)

    return packages
