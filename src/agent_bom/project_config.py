"""Project-level configuration file support for agent-bom.

Loads ``.agent-bom.yaml`` (or ``.agent-bom.yml`` / ``agent-bom.yaml``) from
the current working directory or any ancestor directory, providing per-project
defaults for CLI flags.

Inspired by common scanner configuration files — lets teams commit security
configuration alongside their code without adding CLI flags everywhere.

Supported keys
--------------
::

    # .agent-bom.yaml
    ignore:
      - CVE-2023-1234          # suppress specific CVEs
      - GHSA-xxxx-yyyy-zzzz

    min_severity: medium       # low | medium | high | critical
    fail_on_severity: high     # fail CI when this severity or above found
    fail_on_kev: true          # fail CI when CISA KEV CVE found
    enrich: true               # always run NVD/EPSS/KEV enrichment
    transitive: true           # always scan transitive deps

    policy: path/to/policy.yml # path to proxy policy file

    output: json               # default output format
    output_file: report.json   # default output file

    scan:
      aws: false               # disable cloud scanners by default
      databricks: false
      verify_model_hashes: false

Usage
-----
The CLI auto-loads project config on startup and merges it with CLI flags
(CLI flags always win over project config).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_CONFIG_FILENAMES = (".agent-bom.yaml", ".agent-bom.yml", "agent-bom.yaml")


def find_project_config(start: Path | None = None) -> Path | None:
    """Search ``start`` and its ancestors for a project config file.

    Returns the first matching path found, or None.
    """
    search = (start or Path.cwd()).resolve()
    for directory in [search, *search.parents]:
        for name in _CONFIG_FILENAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def load_project_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load and return the project config as a plain dict.

    Searches for the config file if ``config_path`` is not given.
    Returns an empty dict on missing file or parse error — never raises.
    """
    path = config_path or find_project_config()
    if path is None:
        return {}

    try:
        import yaml  # PyYAML — available via pyyaml dep
    except ImportError:
        logger.debug("PyYAML not available; .agent-bom.yaml not loaded")
        return {}

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        logger.warning("Failed to parse project config %s: %s", path, e)
        return {}

    if not isinstance(raw, dict):
        logger.warning("Project config %s must be a YAML mapping — ignored", path)
        return {}

    logger.debug("Loaded project config from %s", path)
    return raw


def get_ignore_list(config: dict[str, Any]) -> list[str]:
    """Return the list of CVE/GHSA IDs to suppress from the project config."""
    raw = config.get("ignore", [])
    if not isinstance(raw, list):
        return []
    return [str(v) for v in raw if v]


def get_min_severity(config: dict[str, Any]) -> str | None:
    """Return the minimum severity level from project config, or None."""
    val = config.get("min_severity")
    if isinstance(val, str) and val.lower() in ("low", "medium", "high", "critical"):
        return val.lower()
    return None


def get_fail_on_severity(config: dict[str, Any]) -> str | None:
    """Return the fail-on severity threshold from project config, or None."""
    val = config.get("fail_on_severity")
    if isinstance(val, str) and val.lower() in ("low", "medium", "high", "critical"):
        return val.lower()
    return None


def get_policy_path(config: dict[str, Any]) -> Path | None:
    """Return the policy file path from project config, or None."""
    val = config.get("policy")
    if isinstance(val, str) and val:
        return Path(val)
    return None
