"""Enterprise inventory ingestion — JSON and CSV formats, stdin support.

Supports:
- **JSON**: Full inventory schema (``agents[]`` → ``mcp_servers[]`` → ``packages[]``)
- **CSV**:  Flat format for CMDB/spreadsheet export
- **Stdin**: ``--inventory -`` reads from stdin (auto-detects JSON vs CSV)

CSV format (required columns: ``name``, ``version``, ``ecosystem``)::

    name,version,ecosystem,server_name,agent_name,env_keys
    langchain,0.1.0,pypi,ai-server,prod-agent,OPENAI_API_KEY;SLACK_TOKEN
    express,4.18.2,npm,api-server,prod-agent,
    fastapi,0.104.0,pypi,ai-server,prod-agent,

Minimal 3-column CSV also works::

    name,version,ecosystem
    langchain,0.1.0,pypi
    fastapi,0.104.0,pypi

Usage::

    from agent_bom.inventory import load_inventory

    data = load_inventory("fleet.csv")       # CSV file
    data = load_inventory("inventory.json")  # JSON file
    data = load_inventory("-")               # stdin (auto-detect)
"""

from __future__ import annotations

import csv
import io
import json
import logging
import sys
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Required CSV columns for package scanning.
_CSV_REQUIRED_COLUMNS = frozenset({"name", "version", "ecosystem"})

# Size guard to prevent OOM on malicious/huge inputs.
_MAX_INVENTORY_SIZE = 100 * 1024 * 1024  # 100 MB
_ECOSYSTEM_ALIASES = {
    "pip": "pypi",
    "python": "pypi",
    "node": "npm",
    "golang": "go",
    "crates": "cargo",
    "dotnet": "nuget",
}


def _inventory_schema_path() -> Path | None:
    """Return the inventory schema path from source or installed package data."""
    candidate_paths = [
        Path(__file__).parent.parent.parent / "config" / "schemas" / "inventory.schema.json",
        Path(__file__).parent / "data" / "inventory.schema.json",
        Path(__file__).parent.parent.parent / "schemas" / "inventory.schema.json",
    ]
    for candidate in candidate_paths:
        if candidate.exists():
            return candidate

    try:
        import importlib.resources

        package_root = Path(str(importlib.resources.files("agent_bom")))
    except Exception:
        return None

    package_schema = Path(str(importlib.resources.files("agent_bom").joinpath("data", "inventory.schema.json")))
    if package_schema.exists():
        return package_schema

    fallback_paths = [
        package_root / ".." / ".." / "config" / "schemas" / "inventory.schema.json",
        package_root / ".." / ".." / "schemas" / "inventory.schema.json",
    ]
    for candidate in fallback_paths:
        resolved = candidate.resolve()
        if resolved.exists():
            return resolved
    return None


@lru_cache(maxsize=1)
def _inventory_validator():
    """Build and cache the inventory JSON Schema validator."""
    import jsonschema

    schema_path = _inventory_schema_path()
    if not schema_path or not schema_path.exists():
        raise RuntimeError("Inventory schema file not found")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def _validate_inventory_payload(data: Any) -> dict[str, Any]:
    """Validate an inventory payload against the canonical schema."""
    if not isinstance(data, dict):
        raise ValueError("Inventory JSON root must be an object with an 'agents' array")

    errors = sorted(_inventory_validator().iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        path = " -> ".join(str(part) for part in first.path) or "(root)"
        raise ValueError(f"Inventory schema validation failed at {path}: {first.message}")
    return data


def _normalize_inventory_ecosystem(ecosystem: str) -> str:
    """Map common feed aliases into the canonical inventory schema vocabulary."""
    normalized = ecosystem.strip().lower()
    if not normalized:
        return "unknown"
    return _ECOSYSTEM_ALIASES.get(normalized, normalized)


def load_inventory(source: str) -> dict:
    """Load inventory from a file path or stdin (``-``).

    Auto-detects JSON vs CSV:
    - ``.csv`` extension → CSV parser
    - stdin: first non-whitespace char ``{`` or ``[`` → JSON, else CSV
    - everything else → JSON

    Returns:
        Dictionary matching the inventory schema (``{"agents": [...]}``)

    Raises:
        FileNotFoundError: If *source* is a path that does not exist.
        ValueError: If the file is empty or has missing required columns.
    """
    if source == "-":
        return _load_from_stdin()

    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Inventory file not found: {source}")

    file_size = path.stat().st_size
    if file_size > _MAX_INVENTORY_SIZE:
        raise ValueError(f"Inventory file exceeds {_MAX_INVENTORY_SIZE // (1024 * 1024)} MB size limit: {source}")

    if path.suffix.lower() == ".csv":
        with open(path, newline="", encoding="utf-8") as fp:
            return _load_csv_inventory(fp)

    with open(path, encoding="utf-8") as fp:
        return _load_json_inventory(fp)


def _load_from_stdin() -> dict:
    """Read inventory from stdin, auto-detecting format."""
    content = sys.stdin.read(_MAX_INVENTORY_SIZE + 1)
    if len(content) > _MAX_INVENTORY_SIZE:
        raise ValueError(f"Stdin input exceeds {_MAX_INVENTORY_SIZE // (1024 * 1024)} MB size limit")
    if not content.strip():
        raise ValueError("Empty input on stdin")

    fmt = _detect_format(content)
    if fmt == "json":
        return _validate_inventory_payload(json.loads(content))

    return _load_csv_inventory(io.StringIO(content))


def _detect_format(content: str) -> str:
    """Detect whether *content* is JSON or CSV based on first non-whitespace character."""
    stripped = content.lstrip()
    if stripped and stripped[0] in ("{", "["):
        return "json"
    return "csv"


def _load_json_inventory(fp: io.TextIOBase) -> dict:  # type: ignore[override]
    """Parse JSON inventory from a file-like object."""
    return _validate_inventory_payload(json.load(fp))


def _load_csv_inventory(fp: io.TextIOBase) -> dict:  # type: ignore[override]
    """Parse CSV inventory into the standard inventory schema.

    Groups rows by ``(agent_name, server_name)`` to build the full
    ``agents[] → mcp_servers[] → packages[]`` hierarchy.
    """
    reader = csv.DictReader(fp)

    if not reader.fieldnames:
        raise ValueError("CSV file is empty or has no header row")

    # Normalise header names (strip whitespace, lowercase for matching).
    # Maps lowercase-stripped → raw fieldname as DictReader uses it.
    normalised = {h.strip().lower(): h for h in reader.fieldnames}
    missing = _CSV_REQUIRED_COLUMNS - set(normalised)
    if missing:
        raise ValueError(f"CSV missing required columns: {', '.join(sorted(missing))}")

    # Map normalised names back to actual header strings for DictReader access
    col_name = normalised["name"]
    col_version = normalised["version"]
    col_ecosystem = normalised["ecosystem"]
    col_server = normalised.get("server_name", "")
    col_agent = normalised.get("agent_name", "")
    col_env = normalised.get("env_keys", "")

    # Group rows by (agent, server)
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in reader:
        agent = (row.get(col_agent) or "").strip() or "inventory-agent"
        server = (row.get(col_server) or "").strip() or "inventory-server"
        groups[(agent, server)].append(row)

    # Build inventory structure
    agents_by_name: dict[str, dict] = {}
    for (agent_name, server_name), rows in groups.items():
        packages = []
        env: dict[str, str] = {}
        for row in rows:
            name = (row.get(col_name) or "").strip()
            version = (row.get(col_version) or "").strip()
            ecosystem = _normalize_inventory_ecosystem((row.get(col_ecosystem) or "").strip())
            if not name or not version:
                continue
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "ecosystem": ecosystem,
                }
            )
            # Parse semicolon-separated env key names (values always redacted)
            if col_env:
                for key in (row.get(col_env) or "").split(";"):
                    key = key.strip()
                    if key:
                        env[key] = "REDACTED"

        if not packages:
            continue

        server_def = {
            "name": server_name,
            "packages": packages,
            "env": env,
        }

        if agent_name not in agents_by_name:
            agents_by_name[agent_name] = {
                "name": agent_name,
                "agent_type": "custom",
                "mcp_servers": [],
            }
        agents_by_name[agent_name]["mcp_servers"].append(server_def)

    if not agents_by_name:
        raise ValueError("CSV produced no valid inventory entries (check name/version columns)")

    return _validate_inventory_payload({"agents": list(agents_by_name.values())})
