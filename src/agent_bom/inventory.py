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

logger = logging.getLogger(__name__)

# Required CSV columns for package scanning.
_CSV_REQUIRED_COLUMNS = frozenset({"name", "version", "ecosystem"})


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

    from pathlib import Path

    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Inventory file not found: {source}")

    if path.suffix.lower() == ".csv":
        with open(path, newline="", encoding="utf-8") as fp:
            return _load_csv_inventory(fp)

    with open(path, encoding="utf-8") as fp:
        return _load_json_inventory(fp)


def _load_from_stdin() -> dict:
    """Read inventory from stdin, auto-detecting format."""
    content = sys.stdin.read()
    if not content.strip():
        raise ValueError("Empty input on stdin")

    fmt = _detect_format(content)
    if fmt == "json":
        return json.loads(content)

    return _load_csv_inventory(io.StringIO(content))


def _detect_format(content: str) -> str:
    """Detect whether *content* is JSON or CSV based on first non-whitespace character."""
    stripped = content.lstrip()
    if stripped and stripped[0] in ("{", "["):
        return "json"
    return "csv"


def _load_json_inventory(fp: io.TextIOBase) -> dict:  # type: ignore[override]
    """Parse JSON inventory from a file-like object."""
    return json.load(fp)


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
            ecosystem = (row.get(col_ecosystem) or "").strip()
            if not name or not version:
                continue
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "ecosystem": ecosystem or "unknown",
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

    return {"agents": list(agents_by_name.values())}
