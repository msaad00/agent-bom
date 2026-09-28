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
import difflib
import io
import json
import logging
import sys
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any

from agent_bom.asset_provenance import sanitize_discovery_provenance
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType
from agent_bom.security import sanitize_env_vars, sanitize_sensitive_payload

logger = logging.getLogger(__name__)

# Required CSV columns for package scanning.
_CSV_REQUIRED_COLUMNS = frozenset({"name", "version", "ecosystem"})

# Size guard to prevent OOM on malicious/huge inputs.
_MAX_INVENTORY_SIZE = 100 * 1024 * 1024  # 100 MB
_DEFAULT_INVENTORY_SCHEMA_VERSION = "1"
_SUPPORTED_INVENTORY_SCHEMA_VERSIONS = frozenset({_DEFAULT_INVENTORY_SCHEMA_VERSION})
_ECOSYSTEM_ALIASES = {
    "pip": "pypi",
    "python": "pypi",
    "node": "npm",
    "golang": "go",
    "crates": "cargo",
    "dotnet": "nuget",
}


class InventoryValidationError(ValueError):
    """Raised when inventory schema validation fails with operator guidance."""


def _inventory_schema_path(version: str = _DEFAULT_INVENTORY_SCHEMA_VERSION) -> Path | None:
    """Return the inventory schema path from source or installed package data."""
    if version not in _SUPPORTED_INVENTORY_SCHEMA_VERSIONS:
        return None
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


@lru_cache(maxsize=len(_SUPPORTED_INVENTORY_SCHEMA_VERSIONS))
def _inventory_validator(version: str = _DEFAULT_INVENTORY_SCHEMA_VERSION):
    """Build and cache the inventory JSON Schema validator for *version*."""
    import jsonschema

    schema_path = _inventory_schema_path(version)
    if not schema_path or not schema_path.exists():
        raise RuntimeError(f"Inventory schema file not found for schema_version {version!r}")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def _coerce_inventory_schema_version(value: Any) -> str:
    if value is None:
        return _DEFAULT_INVENTORY_SCHEMA_VERSION
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Inventory schema_version must be a non-empty string")
    version = value.strip()
    if version not in _SUPPORTED_INVENTORY_SCHEMA_VERSIONS:
        supported = ", ".join(sorted(_SUPPORTED_INVENTORY_SCHEMA_VERSIONS))
        raise ValueError(f"Unsupported inventory schema_version {version!r}; supported versions: {supported}")
    return version


def _inventory_payload_and_version(data: Any) -> tuple[dict[str, Any], str]:
    if not isinstance(data, dict):
        raise ValueError("Inventory JSON root must be an object with an 'agents' array")

    if "inventory_snapshot" in data and "document_type" in data:
        snapshot = data.get("inventory_snapshot")
        if not isinstance(snapshot, dict):
            raise ValueError("Inventory snapshot in scan report must be an object")
        data = snapshot

    version = _coerce_inventory_schema_version(data.get("schema_version"))
    return data, version


def _validate_inventory_payload(data: Any) -> dict[str, Any]:
    """Validate an inventory payload against the canonical schema."""
    data, version = _inventory_payload_and_version(data)

    errors = sorted(_inventory_validator(version).iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        path = " -> ".join(str(part) for part in first.path) or "(root)"
        suggestion = _inventory_error_suggestion(first)
        details = f"{first.message}{suggestion}"
        raise InventoryValidationError(f"Inventory schema validation failed at {path}: {details}")
    return data


def _inventory_error_suggestion(error: Any) -> str:
    """Return a short "did you mean" hint for common schema mistakes."""
    if error.validator == "additionalProperties" and isinstance(error.instance, dict):
        allowed = set((error.schema or {}).get("properties", {}).keys())
        unexpected = sorted(set(error.instance.keys()) - allowed)
        hint = _closest_name_hint(unexpected, allowed)
        if hint:
            return hint

    if error.validator == "required" and isinstance(error.instance, dict):
        required = set(error.validator_value or [])
        missing = sorted(required - set(error.instance.keys()))
        hint = _closest_name_hint(missing, error.instance.keys(), reverse=True)
        if hint:
            return hint

    if error.validator == "enum" and isinstance(error.instance, str):
        allowed_values = [str(value) for value in error.validator_value or []]
        match = difflib.get_close_matches(error.instance, allowed_values, n=1, cutoff=0.72)
        if match:
            return f" Did you mean {match[0]!r}?"

    return ""


def _closest_name_hint(candidates: list[str], choices: Any, *, reverse: bool = False) -> str:
    choice_list = [str(choice) for choice in choices]
    for candidate in candidates:
        match = difflib.get_close_matches(str(candidate), choice_list, n=1, cutoff=0.72)
        if match:
            if reverse:
                return f" Did you mean {candidate!r} instead of {match[0]!r}?"
            return f" Did you mean {match[0]!r} instead of {candidate!r}?"
    return ""


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

    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        with open(path, encoding="utf-8") as fp:
            return _load_ndjson_inventory(fp)

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
        try:
            return _validate_inventory_payload(json.loads(content))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Inventory JSON error in stdin: line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc

    return _load_csv_inventory(io.StringIO(content))


def _detect_format(content: str) -> str:
    """Detect whether *content* is JSON or CSV based on first non-whitespace character."""
    stripped = content.lstrip()
    if stripped and stripped[0] in ("{", "["):
        return "json"
    return "csv"


def _load_json_inventory(fp: io.TextIOBase) -> dict:  # type: ignore[override]
    """Parse JSON inventory from a file-like object."""
    try:
        return _validate_inventory_payload(json.load(fp))
    except json.JSONDecodeError as exc:
        source = getattr(fp, "name", "inventory file")
        raise ValueError(f"Inventory JSON error in {source}: line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc


def _load_ndjson_inventory(fp: io.TextIOBase) -> dict:
    """Parse line-delimited inventory and validate each agent chunk.

    The first non-empty line may be a metadata object with ``schema_version``,
    ``source``, ``generated_at``, or ``discovery_provenance``. Later lines can
    be either full inventory objects with ``agents`` or individual agent
    objects. This keeps fleet-scale pushed inventory parseable without loading
    one monolithic JSON document before validation.
    """
    source = getattr(fp, "name", "inventory file")
    version = _DEFAULT_INVENTORY_SCHEMA_VERSION
    metadata: dict[str, Any] = {}
    metadata_keys = {"schema_version", "source", "generated_at", "discovery_provenance"}
    agents: list[dict[str, Any]] = []
    saw_payload = False

    for line_no, raw_line in enumerate(fp, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Inventory NDJSON error in {source}: line {line_no}, column {exc.colno}: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"Inventory NDJSON error in {source}: line {line_no}: record must be an object")

        if not saw_payload and "agents" not in record and "name" not in record and set(record).issubset(metadata_keys):
            version = _coerce_inventory_schema_version(record.get("schema_version"))
            metadata = {key: record[key] for key in metadata_keys if key in record}
            metadata["schema_version"] = version
            continue

        saw_payload = True
        if "agents" in record:
            chunk, chunk_version = _inventory_payload_and_version(record)
            if chunk_version != version:
                raise ValueError(
                    f"Inventory NDJSON error in {source}: line {line_no}: mixed schema_version {chunk_version!r} does not match {version!r}"
                )
            chunk_agents = chunk.get("agents")
            if not isinstance(chunk_agents, list):
                raise ValueError(f"Inventory NDJSON error in {source}: line {line_no}: agents must be an array")
        else:
            chunk_agents = [record]

        for agent in chunk_agents:
            try:
                _validate_inventory_payload({"schema_version": version, "agents": [agent]})
            except ValueError as exc:
                raise ValueError(f"Inventory NDJSON error in {source}: line {line_no}: {exc}") from exc
            agents.append(agent)

    if not agents:
        raise ValueError(f"Inventory NDJSON in {source} produced no agent records")

    payload = dict(metadata)
    payload.setdefault("schema_version", version)
    payload["agents"] = agents
    return _validate_inventory_payload(payload)


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
    skipped_empty_identity_rows = 0
    for (agent_name, server_name), rows in groups.items():
        packages = []
        env: dict[str, str] = {}
        for row in rows:
            name = (row.get(col_name) or "").strip()
            version = (row.get(col_version) or "").strip()
            ecosystem = _normalize_inventory_ecosystem((row.get(col_ecosystem) or "").strip())
            if not name or not version:
                skipped_empty_identity_rows += 1
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

    if skipped_empty_identity_rows:
        logger.warning(
            "Skipped %s CSV inventory row(s) with empty package name or version",
            skipped_empty_identity_rows,
        )

    return _validate_inventory_payload({"agents": list(agents_by_name.values())})


def coerce_agent_type_for_inventory(raw_value: object, *, agent_name: str) -> AgentType:
    """Map unknown pushed-inventory agent types to custom without aborting scans."""
    value = str(raw_value or "custom").strip() or "custom"
    try:
        return AgentType(value)
    except ValueError:
        logger.warning("Unknown inventory agent_type %r for %s; treating as custom", value, agent_name)
        return AgentType.CUSTOM


def _inventory_tools(server_data: dict) -> list[MCPTool]:
    # Pre-populated tools, e.g. from Snowflake/cloud inventory.
    tools = []
    for tool_data in server_data.get("tools", []):
        if isinstance(tool_data, str):
            tools.append(MCPTool(name=tool_data, description=""))
        elif isinstance(tool_data, dict):
            tools.append(
                MCPTool(
                    name=tool_data.get("name", ""),
                    description=tool_data.get("description", ""),
                    input_schema=tool_data.get("input_schema"),
                )
            )
    return tools


def _inventory_packages(server_data: dict, package_provenance: dict[str, Any] | None) -> list[Package]:
    # Pre-known packages, e.g. from a cloud asset scan.
    packages = []
    for pkg_data in server_data.get("packages", []):
        if isinstance(pkg_data, str):
            if "@" in pkg_data:
                name, version = pkg_data.rsplit("@", 1)
            else:
                name, version = pkg_data, "unknown"
            packages.append(Package(name=name, version=version, ecosystem="unknown", discovery_provenance=package_provenance))
        elif isinstance(pkg_data, dict):
            packages.append(
                Package(
                    name=pkg_data.get("name", ""),
                    version=pkg_data.get("version", "unknown"),
                    ecosystem=pkg_data.get("ecosystem", "unknown"),
                    purl=pkg_data.get("purl"),
                    discovery_provenance=sanitize_discovery_provenance(
                        pkg_data.get("discovery_provenance"),
                        defaults=package_provenance,
                    ),
                )
            )
    return packages


def _inventory_server(server_data: dict, agent_data: dict, agent_provenance: dict[str, Any] | None) -> MCPServer:
    package_provenance = sanitize_discovery_provenance(server_data.get("discovery_provenance"), defaults=agent_provenance)
    return MCPServer(
        name=server_data.get("name", ""),
        command=server_data.get("command", ""),
        args=server_data.get("args", []),
        env=sanitize_env_vars(server_data.get("env", {})),
        transport=TransportType(server_data.get("transport", "stdio")),
        url=server_data.get("url"),
        config_path=agent_data.get("config_path"),
        working_dir=server_data.get("working_dir"),
        mcp_version=server_data.get("mcp_version"),
        security_blocked=bool(server_data.get("security_blocked", False)),
        security_warnings=list(server_data.get("security_warnings", []) or []),
        security_intelligence=[
            sanitize_security_intelligence_entry(item)
            for item in (server_data.get("security_intelligence", []) or [])
            if isinstance(item, dict)
        ],
        discovery_provenance=package_provenance,
        tools=_inventory_tools(server_data),
        packages=_inventory_packages(server_data, package_provenance),
    )


def _inventory_agent(agent_data: dict, inventory_data: dict, inventory_provenance: dict[str, Any] | None, source_path: str) -> Agent:
    agent_provenance = sanitize_discovery_provenance(
        agent_data.get("discovery_provenance"),
        defaults={**(inventory_provenance or {}), "source": agent_data.get("source", inventory_data.get("source"))},
    )
    mcp_servers = [_inventory_server(server_data, agent_data, agent_provenance) for server_data in agent_data.get("mcp_servers", [])]
    sanitized_metadata = {}
    if isinstance(agent_data.get("metadata"), dict):
        metadata_payload = sanitize_sensitive_payload(agent_data.get("metadata", {}))
        sanitized_metadata = metadata_payload if isinstance(metadata_payload, dict) else {}
    return Agent(
        name=agent_data.get("name", "unknown"),
        agent_type=coerce_agent_type_for_inventory(
            agent_data.get("agent_type", agent_data.get("type", "custom")),
            agent_name=agent_data.get("name", "unknown"),
        ),
        config_path=agent_data.get("config_path", source_path),
        mcp_servers=mcp_servers,
        version=agent_data.get("version"),
        source=agent_data.get("source", inventory_data.get("source")),
        source_id=agent_data.get("source_id"),
        device_fingerprint=agent_data.get("device_fingerprint"),
        metadata=sanitized_metadata,
        discovered_at=agent_data.get("discovered_at") or agent_data.get("first_seen") or "",
        last_seen=agent_data.get("last_seen") or agent_data.get("last_seen_at"),
        discovery_provenance=agent_provenance,
    )


def build_agents_from_inventory(inventory_data: dict, source_path: str) -> list[Agent]:
    """Build Agent objects from a parsed inventory dict (JSON, NDJSON or CSV)."""
    inventory_provenance = sanitize_discovery_provenance(
        inventory_data.get("discovery_provenance"),
        defaults={
            "source_type": "operator_pushed_inventory",
            "observed_via": ["operator_inventory"],
            "source": inventory_data.get("source"),
            "collector": "inventory",
            "confidence": "high",
        },
    )
    return [
        _inventory_agent(agent_data, inventory_data, inventory_provenance, source_path) for agent_data in inventory_data.get("agents", [])
    ]
