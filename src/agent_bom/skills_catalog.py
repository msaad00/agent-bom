"""Persistent catalog of previously seen skill bundles."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_SKILLS_CATALOG = Path.home() / ".agent-bom" / "skills" / "catalog.json"


def skills_catalog_path(path: str | Path | None = None) -> Path:
    """Return the catalog path, creating its parent directory."""
    resolved = Path(path) if path is not None else DEFAULT_SKILLS_CATALOG
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def load_skills_catalog(path: str | Path | None = None) -> dict[str, object]:
    """Load the persistent skills catalog or return an empty one."""
    catalog_path = skills_catalog_path(path)
    if not catalog_path.exists():
        return {"version": 1, "entries": {}}
    data = json.loads(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {"version": 1, "entries": {}}
    entries = data.get("entries")
    if not isinstance(entries, dict):
        data["entries"] = {}
    data.setdefault("version", 1)
    return data


def save_skills_catalog(data: dict[str, object], path: str | Path | None = None) -> Path:
    """Write the persistent skills catalog."""
    catalog_path = skills_catalog_path(path)
    catalog_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return catalog_path


def catalog_scan_timestamp() -> str:
    """Return an ISO provenance timestamp for catalog updates.

    This value is wall-clock and therefore NON-deterministic across runs. It
    must only ever populate clearly-labelled provenance/metadata fields (e.g.
    a ``scanned_at`` block) — never the deterministic findings payload, so that
    two scans of the same skill produce byte-identical findings.
    """
    return datetime.now(timezone.utc).isoformat()
