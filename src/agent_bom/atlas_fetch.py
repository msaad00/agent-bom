"""Load and refresh the MITRE ATLAS catalog.

Mirrors the offline-first pattern from :mod:`agent_bom.mitre_fetch`:

- agent-bom ships a normalized MITRE ATLAS catalog in-repo
  (`src/agent_bom/data/mitre_atlas_catalog.json`).
- Scans read that bundled catalog by default; the curated 65-technique tag
  surface in :mod:`agent_bom.atlas` remains the authoritative tagging map.
- Operators can refresh from upstream via ``sync_catalog()``; the bundled
  catalog is the canonical reference for "X of N upstream techniques covered"
  rollups in dashboards and SARIF metadata.

The scan hot path never requires a live network fetch unless the operator
explicitly enables refresh mode.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Canonical upstream YAML maintained by mitre-atlas/atlas-data.
_ATLAS_YAML_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"

_CATALOG_SCHEMA_VERSION = 1
_FETCH_TIMEOUT = 60
_BUNDLED_CATALOG_PATH = Path(__file__).with_name("data") / "mitre_atlas_catalog.json"
_DEFAULT_SYNC_PATH = Path.home() / ".agent-bom" / "catalogs" / "mitre_atlas_catalog.json"
_ALLOWED_CATALOG_MODES = {"auto", "bundled", "synced", "refresh"}


def _sync_catalog_path() -> Path:
    override = os.environ.get("AGENT_BOM_ATLAS_CATALOG_PATH", "").strip()
    return Path(override).expanduser() if override else _DEFAULT_SYNC_PATH


def _catalog_mode() -> str:
    raw = os.environ.get("AGENT_BOM_ATLAS_CATALOG_MODE", "auto").strip().lower()
    return raw if raw in _ALLOWED_CATALOG_MODES else "auto"


def _empty_catalog(source: str = "unavailable") -> dict:
    return {
        "schema_version": _CATALOG_SCHEMA_VERSION,
        "catalog_id": "mitre_atlas",
        "catalog_type": "mitre_atlas",
        "source": source,
        "atlas_version": "unavailable",
        "updated_at": "",
        "fetched_at": 0,
        "normalized_sha256": "",
        "sources": {},
        "techniques": {},
        "tactics": {},
    }


def _catalog_metadata(catalog: dict) -> dict:
    return {
        "schema_version": catalog.get("schema_version", _CATALOG_SCHEMA_VERSION),
        "catalog_id": catalog.get("catalog_id", "mitre_atlas"),
        "catalog_type": catalog.get("catalog_type", "mitre_atlas"),
        "source": catalog.get("source", "unknown"),
        "atlas_version": catalog.get("atlas_version", "unknown"),
        "updated_at": catalog.get("updated_at", ""),
        "fetched_at": catalog.get("fetched_at", 0),
        "normalized_sha256": catalog.get("normalized_sha256", ""),
        "sources": catalog.get("sources", {}),
        "technique_count": len(catalog.get("techniques", {})),
        "tactic_count": len(catalog.get("tactics", {})),
        "path": catalog.get("_path", ""),
    }


def get_catalog_metadata() -> dict:
    """Return metadata for the active MITRE ATLAS catalog."""
    return _catalog_metadata(build_catalog())


def _load_catalog_file(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read MITRE ATLAS catalog %s: %s", path, exc)
        return None

    if not isinstance(data.get("techniques"), dict):
        logger.warning("Ignoring invalid MITRE ATLAS catalog at %s: missing techniques", path)
        return None

    data.setdefault("schema_version", _CATALOG_SCHEMA_VERSION)
    data.setdefault("catalog_id", "mitre_atlas")
    data.setdefault("catalog_type", "mitre_atlas")
    data.setdefault("source", "synced" if path == _sync_catalog_path() else "bundled")
    data.setdefault("atlas_version", data.get("attack_version", "unknown"))
    data.setdefault("updated_at", "")
    data.setdefault("fetched_at", 0)
    data.setdefault("normalized_sha256", "")
    data.setdefault("sources", {})
    data.setdefault("tactics", {})
    data["_path"] = str(path)
    return data


def _load_bundled_catalog() -> dict:
    catalog = _load_catalog_file(_BUNDLED_CATALOG_PATH)
    return catalog or _empty_catalog("bundled")


def _load_synced_catalog() -> Optional[dict]:
    return _load_catalog_file(_sync_catalog_path())


def _fetch_text(url: str) -> Optional[str]:
    try:
        with httpx.Client(timeout=_FETCH_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.text
    except Exception as exc:  # pragma: no cover — network paths exercised by integration tests
        logger.warning("MITRE ATLAS fetch failed (%s): %s", url, exc)
        return None


def _parse_atlas_yaml(yaml_text: str) -> tuple[str, dict[str, dict], dict[str, dict]]:
    """Parse the ATLAS.yaml bundle into a normalized technique + tactic map."""
    import yaml  # local import — yaml is a heavy dependency on cold-start

    bundle = yaml.safe_load(yaml_text)
    if not isinstance(bundle, dict):
        return "unknown", {}, {}

    version = str(bundle.get("version") or "unknown")
    matrices = bundle.get("matrices") or []
    if not matrices:
        return version, {}, {}

    matrix = matrices[0]
    raw_tactics = matrix.get("tactics") or []
    raw_techniques = matrix.get("techniques") or []

    tactics: dict[str, dict] = {}
    for tac in raw_tactics:
        tac_id = tac.get("id")
        if not tac_id or not isinstance(tac_id, str):
            continue
        tactics[tac_id] = {
            "name": tac.get("name", tac_id),
            "description": (tac.get("description") or "")[:300],
        }

    techniques: dict[str, dict] = {}
    for tech in raw_techniques:
        tech_id = tech.get("id")
        if not tech_id or not isinstance(tech_id, str):
            continue
        if not tech_id.startswith("AML.T"):
            continue
        attck_ref = tech.get("ATT&CK-reference") or {}
        techniques[tech_id] = {
            "name": tech.get("name", tech_id),
            "tactics": list(tech.get("tactics") or []),
            "description": (tech.get("description") or "")[:300],
            "attck_reference": attck_ref.get("id", "") if isinstance(attck_ref, dict) else "",
            "is_subtechnique": "." in tech_id.split("AML.T", 1)[1] if "AML.T" in tech_id else False,
        }

    return version, techniques, tactics


def _normalize_catalog(
    *,
    version: str,
    techniques: dict[str, dict],
    tactics: dict[str, dict],
    source: str,
    fetched_at: float,
    source_hashes: dict[str, dict[str, str]],
) -> dict:
    core = {
        "techniques": techniques,
        "tactics": tactics,
        "atlas_version": version,
    }
    normalized_sha256 = hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "schema_version": _CATALOG_SCHEMA_VERSION,
        "catalog_id": "mitre_atlas",
        "catalog_type": "mitre_atlas",
        "source": source,
        "atlas_version": version,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "fetched_at": fetched_at,
        "normalized_sha256": normalized_sha256,
        "sources": source_hashes,
        **core,
    }


def _write_catalog(catalog: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")


def sync_catalog(output_path: Path | None = None) -> dict:
    """Fetch and normalize the upstream MITRE ATLAS catalog.

    Writes the last-known-good synced catalog to ``~/.agent-bom/catalogs`` by
    default and returns the normalized catalog. If refresh fails, falls back to
    the existing synced catalog, then the bundled catalog.
    """
    yaml_text = _fetch_text(_ATLAS_YAML_URL)

    if not yaml_text:
        fallback = _load_synced_catalog() or _load_bundled_catalog()
        logger.warning("MITRE ATLAS sync failed; using last-known-good catalog from %s", fallback.get("source", "unknown"))
        return fallback

    version, techniques, tactics = _parse_atlas_yaml(yaml_text)

    fetched_at = time.time()
    source_hashes = {
        "atlas_yaml": {
            "url": _ATLAS_YAML_URL,
            "sha256": hashlib.sha256(yaml_text.encode()).hexdigest(),
        },
    }
    catalog = _normalize_catalog(
        version=version,
        techniques=techniques,
        tactics=tactics,
        source="synced",
        fetched_at=fetched_at,
        source_hashes=source_hashes,
    )

    target = output_path or _sync_catalog_path()
    _write_catalog(catalog, target)
    catalog["_path"] = str(target)
    return catalog


def build_catalog(force_refresh: bool = False) -> dict:
    """Return the active MITRE ATLAS catalog without forcing network fetches by default."""
    mode = _catalog_mode()

    if force_refresh or mode == "refresh":
        refreshed = sync_catalog()
        if refreshed.get("techniques"):
            return refreshed

    bundled = _load_bundled_catalog()
    synced = _load_synced_catalog()

    if mode == "bundled":
        return bundled or synced or _empty_catalog("bundled")
    if mode == "synced":
        return synced or bundled or _empty_catalog("synced")

    return synced or bundled or _empty_catalog("bundled")


def load_catalog() -> dict:
    """Public alias used by :mod:`agent_bom.atlas` to read the bundled JSON."""
    return build_catalog()


def get_techniques() -> dict[str, dict]:
    return build_catalog().get("techniques", {})


def get_tactics() -> dict[str, dict]:
    return build_catalog().get("tactics", {})


def get_atlas_version() -> str:
    return build_catalog().get("atlas_version", "unknown")
