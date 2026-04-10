"""Load and refresh MITRE ATT&CK Enterprise + CAPEC catalogs.

Default behavior is deterministic and offline-friendly:

- agent-bom ships a normalized MITRE ATT&CK Enterprise + CAPEC catalog in-repo
- scans read that bundled catalog by default
- operators can explicitly sync a fresher upstream catalog out of band
- long-lived connected deployments can opt into runtime refresh mode

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

_ENTERPRISE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
_CAPEC_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

TOP_TACTIC_PHASE_NAMES = frozenset(
    [
        "initial-access",
        "execution",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "collection",
        "exfiltration",
        "command-and-control",
        "impact",
    ]
)

_CATALOG_SCHEMA_VERSION = 1
_FETCH_TIMEOUT = 60
_BUNDLED_CATALOG_PATH = Path(__file__).with_name("data") / "mitre_attack_catalog.json"
_DEFAULT_SYNC_PATH = Path.home() / ".agent-bom" / "catalogs" / "mitre_attack_catalog.json"
_ALLOWED_CATALOG_MODES = {"auto", "bundled", "synced", "refresh"}


def _sync_catalog_path() -> Path:
    override = os.environ.get("AGENT_BOM_MITRE_CATALOG_PATH", "").strip()
    return Path(override).expanduser() if override else _DEFAULT_SYNC_PATH


def _catalog_mode() -> str:
    raw = os.environ.get("AGENT_BOM_MITRE_CATALOG_MODE", "auto").strip().lower()
    return raw if raw in _ALLOWED_CATALOG_MODES else "auto"


def _empty_catalog(source: str = "unavailable") -> dict:
    return {
        "schema_version": _CATALOG_SCHEMA_VERSION,
        "catalog_id": "mitre_attack_enterprise_capec",
        "catalog_type": "mitre_attack",
        "source": source,
        "attack_version": "unavailable",
        "updated_at": "",
        "fetched_at": 0,
        "normalized_sha256": "",
        "sources": {},
        "techniques": {},
        "cwe_to_attack": {},
    }


def _catalog_metadata(catalog: dict) -> dict:
    return {
        "schema_version": catalog.get("schema_version", _CATALOG_SCHEMA_VERSION),
        "catalog_id": catalog.get("catalog_id", "mitre_attack_enterprise_capec"),
        "catalog_type": catalog.get("catalog_type", "mitre_attack"),
        "source": catalog.get("source", "unknown"),
        "attack_version": catalog.get("attack_version", "unknown"),
        "updated_at": catalog.get("updated_at", ""),
        "fetched_at": catalog.get("fetched_at", 0),
        "normalized_sha256": catalog.get("normalized_sha256", ""),
        "sources": catalog.get("sources", {}),
        "technique_count": len(catalog.get("techniques", {})),
        "cwe_mapping_count": len(catalog.get("cwe_to_attack", {})),
        "path": catalog.get("_path", ""),
    }


def get_catalog_metadata() -> dict:
    """Return metadata for the active MITRE catalog."""
    return _catalog_metadata(build_catalog())


def _load_catalog_file(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read MITRE catalog %s: %s", path, exc)
        return None

    if not isinstance(data.get("techniques"), dict) or not isinstance(data.get("cwe_to_attack"), dict):
        logger.warning("Ignoring invalid MITRE catalog at %s: missing techniques or cwe_to_attack", path)
        return None

    data.setdefault("schema_version", _CATALOG_SCHEMA_VERSION)
    data.setdefault("catalog_id", "mitre_attack_enterprise_capec")
    data.setdefault("catalog_type", "mitre_attack")
    data.setdefault("source", "synced" if path == _sync_catalog_path() else "bundled")
    data.setdefault("updated_at", "")
    data.setdefault("fetched_at", 0)
    data.setdefault("normalized_sha256", "")
    data.setdefault("sources", {})
    data["_path"] = str(path)
    return data


def _load_bundled_catalog() -> dict:
    catalog = _load_catalog_file(_BUNDLED_CATALOG_PATH)
    return catalog or _empty_catalog("bundled")


def _load_synced_catalog() -> Optional[dict]:
    return _load_catalog_file(_sync_catalog_path())


def _fetch_json(url: str) -> Optional[dict]:
    try:
        with httpx.Client(timeout=_FETCH_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.warning("MITRE fetch failed (%s): %s", url, exc)
        return None


def _fetch_text(url: str) -> Optional[str]:
    try:
        with httpx.Client(timeout=_FETCH_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.text
    except Exception as exc:
        logger.warning("MITRE fetch failed (%s): %s", url, exc)
        return None


def _parse_attack_stix(stix_bundle: dict) -> tuple[str, dict[str, dict]]:
    version = "unknown"
    fallback_version = "unknown"
    techniques: dict[str, dict] = {}

    for obj in stix_bundle.get("objects", []):
        obj_type = obj.get("type", "")
        if obj_type == "x-mitre-collection":
            version = obj.get("x_mitre_version") or obj.get("name", "unknown")
        elif obj_type == "x-mitre-matrix" and fallback_version == "unknown":
            modified = (obj.get("modified") or "").split("T", 1)[0]
            spec_version = obj.get("x_mitre_attack_spec_version")
            if modified and spec_version:
                fallback_version = f"snapshot {modified} (spec {spec_version})"
            elif modified:
                fallback_version = f"snapshot {modified}"
            elif spec_version:
                fallback_version = f"spec {spec_version}"

        if obj_type != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        ext_refs = obj.get("external_references", [])
        capec_refs = sorted(
            {ref.get("external_id", "").upper() for ref in ext_refs if ref.get("source_name") == "capec" and ref.get("external_id")}
        )
        tech_id = next((r.get("external_id", "") for r in ext_refs if r.get("source_name") == "mitre-attack"), "")
        if not tech_id or not tech_id.startswith("T"):
            continue

        tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"]
        if not any(t in TOP_TACTIC_PHASE_NAMES for t in tactics):
            continue

        techniques[tech_id] = {
            "name": obj.get("name", tech_id),
            "tactics": tactics,
            "description": (obj.get("description") or "")[:200],
            "platforms": obj.get("x_mitre_platforms", []),
            "capec_refs": capec_refs,
        }

    if version == "unknown":
        version = fallback_version
    return version, techniques


def _parse_capec_stix(capec_bundle: dict, attack_techniques: dict[str, dict]) -> dict[str, list[str]]:
    objects = capec_bundle.get("objects", [])
    capec_stix_to_external: dict[str, str] = {}
    capec_to_cwes: dict[str, set[str]] = {}
    capec_to_attack: dict[str, set[str]] = {}
    weakness_map: dict[str, str] = {}
    embedded_attack_refs: dict[str, set[str]] = {}

    def _normalize_cwe(raw_id: str) -> str:
        value = (raw_id or "").strip().upper()
        if not value:
            return ""
        return value if value.startswith("CWE-") else f"CWE-{value}"

    for obj in objects:
        obj_type = obj.get("type")
        if obj_type == "weakness":
            stix_id = obj.get("id", "")
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "cwe":
                    cwe_id = _normalize_cwe(ref.get("external_id", ""))
                    if cwe_id:
                        weakness_map[stix_id] = cwe_id
        elif obj_type == "attack-pattern":
            stix_id = obj.get("id", "")
            ext_refs = obj.get("external_references", [])
            capec_ids = {
                ref.get("external_id", "").upper() for ref in ext_refs if ref.get("source_name") == "capec" and ref.get("external_id")
            }
            cwe_ids = {_normalize_cwe(ref.get("external_id", "")) for ref in ext_refs if ref.get("source_name") == "cwe"}
            cwe_ids.discard("")
            attack_ids = {
                ref.get("external_id", "").upper()
                for ref in ext_refs
                if ref.get("source_name") in {"ATTACK", "mitre-attack"} and ref.get("external_id", "").startswith("T")
            }
            attack_ids = {tech for tech in attack_ids if tech in attack_techniques}

            if capec_ids:
                capec_id = sorted(capec_ids)[0]
                capec_stix_to_external[stix_id] = capec_id
                if cwe_ids:
                    capec_to_cwes.setdefault(capec_id, set()).update(cwe_ids)
                if attack_ids:
                    capec_to_attack.setdefault(capec_id, set()).update(attack_ids)
            elif attack_ids:
                embedded_attack_refs[stix_id] = attack_ids

    for tech_id, metadata in attack_techniques.items():
        for capec_id in metadata.get("capec_refs", []) or []:
            capec_to_attack.setdefault(capec_id.upper(), set()).add(tech_id)

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        source_ref = obj.get("source_ref", "")
        target_ref = obj.get("target_ref", "")
        capec_id = capec_stix_to_external.get(source_ref)
        if not capec_id:
            continue
        if target_ref in weakness_map:
            capec_to_cwes.setdefault(capec_id, set()).add(weakness_map[target_ref])
        if target_ref in embedded_attack_refs:
            capec_to_attack.setdefault(capec_id, set()).update(embedded_attack_refs[target_ref])

    cwe_to_attack: dict[str, list[str]] = {}
    for capec_id, cwe_ids in capec_to_cwes.items():
        techniques = sorted(capec_to_attack.get(capec_id, set()))
        if not techniques:
            continue
        for cwe_id in cwe_ids:
            existing = set(cwe_to_attack.get(cwe_id, []))
            existing.update(techniques)
            cwe_to_attack[cwe_id] = sorted(existing)
    return cwe_to_attack


def _normalize_catalog(
    *,
    version: str,
    techniques: dict[str, dict],
    cwe_to_attack: dict[str, list[str]],
    source: str,
    fetched_at: float,
    source_hashes: dict[str, dict[str, str]],
) -> dict:
    core = {
        "techniques": techniques,
        "cwe_to_attack": cwe_to_attack,
        "attack_version": version,
    }
    normalized_sha256 = hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "schema_version": _CATALOG_SCHEMA_VERSION,
        "catalog_id": "mitre_attack_enterprise_capec",
        "catalog_type": "mitre_attack",
        "source": source,
        "attack_version": version,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "fetched_at": fetched_at,
        "normalized_sha256": normalized_sha256,
        "sources": source_hashes,
        **core,
    }


def _write_catalog(catalog: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(catalog, separators=(",", ":")))


def sync_catalog(output_path: Path | None = None) -> dict:
    """Fetch and normalize the upstream MITRE ATT&CK + CAPEC catalog.

    Writes the last-known-good synced catalog to ``~/.agent-bom/catalogs`` by
    default and returns the normalized catalog. If refresh fails, falls back to
    the existing synced catalog, then the bundled catalog.
    """
    attack_text = _fetch_text(_ENTERPRISE_STIX_URL)
    capec_text = _fetch_text(_CAPEC_STIX_URL)

    if not attack_text or not capec_text:
        fallback = _load_synced_catalog() or _load_bundled_catalog()
        logger.warning("MITRE sync failed; using last-known-good catalog from %s", fallback.get("source", "unknown"))
        return fallback

    attack_bundle = json.loads(attack_text)
    capec_bundle = json.loads(capec_text)
    version, techniques = _parse_attack_stix(attack_bundle)
    cwe_to_attack = _parse_capec_stix(capec_bundle, techniques)

    fetched_at = time.time()
    source_hashes = {
        "enterprise_attack": {
            "url": _ENTERPRISE_STIX_URL,
            "sha256": hashlib.sha256(attack_text.encode()).hexdigest(),
        },
        "capec": {
            "url": _CAPEC_STIX_URL,
            "sha256": hashlib.sha256(capec_text.encode()).hexdigest(),
        },
    }
    catalog = _normalize_catalog(
        version=version,
        techniques=techniques,
        cwe_to_attack=cwe_to_attack,
        source="synced",
        fetched_at=fetched_at,
        source_hashes=source_hashes,
    )

    target = output_path or _sync_catalog_path()
    _write_catalog(catalog, target)
    catalog["_path"] = str(target)
    return catalog


def build_catalog(force_refresh: bool = False) -> dict:
    """Return the active MITRE catalog without forcing network fetches by default."""
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

    # auto: explicit sync opt-in via local synced catalog, otherwise bundled
    return synced or bundled or _empty_catalog("bundled")


def get_techniques() -> dict[str, dict]:
    return build_catalog().get("techniques", {})


def get_cwe_to_attack() -> dict[str, list[str]]:
    return build_catalog().get("cwe_to_attack", {})


def get_attack_version() -> str:
    return build_catalog().get("attack_version", "unknown")
