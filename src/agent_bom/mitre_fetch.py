"""Fetch and cache MITRE ATT&CK Enterprise technique data from official sources.

Data sources (all public, no auth required):

- **ATT&CK STIX data** — https://github.com/mitre/cti (official MITRE GitHub)
  Published as STIX 2.0 bundles.  We fetch enterprise-attack.json and
  extract only the techniques that belong to the top-10 relevant tactics.

- **CAPEC STIX data** — same GitHub repo (capec/2.1)
  Provides the official CWE → CAPEC → ATT&CK technique bridge.  We parse
  the STIX relationship objects to derive an evidence-based CWE mapping.

Cache TTL: 30 days (``AGENT_BOM_MITRE_CACHE_TTL`` env var, in seconds).
Cache path: ``~/.cache/agent-bom/mitre-attack-catalog.json``.

No technique IDs, names, or mappings are hardcoded in agent-bom source
code.  Everything comes from MITRE's published data.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ─── Official MITRE data URLs (STIX 2.0, public, no auth) ────────────────────

_ENTERPRISE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

_CAPEC_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

# ─── Top-10 enterprise tactics most relevant to AI agent infrastructure ───────
#
# These are the *tactic* short-names as used in MITRE ATT&CK STIX objects
# (``kill_chain_phases[].phase_name``).  The full set of Enterprise tactics is
# 14; we scope to the 10 most directly applicable to AI/MCP infrastructure.
# All *techniques* under these tactics are covered — nothing is cherry-picked.

TOP_TACTIC_PHASE_NAMES = frozenset(
    [
        "initial-access",  # TA0001 — how an attacker enters via vulnerable pkg
        "execution",  # TA0002 — code execution through a CVE
        "privilege-escalation",  # TA0004 — elevation via misconfiguration / auth flaw
        "defense-evasion",  # TA0005 — disabling logging / audit (observed in AI infra)
        "credential-access",  # TA0006 — credential theft, the #1 AI agent risk
        "discovery",  # TA0007 — information disclosure / path traversal
        "collection",  # TA0009 — data gathering via compromised MCP tools
        "exfiltration",  # TA0010 — data leaving via agent tool invocation
        "command-and-control",  # TA0011 — attacker C2 via compromised server
        "impact",  # TA0040 — DoS, data destruction
    ]
)

_DEFAULT_TTL = 30 * 24 * 3600  # 30 days
_CACHE_PATH = Path.home() / ".cache" / "agent-bom" / "mitre-attack-catalog.json"
_FETCH_TIMEOUT = 60  # seconds per HTTP request

# ─── Cache schema ─────────────────────────────────────────────────────────────
#
# {
#   "fetched_at": <unix timestamp>,
#   "attack_version": "ATT&CK v16.1",    # x_mitre_version from STIX bundle
#   "techniques": {
#     "T1059": {
#       "name": "Command and Scripting Interpreter",
#       "tactics": ["execution"],
#       "description": "...",             # first 200 chars
#       "platforms": ["Linux", "macOS"],
#       "sub_techniques": ["T1059.001", ...]
#     },
#     ...
#   },
#   "cwe_to_attack": {
#     "CWE-78": ["T1059", "T1059.004"],   # derived from CAPEC STIX relationships
#     ...
#   }
# }


def _cache_ttl() -> int:
    try:
        return int(os.environ.get("AGENT_BOM_MITRE_CACHE_TTL", _DEFAULT_TTL))
    except ValueError:
        return _DEFAULT_TTL


def _load_cache(ignore_ttl: bool = False) -> Optional[dict]:
    """Return cached catalog if valid, else None.

    Args:
        ignore_ttl: If True, return stale cache regardless of age (used as
                    offline fallback when network fetch fails).
    """
    if not _CACHE_PATH.exists():
        return None
    try:
        data = json.loads(_CACHE_PATH.read_text())
        age = time.time() - data.get("fetched_at", 0)
        if ignore_ttl or age < _cache_ttl():
            return data
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return None


def _save_cache(catalog: dict) -> None:
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_PATH.write_text(json.dumps(catalog, separators=(",", ":")))
    except OSError as exc:
        logger.debug("MITRE cache write failed: %s", exc)


def _fetch_json(url: str) -> Optional[dict]:
    """Fetch a JSON URL with a reasonable timeout.  Returns None on failure."""
    try:
        with httpx.Client(timeout=_FETCH_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.warning("MITRE fetch failed (%s): %s", url, exc)
        return None


def _parse_attack_stix(stix_bundle: dict) -> tuple[str, dict[str, dict]]:
    """Extract technique catalog from enterprise-attack STIX 2.0 bundle.

    Returns:
        ``(version_string, techniques_dict)`` where ``techniques_dict`` maps
        technique ID → metadata dict.  Only techniques in the top-10 tactics
        scope are included.
    """
    version = "unknown"
    techniques: dict[str, dict] = {}

    for obj in stix_bundle.get("objects", []):
        obj_type = obj.get("type", "")

        # Extract ATT&CK version from the identity or x-mitre-collection object
        if obj_type == "x-mitre-collection":
            version = obj.get("x_mitre_version") or obj.get("name", "unknown")

        if obj_type != "attack-pattern":
            continue

        # Skip deprecated / revoked techniques
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        # Technique ID (external_references[0].external_id, e.g. "T1059")
        ext_refs = obj.get("external_references", [])
        tech_id = next(
            (r.get("external_id", "") for r in ext_refs if r.get("source_name") == "mitre-attack"),
            "",
        )
        if not tech_id or not tech_id.startswith("T"):
            continue

        # Tactics via kill_chain_phases
        tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"]

        # Scope to top-10 tactics
        if not any(t in TOP_TACTIC_PHASE_NAMES for t in tactics):
            continue

        techniques[tech_id] = {
            "name": obj.get("name", tech_id),
            "tactics": tactics,
            "description": (obj.get("description") or "")[:200],
            "platforms": obj.get("x_mitre_platforms", []),
        }

    return version, techniques


def _parse_capec_stix(capec_bundle: dict, attack_techniques: dict[str, dict]) -> dict[str, list[str]]:
    """Derive CWE → ATT&CK technique mapping from CAPEC STIX 2.0 bundle.

    CAPEC bridge chain:
      CWE  ←(Related_Weakness)─  CAPEC  ─(uses/maps-to)→  ATT&CK technique

    We parse STIX relationship objects:
    - ``exploits`` / ``related-to`` (CAPEC → CWE)
    - ``uses`` (CAPEC → ATT&CK)

    Only produces mappings for ATT&CK techniques already in our top-10 scope.
    """
    objects = capec_bundle.get("objects", [])

    # Build maps from CAPEC STIX IDs
    # capec_to_cwes: capec_stix_id → [CWE-NNN, ...]
    # capec_to_attack: capec_stix_id → [T-code, ...]
    capec_to_cwes: dict[str, list[str]] = {}
    capec_to_attack: dict[str, list[str]] = {}

    # Index attack-pattern objects by STIX id for later lookup
    capec_external: dict[str, str] = {}  # stix_id → CAPEC-NNN
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        stix_id = obj.get("id", "")
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "capec":
                capec_external[stix_id] = ref["external_id"]

    # Parse relationships
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type", "")
        source_id = obj.get("source_ref", "")
        target_id = obj.get("target_ref", "")

        # CAPEC → CWE (the CAPEC "exploits" or targets a CWE weakness)
        if rel_type in ("exploits", "related-to") and target_id.startswith("weakness--"):
            # CWE external_id lives on weakness objects
            pass  # handled via weakness lookup below

        # CAPEC attack-pattern → ATT&CK attack-pattern
        if rel_type in ("uses", "maps-to") and source_id.startswith("attack-pattern--"):
            # Determine if target is an ATT&CK technique (external_id starts with T)
            pass  # handled via dedicated index below

    # Rebuild with weakness objects included
    weakness_map: dict[str, str] = {}  # stix_id → CWE-NNN
    for obj in objects:
        if obj.get("type") == "weakness":
            stix_id = obj.get("id", "")
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "cwe":
                    cwe_id = ref["external_id"]
                    if not cwe_id.upper().startswith("CWE-"):
                        cwe_id = f"CWE-{cwe_id}"
                    weakness_map[stix_id] = cwe_id.upper()

    # Index attack-pattern external IDs (ATT&CK techniques)
    attack_external: dict[str, str] = {}  # stix_id → T-code
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        stix_id = obj.get("id", "")
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                if tech_id.startswith("T"):
                    attack_external[stix_id] = tech_id

    # Rebuild relationship maps with full index
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type", "")
        source_id = obj.get("source_ref", "")
        target_id = obj.get("target_ref", "")

        # CAPEC → CWE weakness
        if target_id in weakness_map and source_id in capec_external:
            cwe = weakness_map[target_id]
            capec_to_cwes.setdefault(source_id, [])
            if cwe not in capec_to_cwes[source_id]:
                capec_to_cwes[source_id].append(cwe)

        # CAPEC → ATT&CK technique
        if target_id in attack_external and source_id in capec_external:
            tech = attack_external[target_id]
            if tech in attack_techniques:  # only our scoped techniques
                capec_to_attack.setdefault(source_id, [])
                if tech not in capec_to_attack[source_id]:
                    capec_to_attack[source_id].append(tech)

    # Chain: CWE → CAPEC → ATT&CK
    cwe_to_attack: dict[str, list[str]] = {}
    for capec_stix_id, techs in capec_to_attack.items():
        for cwe in capec_to_cwes.get(capec_stix_id, []):
            existing = set(cwe_to_attack.get(cwe, []))
            existing.update(techs)
            cwe_to_attack[cwe] = sorted(existing)

    return cwe_to_attack


def build_catalog(force_refresh: bool = False) -> dict:
    """Return the full MITRE ATT&CK + CAPEC catalog as a dict.

    Loads from cache when valid.  Fetches from MITRE GitHub on first call or
    when the cache has expired.  Falls back to an empty catalog on network
    failure so that scans are never blocked.

    Returns:
        Dict with keys:

        - ``"techniques"`` — ``{T-code: {name, tactics, description, platforms}}``
        - ``"cwe_to_attack"`` — ``{CWE-NNN: [T-code, ...]}`` (CAPEC-derived)
        - ``"attack_version"`` — e.g. ``"ATT&CK v16.1"``
        - ``"fetched_at"`` — unix timestamp
    """
    if not force_refresh:
        cached = _load_cache()
        if cached:
            return cached

    logger.debug("Fetching MITRE ATT&CK Enterprise STIX from %s", _ENTERPRISE_STIX_URL)
    attack_bundle = _fetch_json(_ENTERPRISE_STIX_URL)

    if not attack_bundle:
        # Network failed — serve stale cache rather than silently dropping all ATT&CK tags
        stale = _load_cache(ignore_ttl=True)
        if stale and stale.get("techniques"):
            stale_age_days = int((time.time() - stale.get("fetched_at", 0)) / 86400)
            logger.warning(
                "MITRE ATT&CK fetch failed; using stale cache (%d days old). ATT&CK tags will reflect the cached version.",
                stale_age_days,
            )
            return stale
        logger.warning("MITRE ATT&CK fetch failed and no cache exists; returning empty catalog")
        return {"techniques": {}, "cwe_to_attack": {}, "attack_version": "unavailable", "fetched_at": 0}

    version, techniques = _parse_attack_stix(attack_bundle)
    logger.debug("Parsed %d ATT&CK techniques across top-10 tactics (version: %s)", len(techniques), version)

    # CAPEC for CWE → ATT&CK bridge
    logger.debug("Fetching CAPEC STIX for CWE→ATT&CK bridge from %s", _CAPEC_STIX_URL)
    capec_bundle = _fetch_json(_CAPEC_STIX_URL)
    cwe_to_attack: dict[str, list[str]] = {}
    if capec_bundle:
        cwe_to_attack = _parse_capec_stix(capec_bundle, techniques)
        logger.debug("Derived %d CWE→ATT&CK mappings from CAPEC", len(cwe_to_attack))
    else:
        logger.warning("CAPEC fetch failed; CWE→ATT&CK mapping unavailable")

    catalog = {
        "techniques": techniques,
        "cwe_to_attack": cwe_to_attack,
        "attack_version": version,
        "fetched_at": time.time(),
    }
    _save_cache(catalog)
    return catalog


def get_techniques() -> dict[str, dict]:
    """Return technique catalog dict ``{T-code: {name, tactics, ...}}``."""
    return build_catalog().get("techniques", {})


def get_cwe_to_attack() -> dict[str, list[str]]:
    """Return CWE → ATT&CK technique list derived from official CAPEC data."""
    return build_catalog().get("cwe_to_attack", {})


def get_attack_version() -> str:
    """Return the ATT&CK version string of the cached catalog."""
    return build_catalog().get("attack_version", "unknown")
