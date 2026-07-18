"""Loader + integrity gate for the vendored compliance framework catalog.

Two provenance-tagged data artifacts ship in ``agent_bom/data/`` and are read
here (offline, no network on the hot path):

* ``nist_800_53_rev5_catalog.json`` — the NIST SP 800-53 Rev 5 control catalog
  (control IDs, titles, statement text). NIST SP 800-53 is a U.S. Government
  public-domain work (CC0 1.0 in the OSCAL content repo), so its text is
  vendored in full.
* ``nist_800_53_to_iso_27001_crosswalk.json`` — NIST's own SP 800-53 Rev 5 ->
  ISO/IEC 27001:2022 crosswalk (a NIST OLIR submission, public domain). Only
  ISO Annex A **control identifiers** are vendored; ISO's copyrighted control
  titles/descriptions are never copied.

The maintainer refresh path that regenerates these files from their pinned
official sources is ``scripts/refresh_framework_catalog.py``; the CI integrity
gate is ``scripts/check_framework_catalog.py`` (backed by
:func:`verify_catalog_integrity`).
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

_DATA_DIR = Path(__file__).with_name("data")
NIST_CATALOG_PATH = _DATA_DIR / "nist_800_53_rev5_catalog.json"
CROSSWALK_PATH = _DATA_DIR / "nist_800_53_to_iso_27001_crosswalk.json"

# Provenance fields every vendored artifact must carry (checked by the gate).
_REQUIRED_PROVENANCE = ("schema_version", "license", "source", "normalized_sha256", "updated_at")


@lru_cache(maxsize=1)
def _nist_catalog() -> dict:
    return json.loads(NIST_CATALOG_PATH.read_text())


@lru_cache(maxsize=1)
def _crosswalk() -> dict:
    return json.loads(CROSSWALK_PATH.read_text())


# ── NIST 800-53 catalog ───────────────────────────────────────────────────────


def nist_controls() -> dict[str, dict[str, str]]:
    """Return ``{control_id: {"title", "statement"}}`` for SP 800-53 Rev 5."""
    return _nist_catalog()["controls"]


def nist_catalog_provenance() -> dict:
    """Return the provenance record for the vendored NIST catalog (no controls)."""
    return {k: v for k, v in _nist_catalog().items() if k != "controls"}


# ── NIST -> ISO 27001 crosswalk ───────────────────────────────────────────────


def nist_to_iso_crosswalk() -> dict[str, list[str]]:
    """Return ``{nist_control_id: [iso_annex_a_id, ...]}`` (ISO IDs only)."""
    return _crosswalk()["crosswalk"]


def iso_controls_for_nist(control_id: str) -> list[str]:
    """Return the ISO/IEC 27001:2022 Annex A control IDs NIST maps ``control_id`` to.

    Identifiers only — ISO control titles are copyrighted and not vendored.
    Returns an empty list when NIST publishes no ISO mapping for the control.
    """
    return list(nist_to_iso_crosswalk().get(control_id, []))


def crosswalk_provenance() -> dict:
    """Return the provenance record for the vendored crosswalk (no mappings)."""
    return {k: v for k, v in _crosswalk().items() if k != "crosswalk"}


# ── Integrity gate ────────────────────────────────────────────────────────────


def _digest(payload_key: str, data: dict) -> str:
    return hashlib.sha256(json.dumps({payload_key: data}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_catalog_integrity() -> list[str]:
    """Return a list of integrity problems; empty means the vendored data is sound.

    Verifies, for both artifacts, that every required provenance field is
    present, that the recorded ``normalized_sha256`` matches a fresh digest of
    the payload (so an accidental edit to the vendored data is caught), and that
    the published counts reconcile with the payload.
    """
    problems: list[str] = []

    catalog = _nist_catalog()
    for field in _REQUIRED_PROVENANCE:
        if not catalog.get(field):
            problems.append(f"nist catalog: missing provenance field '{field}'")
    controls = catalog.get("controls", {})
    if catalog.get("control_count") != len(controls):
        problems.append(f"nist catalog: control_count {catalog.get('control_count')} != {len(controls)} controls")
    if catalog.get("normalized_sha256") and _digest("controls", controls) != catalog["normalized_sha256"]:
        problems.append("nist catalog: normalized_sha256 does not match the controls payload (data edited?)")
    for cid, spec in controls.items():
        if not spec.get("title"):
            problems.append(f"nist catalog: control {cid} has no title")
            break

    cross = _crosswalk()
    for field in _REQUIRED_PROVENANCE:
        if not cross.get(field):
            problems.append(f"crosswalk: missing provenance field '{field}'")
    mapping = cross.get("crosswalk", {})
    if cross.get("nist_control_count") != len(mapping):
        problems.append(f"crosswalk: nist_control_count {cross.get('nist_control_count')} != {len(mapping)} entries")
    iso_ids = {iso for ids in mapping.values() for iso in ids}
    if cross.get("iso_control_count") != len(iso_ids):
        problems.append(f"crosswalk: iso_control_count {cross.get('iso_control_count')} != {len(iso_ids)} ISO ids")
    if cross.get("normalized_sha256") and _digest("crosswalk", mapping) != cross["normalized_sha256"]:
        problems.append("crosswalk: normalized_sha256 does not match the crosswalk payload (data edited?)")
    # Legal guard: the crosswalk must reference ISO Annex A by identifier only.
    leaked = [iso for iso in iso_ids if not iso.startswith("A.")]
    if leaked:
        problems.append(f"crosswalk: non-Annex-A ISO references present: {sorted(leaked)[:5]}")

    return problems
