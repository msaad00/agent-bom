#!/usr/bin/env python3
"""Maintainer refresh path for the vendored compliance framework catalog.

Regenerates the two in-repo data artifacts consumed by
``agent_bom.framework_catalog``:

1. ``src/agent_bom/data/nist_800_53_rev5_catalog.json`` — a compact
   ``{control_id: {title, statement}}`` catalog derived from the official NIST
   OSCAL SP 800-53 Rev 5 control catalog. NIST SP 800-53 is a U.S. Government
   work in the public domain (published under CC0 1.0 in the OSCAL content
   repository), so its control IDs, titles, and statement text may be copied
   and redistributed freely.

2. ``src/agent_bom/data/nist_800_53_to_iso_27001_crosswalk.json`` — the
   NIST-authored SP 800-53 Rev 5 -> ISO/IEC 27001:2022 crosswalk (a NIST OLIR
   submission, public domain). Only the ISO Annex A **control identifiers** are
   vendored; ISO's copyrighted control titles/descriptions are never copied.

Supply-chain hygiene: both sources are pinned (an immutable git tag / a dated
OLIR submission filename), fetched only from their official first-party hosts,
and their exact bytes are recorded by sha256 so each artifact is reproducible.
Refreshing means bumping the pinned constants below and re-running this script;
it requires the network fetch to succeed and refuses to write a partial or
fabricated artifact.

Run: python scripts/refresh_framework_catalog.py
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

import httpx

_DATA_DIR = Path(__file__).resolve().parent.parent / "src" / "agent_bom" / "data"
_NIST_CATALOG_OUT = _DATA_DIR / "nist_800_53_rev5_catalog.json"
_CROSSWALK_OUT = _DATA_DIR / "nist_800_53_to_iso_27001_crosswalk.json"

# ── Pinned official first-party sources ──────────────────────────────────────
# NIST OSCAL content, pinned to an immutable release tag (never a mutable
# branch). Bumping the release means changing these three constants.
_OSCAL_RELEASE = "v1.5.0"
_OSCAL_COMMIT = "78650f02ad9321bb7b817846f8fbd4f2bcd620de"
_NIST_CATALOG_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/"
    f"{_OSCAL_RELEASE}/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

# NIST OLIR crosswalk: SP 800-53 Rev 5 -> ISO/IEC 27001:2022, 2023-10-12 update.
_CROSSWALK_URL = (
    "https://csrc.nist.gov/csrc/media/Projects/olir/documents/submissions/sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx"
)
_CROSSWALK_UPDATE_ID = "OLIR 2023-10-12"

_SCHEMA_VERSION = 1
_FETCH_TIMEOUT = 120

_CC0_LICENSE = (
    "U.S. Government public domain (CC0 1.0) — free to copy, redistribute, and "
    "use commercially; attribution to NIST requested but not required."
)


def _fetch_bytes(url: str) -> bytes:
    with httpx.Client(timeout=_FETCH_TIMEOUT, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.content


# ── NIST 800-53 catalog derivation ───────────────────────────────────────────


def _canonical_control_id(control: dict) -> str:
    """Return NIST's canonical human label (``AC-2``, ``AC-2(1)``).

    The OSCAL control carries several ``label`` props; the one with no ``class``
    is the non-zero-padded canonical form used throughout SP 800-53.
    """
    for prop in control.get("props", []):
        if prop.get("name") == "label" and prop.get("class") is None:
            return prop.get("value", "").strip()
    return control.get("id", "").upper()


def _is_withdrawn(control: dict) -> bool:
    return any(prop.get("name") == "status" and prop.get("value") == "withdrawn" for prop in control.get("props", []))


def _statement_text(control: dict) -> str:
    """Assemble the control statement prose verbatim from the OSCAL parts.

    Prose is kept exactly as published (including OSCAL ``{{ insert: param }}``
    assignment markers) so the vendored text is a faithful copy of the
    public-domain source, not an editorialized paraphrase.
    """
    lines: list[str] = []

    def walk(parts: list[dict]) -> None:
        for part in parts:
            if part.get("name") not in {"statement", "item"}:
                continue
            prose = part.get("prose")
            if prose:
                lines.append(prose.strip())
            walk(part.get("parts", []))

    for part in control.get("parts", []):
        if part.get("name") == "statement":
            prose = part.get("prose")
            if prose:
                lines.append(prose.strip())
            walk(part.get("parts", []))
    return "\n".join(lines)


def _walk_controls(controls: list[dict]):
    for control in controls:
        yield control
        yield from _walk_controls(control.get("controls", []))


def _derive_nist_catalog(raw: bytes) -> dict:
    source_sha = hashlib.sha256(raw).hexdigest()
    doc = json.loads(raw)
    catalog = doc["catalog"]
    metadata = catalog.get("metadata", {})

    controls: dict[str, dict] = {}
    withdrawn = 0
    for group in catalog.get("groups", []):
        for control in _walk_controls(group.get("controls", [])):
            if _is_withdrawn(control):
                withdrawn += 1
                continue
            cid = _canonical_control_id(control)
            if not cid:
                continue
            controls[cid] = {
                "title": control.get("title", "").strip(),
                "statement": _statement_text(control),
            }

    payload = {"controls": controls}
    normalized_sha256 = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    return {
        "schema_version": _SCHEMA_VERSION,
        "catalog_id": "nist_sp800_53_rev5",
        "catalog_type": "nist_800_53",
        "framework_slug": "nist-800-53",
        "publication": "NIST SP 800-53 Rev 5",
        "catalog_version": metadata.get("version", "unknown"),
        "oscal_version": metadata.get("oscal-version", "unknown"),
        "catalog_last_modified": metadata.get("last-modified", ""),
        "license": _CC0_LICENSE,
        "source": {
            "url": _NIST_CATALOG_URL,
            "oscal_release": _OSCAL_RELEASE,
            "oscal_commit": _OSCAL_COMMIT,
            "sha256": source_sha,
        },
        "fetched_at": time.time(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "normalized_sha256": normalized_sha256,
        "control_count": len(controls),
        "withdrawn_excluded": withdrawn,
        "controls": controls,
    }


# ── NIST -> ISO 27001 crosswalk derivation ────────────────────────────────────

_XL_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def _norm_nist_id(raw: str) -> str | None:
    """Normalize an OLIR focal element (``AC-02``, ``AC-02(01)``) to ``AC-2``."""
    match = re.match(r"^([A-Z]{2})-0*(\d+)(?:\((\d+)\))?$", raw.strip())
    if not match:
        return None
    family, number, enhancement = match.groups()
    base = f"{family}-{int(number)}"
    return f"{base}({int(enhancement)})" if enhancement else base


def _shared_strings(zf: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in zf.namelist():
        return []
    root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
    return ["".join(t.text or "" for t in si.iter(f"{_XL_NS}t")) for si in root.findall(f"{_XL_NS}si")]


def _iter_rows(zf: zipfile.ZipFile, path: str, shared: list[str]):
    root = ET.fromstring(zf.read(path))
    for row in root.iter(f"{_XL_NS}row"):
        cells: dict[str, str | None] = {}
        for cell in row.findall(f"{_XL_NS}c"):
            ref = cell.get("r", "")
            col = re.match(r"[A-Z]+", ref).group() if re.match(r"[A-Z]+", ref) else ""
            value_el = cell.find(f"{_XL_NS}v")
            value = None
            if value_el is not None:
                value = shared[int(value_el.text)] if cell.get("t") == "s" else value_el.text
            cells[col] = value
        yield cells


def _derive_crosswalk(raw: bytes) -> dict:
    source_sha = hashlib.sha256(raw).hexdigest()
    import io

    zf = zipfile.ZipFile(io.BytesIO(raw))
    shared = _shared_strings(zf)

    workbook = zf.read("xl/workbook.xml").decode()
    rels = zf.read("xl/_rels/workbook.xml.rels").decode()
    rid_target = {m.group(1): m.group(2) for m in re.finditer(r'Id="([^"]+)"\s+Type="[^"]*worksheet"\s+Target="([^"]+)"', rels)}
    sheets = [(m.group(1), m.group(2)) for m in re.finditer(r'<sheet[^>]*name="([^"]*)"[^>]*r:id="([^"]*)"', workbook)]

    mapping: dict[str, set[str]] = {}
    for name, rid in sheets:
        if "Definitions" in name:
            continue
        target = rid_target.get(rid)
        if not target:
            continue
        path = target.lstrip("/") if target.startswith("/") else "xl/" + target
        for i, cells in enumerate(_iter_rows(zf, path, shared)):
            if i == 0:
                continue  # header row
            focal = cells.get("A")
            iso = cells.get("D")
            if not focal or not iso:
                continue
            nist_id = _norm_nist_id(focal)
            if not nist_id:
                continue
            iso = iso.strip()
            # Vendor only ISO Annex A control identifiers (``A.<clause>.<n>``);
            # the OLIR also references ISO management clauses (4-10) which are
            # not Annex A controls.
            if iso.startswith("A."):
                mapping.setdefault(nist_id, set()).add(iso)

    crosswalk = {nist_id: sorted(iso_ids) for nist_id, iso_ids in sorted(mapping.items())}
    payload = {"crosswalk": crosswalk}
    normalized_sha256 = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    iso_ids_all = sorted({iso for ids in crosswalk.values() for iso in ids})
    return {
        "schema_version": _SCHEMA_VERSION,
        "catalog_id": "nist_sp800_53_rev5_to_iso_27001_2022",
        "catalog_type": "nist_800_53_to_iso_27001_crosswalk",
        "mapping_authority": "NIST",
        "publication": "NIST OLIR crosswalk: SP 800-53 Rev 5 -> ISO/IEC 27001:2022",
        "update_id": _CROSSWALK_UPDATE_ID,
        "license": _CC0_LICENSE,
        "iso_reference": (
            "ISO/IEC 27001:2022 Annex A controls are referenced by identifier only. "
            "ISO control titles/descriptions are copyrighted and are NOT vendored."
        ),
        "source": {
            "url": _CROSSWALK_URL,
            "sha256": source_sha,
        },
        "fetched_at": time.time(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "normalized_sha256": normalized_sha256,
        "nist_control_count": len(crosswalk),
        "iso_control_count": len(iso_ids_all),
        "crosswalk": crosswalk,
    }


def main() -> int:
    print(f"→ fetching NIST OSCAL catalog {_OSCAL_RELEASE} …")
    catalog_raw = _fetch_bytes(_NIST_CATALOG_URL)
    catalog = _derive_nist_catalog(catalog_raw)
    _NIST_CATALOG_OUT.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")
    print(
        f"  wrote {_NIST_CATALOG_OUT.name}: {catalog['control_count']} controls "
        f"(catalog {catalog['catalog_version']}, source sha256 {catalog['source']['sha256'][:12]}…)"
    )

    print(f"→ fetching NIST OLIR crosswalk ({_CROSSWALK_UPDATE_ID}) …")
    crosswalk_raw = _fetch_bytes(_CROSSWALK_URL)
    crosswalk = _derive_crosswalk(crosswalk_raw)
    _CROSSWALK_OUT.write_text(json.dumps(crosswalk, indent=2, sort_keys=True) + "\n")
    print(
        f"  wrote {_CROSSWALK_OUT.name}: {crosswalk['nist_control_count']} NIST controls -> "
        f"{crosswalk['iso_control_count']} ISO Annex A controls "
        f"(source sha256 {crosswalk['source']['sha256'][:12]}…)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
