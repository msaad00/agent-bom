#!/usr/bin/env python3
"""Regenerate the shipped MITRE ATT&CK/CAPEC catalog from pinned STIX releases.

This is a thin maintainer entrypoint over the existing refresh path in
``agent_bom.mitre_fetch``. It fetches the *pinned, first-party* ATT&CK and CAPEC
STIX releases (an immutable git tag + versioned filename — never a mutable
``master`` branch), normalizes them, and writes the bundled artifact at
``src/agent_bom/data/mitre_attack_catalog.json`` with full provenance recorded
(pinned release, source URL, source digest, fetch time, technique + tactic
counts).

To refresh to a newer ATT&CK release, bump ``_ATTACK_RELEASE`` / ``_CAPEC_RELEASE``
in ``agent_bom.mitre_fetch`` and re-run this script; the recorded digest then
pins the exact bytes so the artifact is reproducible. The 14 Enterprise tactics
and provenance are locked by ``tests/test_mitre_catalog_provenance.py``.

Usage:
    python scripts/refresh_mitre_attack_catalog.py            # regenerate + print provenance
    python scripts/refresh_mitre_attack_catalog.py --check    # verify counts reconcile (no network)
"""

from __future__ import annotations

import argparse
import sys

from agent_bom.mitre_fetch import _load_bundled_catalog, refresh_bundled_catalog


def _check() -> int:
    catalog = _load_bundled_catalog()
    problems: list[str] = []
    if catalog.get("technique_count") != len(catalog.get("techniques", {})):
        problems.append("technique_count does not match techniques")
    if catalog.get("tactic_count") != len(catalog.get("tactics", {})):
        problems.append("tactic_count does not match tactics")
    if len(catalog.get("tactics", {})) != 14:
        problems.append(f"expected 14 Enterprise tactics, found {len(catalog.get('tactics', {}))}")
    if not catalog.get("attack_release") or catalog.get("attack_release") == "unavailable":
        problems.append("attack_release provenance missing")
    if problems:
        print("Bundled MITRE catalog is inconsistent:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"OK: ATT&CK {catalog['attack_release']} — {catalog['technique_count']} techniques, {catalog['tactic_count']} tactics.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the committed artifact reconciles (no network)")
    args = parser.parse_args()

    if args.check:
        return _check()

    catalog = refresh_bundled_catalog()
    print(f"Wrote {catalog['_path']}")
    print(f"  ATT&CK release : {catalog['attack_release']}")
    print(f"  techniques     : {catalog['technique_count']}")
    print(f"  tactics        : {catalog['tactic_count']}")
    for name, src in catalog["sources"].items():
        print(f"  {name}: release={src['release']} sha256={src['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
