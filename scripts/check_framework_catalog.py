#!/usr/bin/env python3
"""CI gate: fail on vendored compliance-framework catalog drift or tampering.

Verifies the two provenance-tagged data artifacts read by
``agent_bom.framework_catalog`` — the NIST SP 800-53 Rev 5 control catalog and
the NIST -> ISO/IEC 27001:2022 crosswalk — are internally consistent: every
required provenance field is present, the recorded ``normalized_sha256`` matches
a fresh digest of the payload (so an accidental edit to the vendored JSON is
caught), the published counts reconcile, and the crosswalk references ISO by
identifier only (no copyrighted ISO title text).

Regenerate the artifacts from their pinned official sources with:
    python scripts/refresh_framework_catalog.py

Run: python scripts/check_framework_catalog.py
Exit 0 = in sync. Exit 1 = drift/tampering detected.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_bom import framework_catalog as fc  # noqa: E402


def main() -> int:
    problems = fc.verify_catalog_integrity()
    if problems:
        print("Vendored framework-catalog integrity problems:")
        for problem in problems:
            print(f"  - {problem}")
        print("\nRegenerate with: python scripts/refresh_framework_catalog.py")
        return 1
    catalog = fc.nist_catalog_provenance()
    cross = fc.crosswalk_provenance()
    print(
        f"Framework catalog in sync: NIST 800-53 {catalog['catalog_version']} "
        f"({catalog['control_count']} controls); crosswalk "
        f"{cross['nist_control_count']} NIST -> {cross['iso_control_count']} ISO Annex A ids."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
