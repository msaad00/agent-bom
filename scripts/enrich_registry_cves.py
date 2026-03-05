#!/usr/bin/env python3
"""Enrich the MCP registry with CVE data from OSV, EPSS, and CISA KEV.

Usage:
    python scripts/enrich_registry_cves.py                # Enrich all scannable packages
    python scripts/enrich_registry_cves.py --dry-run       # Preview without writing

Queries OSV batch API for each npm/pypi package in the registry, then
enriches with EPSS exploit prediction scores and CISA KEV status.
"""

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Enrich registry with CVE data")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing",
    )
    args = parser.parse_args()

    nvd_api_key = os.environ.get("NVD_API_KEY")

    print("Enriching MCP registry with CVE data (OSV + EPSS + KEV)...")
    if args.dry_run:
        print("(dry run — no files will be modified)")

    from agent_bom.registry import enrich_registry_with_cves_sync

    result = enrich_registry_with_cves_sync(nvd_api_key=nvd_api_key, dry_run=args.dry_run)

    print(f"\nTotal servers: {result.total}")
    print(f"Scannable (npm/pypi): {result.scannable}")
    print(f"With CVEs: {result.enriched}")
    print(f"Total CVEs found: {result.total_cves}")
    print(f"Critical (EPSS >= 0.7 or KEV): {result.total_critical}")
    print(f"In CISA KEV: {result.total_kev}")

    if result.details:
        print("\nVulnerable servers:")
        for d in result.details:
            kev_tag = " [KEV]" if d["kev"] else ""
            print(f"  {d['server']}: {d['cve_count']} CVEs{kev_tag}")
            if d["cves"]:
                print(f"    {', '.join(d['cves'][:5])}")

    if not args.dry_run and result.enriched > 0:
        print("\nRegistry file updated with CVE data.")


if __name__ == "__main__":
    main()
