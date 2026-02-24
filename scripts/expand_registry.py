#!/usr/bin/env python3
"""Expand the bundled MCP registry with servers from the Official MCP Registry.

Usage:
    python scripts/expand_registry.py                   # Fetch and add new servers
    python scripts/expand_registry.py --dry-run          # Preview without writing
    python scripts/expand_registry.py --max-pages 20     # Fetch more pages

Servers are auto-classified with risk_level based on tool names and credential
exposure. Entries are flagged with "auto_enriched": true for manual review.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

REGISTRY_PATH = ROOT / "src" / "agent_bom" / "mcp_registry.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Expand bundled MCP registry")
    parser.add_argument(
        "--max-pages", type=int, default=10,
        help="Maximum pages to fetch (default: 10, ~100 servers/page)",
    )
    parser.add_argument(
        "--page-size", type=int, default=100,
        help="Servers per page (default: 100)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without writing",
    )
    args = parser.parse_args()

    # Load current registry for before/after count
    data = json.loads(REGISTRY_PATH.read_text())
    before = len(data.get("servers", {}))

    print(f"Current registry: {before} servers")
    print(f"Fetching from Official MCP Registry (max {args.max_pages} pages)...")

    from agent_bom.mcp_official_registry import sync_from_official_registry_sync

    result = sync_from_official_registry_sync(
        max_pages=args.max_pages,
        page_size=args.page_size,
        dry_run=args.dry_run,
    )

    print(f"Fetched: {result.total_fetched}")
    print(f"Added: {result.added}")
    print(f"Skipped (already exists): {result.skipped}")

    if result.added > 0:
        # Reload to get new count
        if not args.dry_run:
            after_data = json.loads(REGISTRY_PATH.read_text())
            after = len(after_data.get("servers", {}))
            # Update _total_servers
            after_data["_total_servers"] = after
            REGISTRY_PATH.write_text(json.dumps(after_data, indent=2) + "\n")
            print(f"Registry updated: {before} → {after} servers")
        else:
            print(f"Would add {result.added} servers (dry run)")

    if result.details:
        print("\nNew entries:")
        for d in result.details[:20]:
            print(f"  + {d['server']} (v{d.get('version', '?')})")
        if len(result.details) > 20:
            print(f"  ... and {len(result.details) - 20} more")


if __name__ == "__main__":
    main()
