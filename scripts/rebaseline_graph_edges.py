#!/usr/bin/env python3
"""Re-baseline the graph-accuracy guard fixtures (#2259).

Regenerates the recorded fixtures used by:

- ``tests/test_graph_edge_counts.py``  → ``tests/fixtures/graph_edge_counts.json``
- the visual-diff guard                 → ``tests/fixtures/graph-snapshots/security-graph.json``

Source of truth is the trimmed agent-bom self-scan at
``tests/fixtures/agent_bom_self_scan_inventory.json``.  When the upstream
graph builder *intentionally* changes its edge or node emission, run this
script and check the regenerated fixtures into the same PR.

Usage::

    # Default: rebuild both fixtures from the existing self-scan fixture.
    python scripts/rebaseline_graph_edges.py

    # Print what would change without writing files.
    python scripts/rebaseline_graph_edges.py --dry-run

    # Refresh the upstream self-scan fixture too (runs `agent-bom scan`).
    python scripts/rebaseline_graph_edges.py --refresh-self-scan

The dry-run mode is used by CI as a smoke test that this script still
imports and executes against the current builder.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Make ``tests/`` and ``src/`` importable so we can reuse the helpers.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from tests._graph_helpers import (  # noqa: E402
    EDGE_COUNTS_FIXTURE,
    GRAPH_SNAPSHOT_DIR,
    GRAPH_SNAPSHOT_FIXTURE,
    SELF_SCAN_FIXTURE,
    build_graph_from_inventory,
    edge_counts_by_kind,
    graph_visual_snapshot,
    load_self_scan_fixture,
    node_counts_by_kind,
)


def _refresh_self_scan_fixture() -> None:
    """Run ``agent-bom scan`` and rewrite the trimmed fixture."""
    out_path = ROOT / ".rebaseline_scan.json"
    print(f"  → running: agent-bom scan -p . --format json -o {out_path}")
    subprocess.run(
        ["agent-bom", "scan", "-p", str(ROOT), "--format", "json", "-o", str(out_path)],
        check=True,
    )
    raw = json.loads(out_path.read_text())

    def _trim_agent(a: dict) -> dict:
        return {
            "name": a.get("name"),
            "type": a.get("type"),
            "status": a.get("status"),
            "metadata": a.get("metadata", {}),
            "mcp_servers": [
                {
                    "name": s.get("name"),
                    "command": s.get("command"),
                    "transport": s.get("transport"),
                    "env": s.get("env", {}),
                    "packages": [],
                    "tools": [
                        {
                            "name": t.get("name"),
                            "description": (t.get("description") or "")[:200],
                            "capabilities": t.get("capabilities", []),
                        }
                        for t in s.get("tools", []) or []
                    ],
                }
                for s in a.get("mcp_servers", []) or []
            ],
        }

    def _trim_br(b: dict) -> dict:
        return {
            "vulnerability_id": b.get("vulnerability_id"),
            "severity": b.get("severity"),
            "cvss_score": b.get("cvss_score"),
            "epss_score": b.get("epss_score"),
            "is_kev": b.get("is_kev", False),
            "risk_score": b.get("risk_score", 0),
            "package": b.get("package", ""),
            "affected_agents": b.get("affected_agents", []),
            "affected_servers": b.get("affected_servers", []),
            "exposed_credentials": b.get("exposed_credentials", []),
            "exposed_tools": b.get("exposed_tools", []),
        }

    trimmed = {
        "document_type": raw.get("document_type"),
        "spec_version": raw.get("spec_version"),
        "agents": [_trim_agent(a) for a in raw.get("agents", []) or []],
        "blast_radius": [_trim_br(b) for b in raw.get("blast_radius", []) or []],
        "summary": raw.get("summary", {}),
    }
    SELF_SCAN_FIXTURE.write_text(json.dumps(trimmed, indent=2, sort_keys=True) + "\n")
    out_path.unlink(missing_ok=True)
    print(f"  → wrote {SELF_SCAN_FIXTURE}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Compute fixtures without writing them.")
    parser.add_argument(
        "--refresh-self-scan",
        action="store_true",
        help="Re-run agent-bom scan first to refresh the trimmed self-scan fixture.",
    )
    args = parser.parse_args(argv)

    if args.refresh_self_scan and not args.dry_run:
        _refresh_self_scan_fixture()
    elif args.refresh_self_scan and args.dry_run:
        print("  (--refresh-self-scan ignored with --dry-run)")

    print(f"  → loading inventory: {SELF_SCAN_FIXTURE}")
    inv = load_self_scan_fixture()
    graph = build_graph_from_inventory(inv)

    edge_counts = edge_counts_by_kind(graph)
    node_counts = node_counts_by_kind(graph)
    snapshot = graph_visual_snapshot(graph)

    edge_payload = {
        "_meta": {
            "fixture": SELF_SCAN_FIXTURE.name,
            "tolerance_pct": 5,
            "rebuild_with": "python scripts/rebaseline_graph_edges.py",
        },
        "node_counts": node_counts,
        "edge_counts": edge_counts,
    }

    print("  → edge counts by kind:")
    for kind, count in edge_counts.items():
        print(f"      {kind:>20s}: {count}")
    print("  → node counts by kind:")
    for kind, count in node_counts.items():
        print(f"      {kind:>20s}: {count}")
    print(f"  → visual snapshot: {snapshot['node_count']} nodes, {snapshot['edge_count']} edges")

    if args.dry_run:
        print("DRY-RUN: not writing fixtures.")
        return 0

    GRAPH_SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    EDGE_COUNTS_FIXTURE.write_text(json.dumps(edge_payload, indent=2, sort_keys=True) + "\n")
    GRAPH_SNAPSHOT_FIXTURE.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    print(f"  → wrote {EDGE_COUNTS_FIXTURE}")
    print(f"  → wrote {GRAPH_SNAPSHOT_FIXTURE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
