#!/usr/bin/env python3
"""Seed a dense, realistic agentic-estate graph for UI screenshots / demos.

Builds a multi-cloud estate that exercises every attack-path class the graph
can derive — vuln-anchored chains, internet exposure (port-aware), toxic
exposed+vulnerable, path-to-sensitive-data, and privilege escalation to admin —
then runs the real CNAPP, effective-permission, and governance overlays so the
graph the API serves is identical to a real scan's. Save it into a graph DB and
point ``agent-bom api`` at the same DB (``AGENT_BOM_GRAPH_DB``).

    python scripts/seed_graph_showcase.py --sqlite-db /tmp/showcase-graph.db
    AGENT_BOM_GRAPH_DB=/tmp/showcase-graph.db agent-bom api
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.api.graph_store import SQLiteGraphStore  # noqa: E402
from agent_bom.demo_estate.showcase_graph import (  # noqa: E402
    SHOWCASE_TENANT,
    apply_showcase_overlays,
    build_showcase_graph,
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sqlite-db", default="/tmp/showcase-graph.db", help="Graph DB path to seed")
    args = ap.parse_args()

    g, store, drift = build_showcase_graph(tenant_id=SHOWCASE_TENANT)
    overlays = apply_showcase_overlays(g, tenant_id=SHOWCASE_TENANT, identity_store=store, drift_store=drift)

    db_path = Path(args.sqlite_db).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    graph_store = SQLiteGraphStore(db_path)
    graph_store.save_graph(g)

    print(f"Seeded {len(g.nodes)} nodes / {len(g.edges)} edges → {db_path}")
    print(f"  cnapp:  {overlays['cnapp']}")
    print(f"  effperm:{overlays['effective_permissions']}")
    print(f"  gov:    {overlays['governance']}")
    print(f"  risks:  {len(g.interaction_risks)} interaction risks")
    print(f"\nBoot the API against it:\n  AGENT_BOM_GRAPH_DB={db_path} agent-bom api")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
