"""Durable job storage defaults for demo-estate API servers."""

from __future__ import annotations

import os
from pathlib import Path

from agent_bom.core.settings import env_raw, env_str


def demo_estate_default_persist(demo_state_dir: Path | None) -> str | None:
    """Keep demo jobs in the same durable database as the demo graph.

    The graph always lands on disk in the demo directory. Jobs defaulting to
    memory meant every restart served that graph beside zero jobs and an empty
    posture until the curated scan was recomputed. Any explicitly configured
    job backend wins.
    """
    if demo_state_dir is None or env_raw("AGENT_BOM_DB") or env_raw("AGENT_BOM_POSTGRES_URL") or env_raw("SNOWFLAKE_ACCOUNT"):
        return None
    if env_str("AGENT_BOM_GRAPH_BACKEND").lower() == "neptune":
        return None
    path = str(demo_state_dir / "control-plane.db")
    os.environ["AGENT_BOM_DB"] = path
    return path
