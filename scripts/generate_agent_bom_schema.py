#!/usr/bin/env python3
"""Generate/check the experimental per-agent BOM JSON Schema."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.evidence.agent_bom import AgentBomDocument  # noqa: E402

DESTINATION = ROOT / "docs" / "schemas" / "agent-bom" / "profile-v1.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    schema = AgentBomDocument.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    rendered = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not DESTINATION.exists() or DESTINATION.read_text() != rendered:
            print("Agent BOM schema drift: run python scripts/generate_agent_bom_schema.py")
            return 1
    else:
        DESTINATION.parent.mkdir(parents=True, exist_ok=True)
        DESTINATION.write_text(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
